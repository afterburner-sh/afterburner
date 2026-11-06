// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Inspector / Chrome DevTools Protocol bridge.
//!
//! Boots an HTTP+WebSocket listener on nuclei bound to an inspector port
//! when the JS side calls `inspector.open(port)`. Serves the standard
//! discovery endpoints DevTools queries on attach
//! (`/json/version`, `/json`, `/json/list`, `/json/protocol`) and
//! upgrades `/devtools/page/<id>` requests to a WebSocket carrying CDP
//! JSON frames.
//!
//! Each incoming WebSocket frame becomes an
//! [`InspectorEvent::Message`] on the bounded event channel; the
//! daemon event loop dispatches it to the JS plugin's
//! `__ab_inspector_dispatch` handler, which routes it through the
//! same method table the in-process `Session.post` API uses. Replies
//! and notifications come back via [`Self::send`], which fans out
//! to every connected WebSocket session.

use kovan_channel::flavors::bounded::{Receiver, Sender, channel};
use kovan_map::HopscotchMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU16, Ordering};

use crate::daemon_http::h1::{Conn, ReadError, text_response};
use http::{HeaderValue, Response};
use nuclei::net::{TcpListener, TcpStream};
use nuclei::runtime::RuntimeHandle;
use nuclei::sync::mpsc::UnboundedSender;
use nuclei::task::Task;
use serde_json::json;

mod ws;
use ws::{Message, Ws};

pub type SessionId = i32;

/// Largest request body the discovery endpoints accept.
const MAX_REQUEST_BODY: usize = 2 * 1024 * 1024;

/// Single CDP frame routed from the WebSocket reader to the JS
/// plugin via the daemon event loop.
#[derive(Debug, Clone)]
pub struct InspectorEvent {
    pub session_id: SessionId,
    pub kind: InspectorEventKind,
}

#[derive(Debug, Clone)]
pub enum InspectorEventKind {
    /// A CDP JSON-RPC request frame from the client.
    Message(String),
    /// Client opened a new WebSocket session.
    SessionOpened,
    /// Client closed the WebSocket. Removes the per-session sender.
    SessionClosed,
}

pub const ERR_NO_RUNTIME: i32 = -1;
pub const ERR_BIND: i32 = -2;
pub const ERR_ALREADY_OPEN: i32 = -3;
pub const ERR_NOT_OPEN: i32 = -4;

/// Shared state across the HTTP connections and the daemon event loop.
struct InspectorInner {
    next_session_id: AtomicI32,
    /// Per-session outbound channel: the dispatcher pushes frames the
    /// WS task drains. Unbounded so the JS handler never
    /// blocks; backpressure isn't needed at CDP scale (a single human
    /// debugger driving the protocol).
    sessions: HopscotchMap<SessionId, UnboundedSender<String>>,
    events_tx: Sender<InspectorEvent>,
    events_rx: Receiver<InspectorEvent>,
    bound_port: AtomicU16,
    /// Active breakpoint pause channels. Keyed by pause_id. When a JS
    /// breakpoint fires, the JS side calls `host_inspector_pause`
    /// which inserts a (pause_id, Sender) here and blocks on the
    /// matching Receiver. The WebSocket reader intercepts
    /// `Debugger.resume`/`stepOver`/`stepInto`/`stepOut` messages on
    /// the Rust side (not in JS) and signals the Sender, unblocking
    /// the paused wasmtime instance. Going through JS would deadlock,
    /// since the wasmtime instance is what's blocked.
    pause_signals: HopscotchMap<i64, kovan_channel::flavors::bounded::Sender<i32>>,
    next_pause_id: AtomicI64,
}

/// Public coordinator handle stored on `HostState::daemon_inspector`.
pub struct DaemonInspector {
    inner: Arc<InspectorInner>,
    runtime: RuntimeHandle,
    server_task: parking_lot_free::OnceCell<Task<()>>,
}

/// Tiny once-cell used because we want one-shot publish of the
/// listener task without pulling in std's Mutex. `Task` is Clone-free,
/// so we can't store it in a HopscotchMap; this cell
/// is set exactly once at `open()` and read at `close()`.
mod parking_lot_free {
    use std::cell::UnsafeCell;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub struct OnceCell<T> {
        set: AtomicBool,
        value: UnsafeCell<Option<T>>,
    }
    unsafe impl<T: Send> Send for OnceCell<T> {}
    unsafe impl<T: Send> Sync for OnceCell<T> {}
    impl<T> OnceCell<T> {
        pub const fn new() -> Self {
            Self {
                set: AtomicBool::new(false),
                value: UnsafeCell::new(None),
            }
        }
        pub fn set(&self, v: T) -> bool {
            if self
                .set
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return false;
            }
            unsafe {
                *self.value.get() = Some(v);
            }
            true
        }
        pub fn take(&self) -> Option<T> {
            if !self.set.swap(false, Ordering::AcqRel) {
                return None;
            }
            unsafe { (*self.value.get()).take() }
        }
    }
}

impl DaemonInspector {
    pub fn new(runtime: RuntimeHandle) -> Arc<Self> {
        let (tx, rx) = channel::<InspectorEvent>(1024);
        Arc::new(Self {
            inner: Arc::new(InspectorInner {
                next_session_id: AtomicI32::new(1),
                sessions: HopscotchMap::new(),
                events_tx: tx,
                events_rx: rx,
                bound_port: AtomicU16::new(0),
                pause_signals: HopscotchMap::new(),
                next_pause_id: AtomicI64::new(1),
            }),
            runtime,
            server_task: parking_lot_free::OnceCell::new(),
        })
    }

    /// Block the calling thread until any WS client sends a
    /// `Debugger.resume`-class command. Used by `__host_inspector_pause`
    /// when a breakpoint fires. Returns 0 for resume, 1 for stepOver,
    /// 2 for stepInto, 3 for stepOut - so the JS side can react
    /// differently to stepping commands. If no inspector listener
    /// is open or no client is connected, returns -1 immediately so
    /// the JS side doesn't deadlock forever waiting for nothing.
    pub fn pause_block(&self) -> i32 {
        if self.bound_port() == 0 || self.inner.sessions.iter().next().is_none() {
            return -1;
        }
        let (tx, rx) = kovan_channel::bounded::<i32>(1);
        let pause_id = self.inner.next_pause_id.fetch_add(1, Ordering::Relaxed);
        self.inner.pause_signals.insert(pause_id, tx);
        // Block this thread until the WS reader signals via send().
        // kovan_channel's recv is blocking by default; the wasmtime
        // instance pauses here while the daemon's other tasks
        // (including the inspector listener) continue.
        let code = rx.recv().unwrap_or(-1);
        self.inner.pause_signals.remove(&pause_id);
        code
    }

    /// Drain any pending pause signals - used on listener teardown so
    /// the JS side doesn't stay blocked when the inspector closes.
    fn release_all_pauses(&self) {
        let ids: Vec<i64> = self.inner.pause_signals.iter().map(|(id, _)| id).collect();
        for id in ids {
            if let Some(tx) = self.inner.pause_signals.remove(&id) {
                tx.send(-1);
            }
        }
    }

    pub fn try_recv_event(&self) -> Option<InspectorEvent> {
        self.inner.events_rx.try_recv()
    }

    pub fn bound_port(&self) -> u16 {
        self.inner.bound_port.load(Ordering::Acquire)
    }

    /// Send a JSON CDP frame to every connected WebSocket session.
    /// `session_id == 0` broadcasts to all; otherwise routes to one.
    pub fn send(&self, session_id: SessionId, payload: String) {
        if session_id == 0 {
            for (_id, tx) in self.inner.sessions.iter() {
                let _ = tx.send(payload.clone());
            }
        } else if let Some(tx) = self.inner.sessions.get(&session_id) {
            let _ = tx.send(payload);
        }
    }

    /// Open the inspector listener. `port == 0` requests an ephemeral
    /// port from the OS; the bound port is returned. Returns the
    /// positive bound port, or a negative `ERR_*` code.
    pub fn open(self: &Arc<Self>, port: u16) -> i32 {
        if self.bound_port() != 0 {
            return ERR_ALREADY_OPEN;
        }
        let inner = Arc::clone(&self.inner);
        let _enter = self.runtime.enter();
        let std_listener = match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => l,
            Err(_) => return ERR_BIND,
        };
        let actual_port = match std_listener.local_addr() {
            Ok(a) => a.port(),
            Err(_) => return ERR_BIND,
        };
        let listener = match TcpListener::new(std_listener) {
            Ok(l) => l,
            Err(_) => return ERR_BIND,
        };
        inner.bound_port.store(actual_port, Ordering::Release);

        let task = self.runtime.spawn(serve(listener, inner));
        self.server_task.set(task);
        actual_port as i32
    }

    /// Tear down the inspector listener and disconnect every session.
    /// Idempotent.
    pub fn close(&self) -> i32 {
        if self.bound_port() == 0 {
            return ERR_NOT_OPEN;
        }
        // Dropping the task cancels the accept loop.
        drop(self.server_task.take());
        // Drop every per-session sender. The WS task observes
        // its receiver close and shuts down, which closes the socket.
        let ids: Vec<SessionId> = self.inner.sessions.iter().map(|(id, _)| id).collect();
        for id in ids {
            self.inner.sessions.remove(&id);
        }
        self.inner.bound_port.store(0, Ordering::Release);
        // Wake any paused JS instance with -1 so user code doesn't
        // hang after the inspector listener closes.
        self.release_all_pauses();
        0
    }
}

// ---- HTTP routing ---------------------------------------------

async fn serve(listener: TcpListener, inner: Arc<InspectorInner>) {
    while let Ok((stream, _peer)) = listener.accept().await {
        nuclei::spawn(serve_connection(stream, Arc::clone(&inner))).detach();
    }
}

/// The inspector's routes; every other path is a 404.
enum Route {
    Version,
    Protocol,
    Targets,
    Devtools,
    NotFound,
}

fn route(path: &str) -> Route {
    match path {
        "/json" | "/json/list" => Route::Targets,
        "/json/version" => Route::Version,
        "/json/protocol" => Route::Protocol,
        _ => match path.strip_prefix("/devtools/page/") {
            Some(id) if !id.is_empty() && !id.contains('/') => Route::Devtools,
            _ => Route::NotFound,
        },
    }
}

async fn serve_connection(stream: TcpStream, inner: Arc<InspectorInner>) {
    let mut conn = Conn::new(stream);
    loop {
        let request = match conn.read_request(MAX_REQUEST_BODY).await {
            Ok(Some(r)) => r,
            Ok(None) | Err(ReadError::Io) => return,
            Err(ReadError::Reject(status, reason)) => {
                let _ = conn.write_reject(status, reason).await;
                return;
            }
        };
        let keep_alive = request.keep_alive();
        let head_only = request.method == "HEAD";
        let readable = request.method == "GET" || head_only;
        let path = request.url.split('?').next().unwrap_or("/");
        let response = match route(path) {
            Route::NotFound => text_response(404, ""),
            _ if !readable => {
                let mut r = text_response(405, "");
                r.headers_mut()
                    .insert("allow", HeaderValue::from_static("GET,HEAD"));
                r
            }
            Route::Version => json_response(&version_doc(&inner)),
            Route::Protocol => json_response(&protocol_doc()),
            Route::Targets => json_response(&targets_doc(&inner)),
            Route::Devtools => {
                let accept = if head_only { None } else { upgrade_accept(&request) };
                match accept {
                    Some(accept) => {
                        let reply = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\
                             connection: Upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
                        );
                        if conn.write_raw(reply.as_bytes()).await.is_err() {
                            return;
                        }
                        let (io, ahead) = conn.into_parts();
                        session(Ws::new(io, ahead), inner).await;
                        return;
                    }
                    None => text_response(400, "burn: expected a WebSocket upgrade"),
                }
            }
        };
        if conn
            .write_response(&response, request.minor, head_only, keep_alive)
            .await
            .is_err()
            || !keep_alive
        {
            return;
        }
    }
}

/// The `Sec-WebSocket-Accept` value when `request` is a valid WebSocket
/// upgrade (RFC 6455 section 4.2.1), else `None`.
fn upgrade_accept(request: &crate::daemon_http::h1::Request) -> Option<String> {
    let token = |name: &str, wanted: &str| {
        request
            .header(name)
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(wanted)))
    };
    if !token("upgrade", "websocket")
        || !token("connection", "upgrade")
        || request.header("sec-websocket-version") != Some("13")
    {
        return None;
    }
    request
        .header("sec-websocket-key")
        .filter(|k| !k.is_empty())
        .map(ws::accept_key)
}

fn json_response(value: &serde_json::Value) -> Response<Vec<u8>> {
    let mut response = Response::new(serde_json::to_vec(value).unwrap_or_default());
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/json"),
    );
    response
}

fn version_doc(inner: &InspectorInner) -> serde_json::Value {
    let port = inner.bound_port.load(Ordering::Acquire);
    json!({
        "Browser": "burn/1.0",
        "Protocol-Version": "1.3",
        "User-Agent": "burn-cdp/1.0",
        "V8-Version": "Afterburner",
        "WebKit-Version": "0.0",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/burn-{port}"),
    })
}

fn protocol_doc() -> serde_json::Value {
    // Real Node ships a 6 KiB protocol descriptor here. We embed a
    // minimal shape so DevTools' GET /json/protocol succeeds even
    // without a full document.
    json!({
        "version": { "major": "1", "minor": "3" },
        "domains": [
            { "domain": "Runtime" },
            { "domain": "Debugger" },
            { "domain": "HeapProfiler" },
            { "domain": "Profiler" },
            { "domain": "Inspector" },
        ],
    })
}

fn targets_doc(inner: &InspectorInner) -> serde_json::Value {
    let port = inner.bound_port.load(Ordering::Acquire);
    json!([{
        "description": "burn instance",
        "devtoolsFrontendUrl": format!(
            "devtools://devtools/bundled/inspector.html?ws=127.0.0.1:{port}/devtools/page/burn-{port}"
        ),
        "id": format!("burn-{port}"),
        "title": "burn",
        "type": "node",
        "url": "burn://main",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/burn-{port}"),
    }])
}

// ---- WebSocket session ----------------------------------------

async fn session(mut socket: Ws<TcpStream>, inner: Arc<InspectorInner>) {
    let session_id = inner.next_session_id.fetch_add(1, Ordering::Relaxed);
    let (out_tx, mut out_rx) = nuclei::sync::mpsc::unbounded_channel::<String>();
    inner.sessions.insert(session_id, out_tx);

    // Notify JS that a session opened so it can send the
    // `Runtime.executionContextCreated` notification once
    // Runtime.enable arrives.
    inner.events_tx.send(InspectorEvent {
        session_id,
        kind: InspectorEventKind::SessionOpened,
    });

    // One task serves both directions: client frames in, queued CDP replies
    // and notifications out. When the socket closes we notify JS so any
    // per-session state can be cleaned up.
    loop {
        nuclei::select! {
            incoming = socket.next() => {
                let text = match incoming {
                    Ok(Message::Text(t)) => t,
                    Ok(Message::Binary(b)) => match String::from_utf8(b) {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                    Ok(Message::Ping(payload)) => {
                        if socket.send_pong(&payload).await.is_err() {
                            break;
                        }
                        continue;
                    }
                    Ok(Message::Pong) => continue,
                    Ok(Message::Close(payload)) => {
                        let _ = socket.send_close(&payload).await;
                        break;
                    }
                    Err(_) => break,
                };
                if intercept_resume(&inner, session_id, &text) {
                    continue;
                }
                inner.events_tx.send(InspectorEvent {
                    session_id,
                    kind: InspectorEventKind::Message(text),
                });
            }
            outgoing = out_rx.recv() => {
                match outgoing {
                    Some(payload) => {
                        if socket.send_text(&payload).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = socket.send_close(&[3, 232]).await;
                        break;
                    }
                }
            }
        }
    }

    inner.sessions.remove(&session_id);
    inner.events_tx.send(InspectorEvent {
        session_id,
        kind: InspectorEventKind::SessionClosed,
    });
}

/// Intercept resume-class commands on the Rust side: when the
/// JS instance is parked in `host_inspector_pause`, the WS
/// event-loop can't route the resume through JS (the wasmtime
/// store is busy). Wake the pause channel directly here. Returns
/// `true` when `text` was such a command and is fully handled.
fn intercept_resume(inner: &InspectorInner, session_id: SessionId, text: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    let Some(method) = v.get("method").and_then(|m| m.as_str()) else {
        return false;
    };
    let code = match method {
        "Debugger.resume" => 0,
        "Debugger.stepOver" => 1,
        "Debugger.stepInto" => 2,
        "Debugger.stepOut" => 3,
        _ => return false,
    };
    let ids: Vec<i64> = inner.pause_signals.iter().map(|(id, _)| id).collect();
    for id in ids {
        if let Some(tx) = inner.pause_signals.remove(&id) {
            tx.send(code);
        }
    }
    // Send the spec ack so the client's pending id
    // resolves. The JS dispatcher also handles this
    // method but for the no-paused case its result is
    // identical (`{}`).
    if let Some(id) = v.get("id").and_then(|x| x.as_i64()) {
        let reply = serde_json::json!({"id": id, "result": {}}).to_string();
        if let Some(s) = inner.sessions.get(&session_id) {
            let _ = s.send(reply);
        }
    }
    true
}
