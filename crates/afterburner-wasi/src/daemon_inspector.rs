// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Inspector / Chrome DevTools Protocol bridge.
//!
//! Boots an axum HTTP+WebSocket listener bound to an inspector port
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

use axum::Router;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::{Json, Response};
use axum::routing::get;
use serde_json::json;
use tokio::sync::mpsc::UnboundedSender as TokioUnboundedSender;
use tokio::task::JoinHandle;

pub type SessionId = i32;

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

/// Shared state across the axum router and the daemon event loop.
struct InspectorInner {
    next_session_id: AtomicI32,
    /// Per-session outbound channel: the dispatcher pushes frames the
    /// WS writer drains. Tokio unbounded so the JS handler never
    /// blocks; backpressure isn't needed at CDP scale (a single human
    /// debugger driving the protocol).
    sessions: HopscotchMap<SessionId, TokioUnboundedSender<String>>,
    events_tx: Sender<InspectorEvent>,
    events_rx: Receiver<InspectorEvent>,
    bound_port: AtomicU16,
    /// Active breakpoint pause channels. Keyed by pause_id. When a JS
    /// breakpoint fires, the JS side calls `host_inspector_pause`
    /// which inserts a (pause_id, Sender) here and blocks on the
    /// matching Receiver. The WebSocket reader intercepts
    /// `Debugger.resume`/`stepOver`/`stepInto`/`stepOut` messages on
    /// the Rust side (not in JS) and signals the Sender, unblocking
    /// the paused wasmtime instance. Going through JS would deadlock
    /// — the wasmtime instance is what's blocked.
    pause_signals: HopscotchMap<i64, kovan_channel::flavors::bounded::Sender<i32>>,
    next_pause_id: AtomicI64,
}

/// Public coordinator handle stored on `HostState::daemon_inspector`.
pub struct DaemonInspector {
    inner: Arc<InspectorInner>,
    runtime: tokio::runtime::Handle,
    server_task: parking_lot_free::OnceCell<JoinHandle<()>>,
}

/// Tiny once-cell used because we want one-shot publish of the
/// listener task without pulling in std's Mutex. `JoinHandle` is
/// Clone-free, so we can't store it in a HopscotchMap; this cell
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
    pub fn new(runtime: tokio::runtime::Handle) -> Arc<Self> {
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
    /// 2 for stepInto, 3 for stepOut — so the JS side can react
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

    /// Drain any pending pause signals — used on listener teardown so
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
        if std_listener.set_nonblocking(true).is_err() {
            return ERR_BIND;
        }
        let listener = match tokio::net::TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(_) => return ERR_BIND,
        };
        inner.bound_port.store(actual_port, Ordering::Release);

        let app = Router::new()
            .route("/json", get(json_targets))
            .route("/json/list", get(json_targets))
            .route("/json/version", get(json_version))
            .route("/json/protocol", get(json_protocol))
            .route("/devtools/page/{id}", get(ws_handler))
            .with_state(Arc::clone(&inner));

        let task = self.runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        self.server_task.set(task);
        actual_port as i32
    }

    /// Tear down the inspector listener and disconnect every session.
    /// Idempotent.
    pub fn close(&self) -> i32 {
        if self.bound_port() == 0 {
            return ERR_NOT_OPEN;
        }
        if let Some(t) = self.server_task.take() {
            t.abort();
        }
        // Drop every per-session sender. The WS writer task observes
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

// ---- HTTP discovery handlers ----------------------------------

async fn json_version(State(inner): State<Arc<InspectorInner>>) -> Json<serde_json::Value> {
    let port = inner.bound_port.load(Ordering::Acquire);
    Json(json!({
        "Browser": "burn/1.0",
        "Protocol-Version": "1.3",
        "User-Agent": "burn-cdp/1.0",
        "V8-Version": "Afterburner",
        "WebKit-Version": "0.0",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/burn-{port}"),
    }))
}

async fn json_protocol() -> Json<serde_json::Value> {
    // Real Node ships a 6 KiB protocol descriptor here. We embed a
    // minimal shape so DevTools' GET /json/protocol succeeds even
    // without a full document.
    Json(json!({
        "version": { "major": "1", "minor": "3" },
        "domains": [
            { "domain": "Runtime" },
            { "domain": "Debugger" },
            { "domain": "HeapProfiler" },
            { "domain": "Profiler" },
            { "domain": "Inspector" },
        ],
    }))
}

async fn json_targets(State(inner): State<Arc<InspectorInner>>) -> Json<serde_json::Value> {
    let port = inner.bound_port.load(Ordering::Acquire);
    Json(json!([{
        "description": "burn instance",
        "devtoolsFrontendUrl": format!(
            "devtools://devtools/bundled/inspector.html?ws=127.0.0.1:{port}/devtools/page/burn-{port}"
        ),
        "id": format!("burn-{port}"),
        "title": "burn",
        "type": "node",
        "url": "burn://main",
        "webSocketDebuggerUrl": format!("ws://127.0.0.1:{port}/devtools/page/burn-{port}"),
    }]))
}

// ---- WebSocket upgrade ----------------------------------------

async fn ws_handler(State(inner): State<Arc<InspectorInner>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, inner))
}

async fn handle_ws(socket: WebSocket, inner: Arc<InspectorInner>) {
    use futures_util::{SinkExt, StreamExt};

    let session_id = inner.next_session_id.fetch_add(1, Ordering::Relaxed);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    inner.sessions.insert(session_id, out_tx);

    // Notify JS that a session opened so it can send the
    // `Runtime.executionContextCreated` notification once
    // Runtime.enable arrives.
    inner.events_tx.send(InspectorEvent {
        session_id,
        kind: InspectorEventKind::SessionOpened,
    });

    let (mut sink, mut stream) = socket.split();

    // Writer task — drains the per-session out channel into the WS.
    let writer = tokio::spawn(async move {
        while let Some(payload) = out_rx.recv().await {
            if sink.send(Message::Text(payload.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Reader loop — runs in this task. When the socket closes,
    // we abort the writer and notify JS so any per-session state
    // can be cleaned up.
    while let Some(msg) = stream.next().await {
        let bytes = match msg {
            // axum 0.8 / tungstenite ship Text as Utf8Bytes and Binary
            // as Bytes — convert both to owned String for downstream
            // serde_json parsing.
            Ok(Message::Text(t)) => t.to_string(),
            Ok(Message::Binary(b)) => match String::from_utf8(b.to_vec()) {
                Ok(s) => s,
                Err(_) => continue,
            },
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
            Ok(Message::Close(_)) => break,
            Err(_) => break,
        };
        // Intercept resume-class commands on the Rust side: when the
        // JS instance is parked in `host_inspector_pause`, the WS
        // event-loop can't route the resume through JS (the wasmtime
        // store is busy). Wake the pause channel directly here.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&bytes)
            && let Some(method) = v.get("method").and_then(|m| m.as_str())
        {
            let code = match method {
                "Debugger.resume" => Some(0),
                "Debugger.stepOver" => Some(1),
                "Debugger.stepInto" => Some(2),
                "Debugger.stepOut" => Some(3),
                _ => None,
            };
            if let Some(c) = code {
                let ids: Vec<i64> = inner.pause_signals.iter().map(|(id, _)| id).collect();
                for id in ids {
                    if let Some(tx) = inner.pause_signals.remove(&id) {
                        tx.send(c);
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
                continue;
            }
        }
        inner.events_tx.send(InspectorEvent {
            session_id,
            kind: InspectorEventKind::Message(bytes),
        });
    }

    inner.sessions.remove(&session_id);
    writer.abort();
    inner.events_tx.send(InspectorEvent {
        session_id,
        kind: InspectorEventKind::SessionClosed,
    });
}
