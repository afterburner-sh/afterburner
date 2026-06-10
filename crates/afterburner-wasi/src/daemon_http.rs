// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Daemon HTTP coordinator — host-side state that backs
//! `__host_http_listen` / `__host_http_reply`.
//!
//! Owns the axum listeners spawned by user scripts' `.listen(port)`
//! calls and the per-request reply channels that ferry
//! `ServerResponse.end(body)` output back to the waiting axum task.
//!
//! Listener binding happens synchronously so `.listen(3000)` that
//! collides with an already-used port surfaces EADDRINUSE immediately
//! (matching Node), and `server.close()` releases the port via the
//! `__host_http_close` import. The `ports_in_use` map keyed by port
//! provides O(1) within-process collision detection without racing
//! against the OS.
//!
//! The coordinator lives inside an `Arc<DaemonHttp>` attached to
//! `HostState::daemon_http` on the daemon runtime's long-lived
//! Store. One-shot UDF / script thrusts leave it as `None` so they
//! don't pay the coordinator's cost.
//!
//! Axum listener plumbing lives behind the `daemon` feature.
//! Without the feature, `DaemonHttp` is a pure-accounting stub: it
//! reserves `server_id`s and records `pending` reply slots, but
//! never binds a real socket. The `burn` CLI enables the feature;
//! library consumers who only run UDF / one-shot scripts leave it off.

use kovan_map::HopscotchMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};

/// Opaque identifier the JS side uses to key handlers and requests.
pub type ServerId = i32;
pub type ReqId = i64;

/// Per-listener state.
#[derive(Debug, Clone)]
pub struct ListenerSlot {
    pub port: u16,
}

/// Per-request state the host keeps while an in-flight request is
/// waiting on JS to call `res.end()`. Populated when axum receives
/// the request; consumed by `__host_http_reply`.
#[derive(Clone)]
pub struct PendingReply {
    pub sender: kovan_channel::flavors::bounded::Sender<ReplyEnvelope>,
}

/// Response payload the JS side hands back via `__host_http_reply`.
#[derive(Debug, Clone)]
pub struct ReplyEnvelope {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Incoming event dispatched from the axum listener to the daemon
/// event loop. The CLI's dispatcher thread wraps this in a
/// `{mode: "daemon-event", event: ...}` envelope for the plugin.
#[derive(Debug, Clone)]
pub struct DaemonEvent {
    pub server_id: ServerId,
    pub req_id: ReqId,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Negative return codes for `__host_http_listen`. Mirrored in
/// `polyfills/http.js` — keep them in sync.
pub const LISTEN_ERR_NO_DAEMON: i32 = -1;
pub const LISTEN_ERR_ADDR_IN_USE: i32 = -2;
pub const LISTEN_ERR_IO: i32 = -3;
/// The manifold's `listen` axis does not grant the requested port.
/// Same `PermissionDenied` taxonomy as outbound net / fs denials: the
/// host records a "permission denied" `last_error` and the JS polyfill
/// surfaces `EACCES` with that detail.
pub const LISTEN_ERR_PERMISSION: i32 = -4;

/// Outcome of `try_claim_port_for`. Sibling-protocol coordinators
/// branch on this: [`Owner`] performs the bind; [`Follower`] returns
/// the existing id without binding (shared-listeners shard rejoin);
/// [`Busy`] is the unshared-mode collision path.
#[derive(Debug, Clone, Copy)]
pub enum PortClaim {
    Owner(ServerId),
    Follower(ServerId),
    Busy,
}

/// Host-side coordinator attached to `HostState::daemon_http` when a
/// script enters daemon mode.
pub struct DaemonHttp {
    next_server_id: AtomicI32,
    next_req_id: AtomicI64,
    listeners: HopscotchMap<ServerId, ListenerSlot>,
    /// port → owning server_id. Lets the next `.listen()` on
    /// the same port fail with EADDRINUSE without racing through the
    /// OS bind, and keeps close() accounting honest.
    ports_in_use: HopscotchMap<u16, ServerId>,
    /// Parallel claim map for QUIC/UDP listeners. Same shape as
    /// `ports_in_use` — a port can be simultaneously claimed by an
    /// HTTP TCP listener (this map's TCP sibling) and an H3 UDP
    /// listener (this map). The two are independent because TCP and
    /// UDP are distinct sockets at the kernel level; sharing the
    /// port number is RFC-legal.
    h3_ports_in_use: HopscotchMap<u16, ServerId>,
    pending: HopscotchMap<ReqId, PendingReply>,
    /// When true, `bind_listener` for an already-bound port returns
    /// the existing `server_id` instead of `LISTEN_ERR_ADDR_IN_USE`.
    /// This is the multi-shard contract: every shard's daemon-init
    /// runs the same source, so each shard calls `app.listen(port)`,
    /// but only the first call binds a real socket — subsequent calls
    /// register the handler under the same id and let the dispatcher
    /// route requests to whichever shard is least busy.
    ///
    /// Off by default so single-shard daemons preserve Node's
    /// "EADDRINUSE on double-listen" semantics. Multi-shard arbitration
    /// is fully lock-free: `HopscotchMap::get_or_insert` (CAS-based
    /// in `kovan_map`) atomically resolves which shard claims the
    /// port. Losers see the winner's id without taking any lock.
    shared_listeners: AtomicBool,

    /// Daemon-feature channel — axum handlers push `DaemonEvent`s
    /// through here; the CLI's dispatcher thread pops them off and
    /// calls `DaemonRuntime::dispatch_event`. `None` in stub mode
    /// (no `with_runtime` call).
    #[cfg(feature = "daemon")]
    event_tx: Option<kovan_channel::flavors::bounded::Sender<DaemonEvent>>,
    #[cfg(feature = "daemon")]
    event_rx: Option<kovan_channel::flavors::bounded::Receiver<DaemonEvent>>,

    /// Abort handles per listener so `server.close()` can release
    /// the port cleanly. `tokio::task::AbortHandle` is `Clone` so it
    /// stores fine inside the kovan map; aborting cancels the axum
    /// `serve` future, which drops the bound `TcpListener`.
    #[cfg(feature = "daemon")]
    listener_tasks: HopscotchMap<ServerId, tokio::task::AbortHandle>,

    /// Tokio runtime handle used to spawn axum listener tasks. `None`
    /// in stub mode — any call to `bind_listener` without a handle
    /// logs and returns a negative error.
    #[cfg(feature = "daemon")]
    runtime: Option<tokio::runtime::Handle>,
}

impl fmt::Debug for DaemonHttp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonHttp")
            .field(
                "next_server_id",
                &self.next_server_id.load(Ordering::Relaxed),
            )
            .field("next_req_id", &self.next_req_id.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for DaemonHttp {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonHttp {
    /// Stub-mode constructor — no runtime attached, so
    /// `bind_listener` allocates a `server_id` without binding a
    /// real socket. Used by tests that exercise the plugin ↔ host
    /// ABI directly.
    pub fn new() -> Self {
        Self {
            next_server_id: AtomicI32::new(1),
            next_req_id: AtomicI64::new(1),
            listeners: HopscotchMap::new(),
            ports_in_use: HopscotchMap::new(),
            h3_ports_in_use: HopscotchMap::new(),
            pending: HopscotchMap::new(),
            shared_listeners: AtomicBool::new(false),
            #[cfg(feature = "daemon")]
            event_tx: None,
            #[cfg(feature = "daemon")]
            event_rx: None,
            #[cfg(feature = "daemon")]
            listener_tasks: HopscotchMap::new(),
            #[cfg(feature = "daemon")]
            runtime: None,
        }
    }

    /// Switch the coordinator into shared-listener mode. Must be
    /// called BEFORE any `bind_listener` call — flipping this mid-
    /// flight would race with in-flight binds. Multi-shard pools
    /// flip this at construction.
    pub fn enable_shared_listeners(&self) {
        self.shared_listeners.store(true, Ordering::Release);
    }

    /// Whether shared-listener mode is on.
    pub fn is_shared_listeners(&self) -> bool {
        self.shared_listeners.load(Ordering::Acquire)
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Real-mode constructor — `bind_listener` will actually bind a
    /// TCP socket and spawn an axum service on the supplied
    /// runtime. `event_queue_cap` bounds the axum→dispatcher
    /// channel; overflow backpressures incoming requests.
    #[cfg(feature = "daemon")]
    pub fn with_runtime(handle: tokio::runtime::Handle, event_queue_cap: usize) -> Arc<Self> {
        let (tx, rx) = kovan_channel::bounded(event_queue_cap);
        Arc::new(Self {
            next_server_id: AtomicI32::new(1),
            next_req_id: AtomicI64::new(1),
            listeners: HopscotchMap::new(),
            ports_in_use: HopscotchMap::new(),
            h3_ports_in_use: HopscotchMap::new(),
            pending: HopscotchMap::new(),
            shared_listeners: AtomicBool::new(false),
            event_tx: Some(tx),
            event_rx: Some(rx),
            listener_tasks: HopscotchMap::new(),
            runtime: Some(handle),
        })
    }

    /// Number of currently-registered listeners. B2.5 uses this to
    /// decide whether `burn foo.js` should exit after running daemon-
    /// init (no listeners → plain script) or enter the event loop
    /// (listeners present → daemon).
    pub fn listener_count(&self) -> usize {
        let seen = self.next_server_id.load(Ordering::Relaxed);
        (1..seen)
            .filter(|id| self.listeners.get(id).is_some())
            .count()
    }

    /// Stub-mode listener registration — reserves a `server_id`
    /// without binding. Returned for tests / abstract drivers.
    /// Still honours within-process port collisions so stub-mode
    /// tests exercise the EADDRINUSE path.
    ///
    /// In shared-listener mode (multi-shard pool), an already-bound
    /// port returns the existing id instead of erroring — first call
    /// "binds" (registers), subsequent calls just rejoin.
    ///
    /// Lock-free port arbitration via `HopscotchMap::get_or_insert`
    /// (CAS-based in kovan_map). N shards racing on the same port
    /// converge atomically: exactly one shard's id wins; the others
    /// see it without ever taking a lock.
    pub fn register_listener(&self, port: u16) -> ServerId {
        let new_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
        let claimed = self.ports_in_use.get_or_insert(port, new_id);
        if claimed != new_id {
            // Another shard claimed first.
            if self.shared_listeners.load(Ordering::Acquire) {
                return claimed;
            }
            return LISTEN_ERR_ADDR_IN_USE;
        }
        self.listeners.insert(new_id, ListenerSlot { port });
        new_id
    }

    /// Release a listener's port + accounting. Called from
    /// `__host_http_close` via `server.close()` in JS. Returns
    /// `true` if the server_id was known.
    ///
    /// On the daemon path this also aborts the axum task so the
    /// socket is freed and a subsequent `.listen(port)` in the same
    /// process succeeds.
    pub fn close_listener(&self, id: ServerId) -> bool {
        let Some(slot) = self.listeners.remove(&id) else {
            return false;
        };
        self.ports_in_use.remove(&slot.port);
        #[cfg(feature = "daemon")]
        {
            if let Some(handle) = self.listener_tasks.remove(&id) {
                handle.abort();
            }
        }
        true
    }

    /// Fetch (and remove) a pending reply slot. Called from
    /// `__host_http_reply` to signal the axum task.
    pub fn take_reply(&self, req_id: ReqId) -> Option<PendingReply> {
        self.pending.remove(&req_id)
    }

    /// Install a pending reply slot; returns the `req_id` the JS
    /// side should later hand to `__host_http_reply`.
    pub fn register_pending(
        &self,
        sender: kovan_channel::flavors::bounded::Sender<ReplyEnvelope>,
    ) -> ReqId {
        let id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        self.pending.insert(id, PendingReply { sender });
        id
    }

    /// Signal the pending reply for `req_id` with the response
    /// payload the JS side handed to `__host_http_reply`. Returns
    /// `true` if a waiter was present. Missing slots are silently
    /// dropped — the most likely cause is a stale reply after the
    /// axum task already timed out or disconnected.
    pub fn deliver_reply(&self, req_id: ReqId, reply: ReplyEnvelope) -> bool {
        if let Some(PendingReply { sender }) = self.pending.remove(&req_id) {
            sender.send(reply);
            true
        } else {
            false
        }
    }

    /// Three-way claim outcome for sibling-protocol coordinators (H3,
    /// any future transport). [`PortClaim::Owner`] means this caller
    /// won the CAS and must perform the real bind; [`PortClaim::
    /// Follower`] means another shard already bound the port — the
    /// caller should *not* bind, just register its JS handler under
    /// the existing id (shared-listeners mode); [`PortClaim::Busy`]
    /// is the single-shard collision path.
    pub fn try_claim_port_for(&self, port: u16) -> PortClaim {
        let new_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
        let claimed = self.ports_in_use.get_or_insert(port, new_id);
        if claimed != new_id {
            if self.shared_listeners.load(Ordering::Acquire) {
                return PortClaim::Follower(claimed);
            }
            return PortClaim::Busy;
        }
        self.listeners.insert(new_id, ListenerSlot { port });
        PortClaim::Owner(new_id)
    }

    /// Back-compat shim — the H3 path used to call this. Routes to
    /// [`Self::try_claim_port_for`] and flattens to a positive id (
    /// owner or follower) or a negative LISTEN_ERR. Only the owner
    /// path should bind; callers that need the distinction should
    /// use the typed [`PortClaim`] variant directly.
    pub fn allocate_server_id_for(&self, port: u16) -> ServerId {
        match self.try_claim_port_for(port) {
            PortClaim::Owner(id) | PortClaim::Follower(id) => id,
            PortClaim::Busy => LISTEN_ERR_ADDR_IN_USE,
        }
    }

    /// Release a port claim AND its listener-slot accounting (used by
    /// sibling-protocol coordinators when their bind fails after
    /// [`Self::allocate_server_id_for`] already ran). Both removals
    /// are required — leaving the listener slot in place keeps
    /// `listener_count() > 0`, which triggers shard-pool expansion
    /// and re-evaluates the script across N shards (which in turn
    /// re-calls the failing listen, looping).
    pub fn release_port(&self, port: u16) {
        if let Some(id) = self.ports_in_use.remove(&port) {
            self.listeners.remove(&id);
        }
    }

    /// QUIC sibling of [`Self::try_claim_port_for`]. Independent map
    /// (`h3_ports_in_use`) so the same port number can be claimed by
    /// a TCP listener (HTTP/1+H2) and a UDP listener (H3) at the same
    /// time, exactly as the kernel allows.
    pub fn try_claim_h3_port(&self, port: u16) -> PortClaim {
        // Negative sentinel pool — we don't need a real `server_id`
        // here, just a "did I win the CAS" signal. UDP-side
        // `server_id` for event dispatch comes from the JS-side
        // HTTP listener.
        let new_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
        let claimed = self.h3_ports_in_use.get_or_insert(port, new_id);
        if claimed != new_id {
            if self.shared_listeners.load(Ordering::Acquire) {
                return PortClaim::Follower(claimed);
            }
            return PortClaim::Busy;
        }
        PortClaim::Owner(new_id)
    }

    pub fn release_h3_port(&self, port: u16) {
        self.h3_ports_in_use.remove(&port);
    }

    /// Register an abort handle for a sibling listener task so
    /// `server.close()` aborts it cleanly.
    #[cfg(feature = "daemon")]
    pub fn register_listener_task(&self, id: ServerId, abort: tokio::task::AbortHandle) {
        self.listener_tasks.insert(id, abort);
    }

    /// Tokio runtime handle attached to the coordinator. `None` in
    /// stub mode (no `with_runtime` call). Sibling coordinators that
    /// need to spawn tasks call this once at bind time.
    #[cfg(feature = "daemon")]
    pub fn runtime_handle(&self) -> Option<tokio::runtime::Handle> {
        self.runtime.clone()
    }

    /// Sender side of the daemon event channel — sibling coordinators
    /// (HTTP/3 etc.) push their incoming requests onto the same
    /// channel the H1/H2 axum loop uses, so JS sees one unified
    /// dispatch stream.
    #[cfg(feature = "daemon")]
    pub fn event_sender(&self) -> Option<kovan_channel::flavors::bounded::Sender<DaemonEvent>> {
        self.event_tx.clone()
    }

    /// Bind a TCP listener on `port` synchronously; on success,
    /// register the accepted socket with axum on the stored runtime
    /// handle and return the new `server_id`.
    ///
    /// Returns:
    ///
    /// * positive `server_id` — bound and serving.
    /// * [`LISTEN_ERR_NO_DAEMON`] (-1) — coordinator constructed via
    ///   [`Self::new`] / [`Self::shared`] (no runtime). Stub path:
    ///   allocate id without binding, preserving ABI-test symmetry.
    /// * [`LISTEN_ERR_ADDR_IN_USE`] (-2) — port already bound, by us
    ///   or by the OS.
    /// * [`LISTEN_ERR_IO`] (-3) — any other bind failure (permission
    ///   denied on a privileged port, interface vanished, etc.).
    ///
    /// The synchronous bind closes the race where a stale axum task
    /// silently owned a port: if the OS refuses the bind we return a
    /// typed error *before* allocating a `server_id`, so JS sees
    /// the failure up front rather than via a stderr eprintln.
    #[cfg(feature = "daemon")]
    pub fn bind_listener(self: &Arc<Self>, port: u16) -> i32 {
        let (Some(runtime), Some(event_tx)) = (self.runtime.as_ref(), self.event_tx.clone()) else {
            // Stub path still enforces within-process collision so
            // the no-runtime tests exercise the same EADDRINUSE edge.
            return self.register_listener(port);
        };

        // Lock-free port arbitration. `get_or_insert` is a CAS in
        // kovan_map's HopscotchMap — N shards racing converge
        // atomically: exactly one's `new_id` becomes the claim.
        let new_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
        let claimed_id = self.ports_in_use.get_or_insert(port, new_id);
        if claimed_id != new_id {
            // Another shard claimed first.
            if self.shared_listeners.load(Ordering::Acquire) {
                return claimed_id;
            }
            return LISTEN_ERR_ADDR_IN_USE;
        }

        // We own the claim. Bind the real socket. When the process is
        // a forked cluster worker (`BURN_CLUSTER_REUSEPORT=1`) the
        // bind goes through the SO_REUSEPORT path so sibling worker
        // subprocesses can co-bind the same port and the kernel
        // 4-tuple-balances accept().
        let bind_addr: std::net::SocketAddr = match format!("127.0.0.1:{port}").parse() {
            Ok(a) => a,
            Err(_) => {
                self.ports_in_use.remove(&port);
                return LISTEN_ERR_IO;
            }
        };
        let std_listener = match crate::daemon_cluster::build_tcp_listener(bind_addr) {
            Ok(l) => l,
            Err(crate::daemon_cluster::ClusterBindError::AddrInUse) => {
                self.ports_in_use.remove(&port);
                return LISTEN_ERR_ADDR_IN_USE;
            }
            Err(crate::daemon_cluster::ClusterBindError::Io(_)) => {
                self.ports_in_use.remove(&port);
                return LISTEN_ERR_IO;
            }
        };
        if std_listener.set_nonblocking(true).is_err() {
            self.ports_in_use.remove(&port);
            return LISTEN_ERR_IO;
        }
        // `TcpListener::from_std` registers the raw fd with the tokio
        // reactor — it panics if called outside a runtime context.
        // Enter the runtime synchronously for the duration of the
        // conversion + spawn so the host function can stay sync.
        let _enter = runtime.enter();
        let tokio_listener = match tokio::net::TcpListener::from_std(std_listener) {
            Ok(l) => l,
            Err(_) => {
                self.ports_in_use.remove(&port);
                return LISTEN_ERR_IO;
            }
        };

        // Bound. Publish the listener slot + axum task.
        self.listeners.insert(new_id, ListenerSlot { port });

        let coord = Arc::clone(self);
        let handle = runtime.spawn(axum_server::serve_listener(
            tokio_listener,
            new_id,
            coord,
            event_tx,
        ));
        self.listener_tasks.insert(new_id, handle.abort_handle());
        new_id
    }

    /// Non-daemon-feature variant — allocates an id without binding
    /// a real socket. Matches the stub behaviour pre-B2.4 so test
    /// harnesses exercising the plugin ABI still work without the
    /// `daemon` feature.
    #[cfg(not(feature = "daemon"))]
    pub fn bind_listener(self: &Arc<Self>, port: u16) -> i32 {
        self.register_listener(port)
    }

    /// Pop the next event off the axum→dispatcher channel. Blocks
    /// until one arrives or the channel disconnects (all senders
    /// dropped). The CLI's dispatcher thread drives this in a loop
    /// until it receives a shutdown signal.
    #[cfg(feature = "daemon")]
    pub fn recv_event(&self) -> Option<DaemonEvent> {
        self.event_rx.as_ref().and_then(|rx| rx.recv())
    }

    /// Non-daemon-feature recv — always returns None since no axum
    /// task is pushing events.
    #[cfg(not(feature = "daemon"))]
    pub fn recv_event(&self) -> Option<DaemonEvent> {
        None
    }

    /// Non-blocking event pop. Returns `None` when the queue is
    /// empty (distinct from the channel being closed). Useful for
    /// dispatcher loops that need a shutdown signal orthogonal to
    /// the event stream.
    #[cfg(feature = "daemon")]
    pub fn try_recv_event(&self) -> Option<DaemonEvent> {
        self.event_rx.as_ref().and_then(|rx| rx.try_recv())
    }

    #[cfg(not(feature = "daemon"))]
    pub fn try_recv_event(&self) -> Option<DaemonEvent> {
        None
    }
}

#[cfg(feature = "daemon")]
mod axum_server {
    //! axum handler wiring for incoming HTTP requests. Each listener
    //! spawned by `bind_listener` runs its own `serve` task; the
    //! handler converts the request into a `DaemonEvent`, ships it
    //! to the dispatcher thread via the shared channel, and awaits
    //! the reply that `__host_http_reply` delivers.

    use super::*;

    /// Drive an already-bound listener through axum. Used by the
    /// path where `bind_listener` performs a synchronous bind so
    /// EADDRINUSE surfaces to JS before we ever allocate a server_id.
    pub(super) async fn serve_listener(
        listener: tokio::net::TcpListener,
        server_id: ServerId,
        coord: Arc<DaemonHttp>,
        _event_tx: kovan_channel::flavors::bounded::Sender<DaemonEvent>,
    ) {
        // Per-connection accept loop. `hyper-util::server::conn::auto`
        // inspects the first ~24 bytes of the accepted socket: if it
        // sees the H2 connection preface
        // (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) it serves H2 frames
        // (multiplexed streams, HPACK headers); otherwise it falls
        // back to HTTP/1.1. One listener thus serves both protocols
        // transparently, so `http2.createServer().listen()` and
        // `http.createServer().listen()` route through the same path
        // and the wire negotiation is invisible from the JS side.
        use hyper::service::service_fn;
        use hyper_util::rt::{TokioExecutor, TokioIo};

        let state = Arc::new(ServerState {
            server_id,
            coord: Arc::clone(&coord),
        });
        loop {
            let (socket, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("burn: serve_listener({server_id}): accept failed: {e}");
                    return;
                }
            };
            let conn_state = Arc::clone(&state);
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let conn_state = Arc::clone(&conn_state);
                    async move {
                        Ok::<_, std::convert::Infallible>(dispatch_hyper(conn_state, req).await)
                    }
                });
                let io = TokioIo::new(socket);
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let _ = builder.serve_connection_with_upgrades(io, svc).await;
            });
        }
    }

    /// hyper-native dispatcher — same flow as the axum `dispatch_request`
    /// but operates on `hyper::Request<Incoming>` so the H1/H2 auto
    /// negotiation can hand us the request directly.
    async fn dispatch_hyper(
        state: Arc<ServerState>,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> hyper::Response<axum::body::Body> {
        use http_body_util::BodyExt;

        let (parts, body) = req.into_parts();
        let method = parts.method.to_string();
        let url = parts
            .uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".into());
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        const MAX_BODY: usize = 16 * 1024 * 1024;
        let collected = match body.collect().await {
            Ok(c) => c,
            Err(e) => {
                let mut resp = hyper::Response::new(axum::body::Body::from(format!(
                    "burn: request body: {e}"
                )));
                *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
                return resp;
            }
        };
        let body_bytes = collected.to_bytes();
        if body_bytes.len() > MAX_BODY {
            let mut resp = hyper::Response::new(axum::body::Body::from(format!(
                "burn: request body exceeds {} bytes",
                MAX_BODY
            )));
            *resp.status_mut() = hyper::StatusCode::PAYLOAD_TOO_LARGE;
            return resp;
        }

        let (reply_tx, reply_rx) = kovan_channel::bounded::<ReplyEnvelope>(1);
        let req_id = state.coord.register_pending(reply_tx);
        let event = DaemonEvent {
            server_id: state.server_id,
            req_id,
            method,
            url,
            headers,
            body: body_bytes.to_vec(),
        };
        let Some(event_tx) = state.coord.event_tx.as_ref() else {
            let mut resp = hyper::Response::new(axum::body::Body::from(
                "burn: daemon not running\n".to_string(),
            ));
            *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
            return resp;
        };
        event_tx.send_async(event).await;
        let reply = reply_rx.recv_async().await;

        let mut builder = hyper::Response::builder().status(reply.status);
        for (name, value) in &reply.headers {
            builder = builder.header(name, value);
        }
        match builder.body(axum::body::Body::from(reply.body)) {
            Ok(r) => r,
            Err(_) => {
                let mut resp = hyper::Response::new(axum::body::Body::from(
                    "burn: response build failed".to_string(),
                ));
                *resp.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
                resp
            }
        }
    }

    #[derive(Clone)]
    struct ServerState {
        server_id: ServerId,
        coord: Arc<DaemonHttp>,
    }
}

use std::fmt;
