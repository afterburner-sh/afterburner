// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `net` - raw TCP host coordinator (B7).
//!
//! Backs the `net.createConnection` / `net.createServer` polyfill in
//! `polyfills/net.js`. The host owns every `tokio::net::TcpStream` and
//! `tokio::net::TcpListener`; the JS-side `Socket` / `Server` is a
//! thin façade that crosses into Rust through `__host_net_*` imports.
//!
//! ## Architecture
//!
//! Per connection, one tokio task drives both halves of the socket
//! through `tokio::select!`:
//!
//! ```text
//!   reader  ── stream.read() ────────────►  Data / End / Error events
//!   writer  ── tokio::sync::Notify ───────►  drain queue & write
//!                  ▲
//!                  │ wake on every send
//!   producer  ── kovan unbounded queue ───  __host_net_write
//! ```
//!
//! The wake `Notify` paired with `try_recv` gives us async semantics
//! over a kovan channel - no polling, no Mutex, no `tokio::sync::mpsc`
//! (workspace rule: kovan channels everywhere).
//!
//! ## Backpressure
//!
//! `socket.write()` returns `false` when the per-conn pending-byte
//! count exceeds 64 KiB. The writer task posts a `Drain` event the
//! moment the queue clears the threshold, mirroring Node.
//!
//! ## Lock-free
//!
//! `HopscotchMap<ConnId, ConnHandle>` for active connections,
//! `HopscotchMap<ServerId, ListenerHandle>` for listeners, atomics
//! for counters, kovan_channel for events. **No `Mutex` anywhere.**
//!
//! ## Manifold
//!
//! `net.connect` requires `NetAccess::OutboundFull` (raw TCP escapes
//! URL-shaped policy, so `OutboundHttp` is **rejected**). Hostname
//! allow-lists support exact matches, `*`, and `*.suffix` wildcards.
//! Inbound listening is daemon-mode-only; the library API never
//! installs a `DaemonNet` so `net.createServer` cleanly errors.

use afterburner_core::{Manifold, NetAccess};
use kovan_channel::flavors::bounded::{
    Receiver as BoundedRx, Sender as BoundedTx, channel as bounded_channel,
};
use kovan_channel::flavors::unbounded::{
    Receiver as UnboundedRx, Sender as UnboundedTx, channel as unbounded_channel,
};
use kovan_map::HopscotchMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::AbortHandle;

pub type ConnId = i32;
pub type ServerId = i32;

/// 64 KiB write high-water mark - matches Node's default Socket
/// `writableHighWaterMark`. Crossing it makes `write()` return false;
/// dropping back below fires `'drain'`.
pub const WRITE_HWM: usize = 64 * 1024;

/// 64 KiB read chunk granularity - matches Node's default. Larger
/// peer reads get split across multiple `'data'` events.
pub const READ_CHUNK: usize = 64 * 1024;

pub mod errors {
    pub const E_NO_DAEMON: i32 = -1;
    pub const E_PERMISSION: i32 = -2;
    pub const E_BAD_ID: i32 = -3;
    pub const E_BAD_HOST: i32 = -4;
    pub const E_BAD_PORT: i32 = -5;
    pub const E_BAD_PAYLOAD: i32 = -6;
    pub const E_OTHER: i32 = -7;
}

/// Events surfaced to the daemon event loop. The CLI converts these
/// into `{kind:"net-..."}` envelopes for the daemon-event dispatcher
/// to route into `__ab_net_handlers[conn_id]` /
/// `__ab_net_server_handlers[server_id]`.
#[derive(Debug, Clone)]
pub enum NetEvent {
    Connect {
        conn_id: ConnId,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
    },
    Connection {
        server_id: ServerId,
        conn_id: ConnId,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
    },
    Data {
        conn_id: ConnId,
        payload_b64: String,
    },
    End {
        conn_id: ConnId,
    },
    Drain {
        conn_id: ConnId,
    },
    Close {
        conn_id: ConnId,
        had_error: bool,
    },
    Error {
        conn_id: ConnId,
        message: String,
        code: String,
    },
    Listening {
        server_id: ServerId,
        port: u16,
    },
    ServerError {
        server_id: ServerId,
        message: String,
    },
}

/// Per-connection state kept in the lock-free registry. Cloning is
/// cheap (Arc + kovan Sender + AbortHandle, all `Clone`), so this
/// satisfies the `V: Clone` bound on `HopscotchMap`.
#[derive(Clone)]
struct ConnHandle {
    write_tx: UnboundedTx<WriteCmd>,
    /// Wakes the connection task's `tokio::select!` arm when a new
    /// `WriteCmd` lands on `write_tx`. Sender uses `notify_one`;
    /// receiver does `try_recv` then `notified().await`. Notify
    /// stores at most one permit so we never miss a wakeup, and it's
    /// implemented with atomics + wakers (no Mutex).
    wake: Arc<Notify>,
    /// Bytes pending the writer hasn't yet handed to the kernel. The
    /// polyfill reads this via `__host_net_pending(conn_id)` to
    /// implement Node-style backpressure on `write()`.
    pending_bytes: Arc<AtomicUsize>,
    /// Aborts the connection task on `socket.destroy()`.
    abort: AbortHandle,
    /// Idempotency latch for `socket.end()`.
    half_closed: Arc<AtomicBool>,
}

/// The bound port is announced via the `Listening` event; we don't
/// need to keep it in the registry.
#[derive(Clone)]
struct ListenerHandle {
    abort: AbortHandle,
}

enum WriteCmd {
    Bytes(Vec<u8>),
    End,
    /// `socket.setNoDelay(enable)` - toggles `TCP_NODELAY`. We route
    /// it through the same queue as writes so the option flip can't
    /// race with bytes already in flight (the worker task is the
    /// single owner of the stream).
    SetNoDelay(bool),
    /// `socket.setKeepAlive(enable[, initialDelayMs])`. `delay_ms` is
    /// the idle interval before the first keep-alive probe; ignored
    /// when `enable` is false.
    SetKeepAlive {
        enable: bool,
        delay_ms: i32,
    },
}

pub struct DaemonNet {
    runtime: Handle,
    manifold: Manifold,
    next_conn_id: AtomicI32,
    next_server_id: AtomicI32,
    conns: HopscotchMap<ConnId, ConnHandle>,
    servers: HopscotchMap<ServerId, ListenerHandle>,
    alive_conns: AtomicUsize,
    alive_servers: AtomicUsize,
    events_tx: BoundedTx<NetEvent>,
    events_rx: BoundedRx<NetEvent>,
    /// Multi-shard port arbiter. `Some` when this coordinator was
    /// built via `new_with_claims` (every shard's instance shares
    /// the same `Arc`). On `listen(port)`, the first shard to call
    /// `try_claim` becomes the kernel-level owner; subsequent
    /// shards become followers (allocate a local server_id, no
    /// real bind, no listener task). `None` means single-shard
    /// mode - `listen(port)` always tries the real bind.
    shared_claims: Option<Arc<crate::daemon_port_claims::SharedPortClaims>>,
    /// `server_id` → port for owners, so `close_server` can release
    /// the shared claim when the user calls `server.close()`.
    /// Followers are NOT in this map (they don't own the claim).
    owned_listener_ports: HopscotchMap<ServerId, u16>,
}

impl std::fmt::Debug for DaemonNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonNet")
            .field("alive_conns", &self.alive_conns.load(Ordering::Relaxed))
            .field("alive_servers", &self.alive_servers.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl DaemonNet {
    pub fn new(runtime: Handle, manifold: Manifold) -> Arc<Self> {
        Self::new_inner(runtime, manifold, None)
    }

    /// Construct a `DaemonNet` that participates in a multi-shard
    /// pool. The supplied `claims` is shared across every shard's
    /// `DaemonNet` instance, so `listen(port)` calls converge on a
    /// single owner without `EADDRINUSE` from sibling shards. See
    /// `daemon_port_claims` for the contract.
    pub fn new_with_claims(
        runtime: Handle,
        manifold: Manifold,
        claims: Arc<crate::daemon_port_claims::SharedPortClaims>,
    ) -> Arc<Self> {
        Self::new_inner(runtime, manifold, Some(claims))
    }

    fn new_inner(
        runtime: Handle,
        manifold: Manifold,
        shared_claims: Option<Arc<crate::daemon_port_claims::SharedPortClaims>>,
    ) -> Arc<Self> {
        let (tx, rx) = bounded_channel::<NetEvent>(4096);
        Arc::new(Self {
            runtime,
            manifold,
            next_conn_id: AtomicI32::new(1),
            // Server-accepted connections share the same id space as
            // client-side connections, but to avoid collisions when
            // both paths run concurrently we anchor server ids in a
            // disjoint range. Counter starts at 1; outbound connect
            // and accepted-connection allocation both go through
            // `next_conn_id` - a single monotonic counter - so each
            // socket gets a unique handle.
            next_server_id: AtomicI32::new(1),
            conns: HopscotchMap::new(),
            servers: HopscotchMap::new(),
            alive_conns: AtomicUsize::new(0),
            alive_servers: AtomicUsize::new(0),
            events_tx: tx,
            events_rx: rx,
            shared_claims,
            owned_listener_ports: HopscotchMap::new(),
        })
    }

    pub fn try_recv_event(&self) -> Option<NetEvent> {
        self.events_rx.try_recv()
    }

    pub fn has_refs(&self) -> bool {
        self.alive_conns.load(Ordering::Acquire) > 0
            || self.alive_servers.load(Ordering::Acquire) > 0
    }

    pub fn pending_bytes(&self, conn_id: ConnId) -> i32 {
        self.conns
            .get(&conn_id)
            .map(|h| h.pending_bytes.load(Ordering::Acquire) as i32)
            .unwrap_or(0)
    }

    /// Initiate an outbound TCP connect. Returns the new `conn_id`
    /// (≥1) on success or one of [`errors`] on Manifold rejection /
    /// bad input. The actual `connect(2)` happens asynchronously;
    /// success / failure is announced via `Connect` / `Error` events.
    pub fn connect(self: &Arc<Self>, host: &str, port: u16, last_error: &mut String) -> i32 {
        if !net_outbound_allowed(&self.manifold, host, port) {
            *last_error = format!("net.connect: not granted by manifold (host {host}:{port})");
            return errors::E_PERMISSION;
        }
        if host.is_empty() {
            *last_error = "net.connect: empty host".into();
            return errors::E_BAD_HOST;
        }
        if port == 0 {
            *last_error = "net.connect: port must be > 0".into();
            return errors::E_BAD_PORT;
        }

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let handle = self.spawn_client_socket(conn_id, host.to_string(), port);
        self.conns.insert(conn_id, handle);
        self.alive_conns.fetch_add(1, Ordering::Release);
        conn_id
    }

    pub fn write(&self, conn_id: ConnId, data: Vec<u8>, last_error: &mut String) -> i32 {
        let Some(handle) = self.conns.get(&conn_id) else {
            *last_error = format!("net.write: unknown conn id {conn_id}");
            return errors::E_BAD_ID;
        };
        if handle.half_closed.load(Ordering::Acquire) {
            *last_error = format!("net.write: conn {conn_id} already half-closed");
            return errors::E_BAD_ID;
        }
        let n = data.len();
        handle.pending_bytes.fetch_add(n, Ordering::AcqRel);
        handle.write_tx.send(WriteCmd::Bytes(data));
        handle.wake.notify_one();
        0
    }

    pub fn end(&self, conn_id: ConnId, last_error: &mut String) -> i32 {
        let Some(handle) = self.conns.get(&conn_id) else {
            *last_error = format!("net.end: unknown conn id {conn_id}");
            return errors::E_BAD_ID;
        };
        if handle
            .half_closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            handle.write_tx.send(WriteCmd::End);
            handle.wake.notify_one();
        }
        0
    }

    pub fn destroy(&self, conn_id: ConnId) -> i32 {
        // Cloning the handle (cheap - Arcs + AbortHandle) keeps the
        // entry visible to `pending_bytes()` / `mark_closed` until the
        // synthetic Close event has been dispatched to JS. Aborting the
        // task here means the task can't itself emit Close, so we send
        // the terminal event from the destroyer's thread. `alive_conns`
        // stays positive so the daemon event loop doesn't bail before
        // the close envelope reaches JS - `mark_closed` decrements when
        // the JS dispatch completes.
        if let Some(handle) = self.conns.get(&conn_id) {
            handle.abort.abort();
            self.events_tx.send(NetEvent::Close {
                conn_id,
                had_error: false,
            });
        }
        0
    }

    pub fn set_no_delay(&self, conn_id: ConnId, enable: bool) -> i32 {
        // Cross to the worker thread that owns the TcpStream. The
        // option flip happens in `drive_socket` via tokio's
        // `set_nodelay` (which itself goes through `setsockopt`).
        let Some(handle) = self.conns.get(&conn_id) else {
            return errors::E_BAD_ID;
        };
        handle.write_tx.send(WriteCmd::SetNoDelay(enable));
        handle.wake.notify_one();
        0
    }

    pub fn set_keep_alive(&self, conn_id: ConnId, enable: bool, delay_ms: i32) -> i32 {
        let Some(handle) = self.conns.get(&conn_id) else {
            return errors::E_BAD_ID;
        };
        handle
            .write_tx
            .send(WriteCmd::SetKeepAlive { enable, delay_ms });
        handle.wake.notify_one();
        0
    }

    pub fn listen(self: &Arc<Self>, host: &str, port: u16, last_error: &mut String) -> i32 {
        if host.is_empty() {
            *last_error = "net.listen: empty host".into();
            return errors::E_BAD_HOST;
        }

        // Multi-shard arbitration: when shared_claims is set, only
        // the shard that wins the lock-free CAS does the real bind.
        // Followers register a no-op listener - JS sees the port
        // as "bound", connection events flow only through the
        // owner shard. See `daemon_port_claims` for the rationale.
        if let Some(claims) = &self.shared_claims {
            use crate::daemon_port_claims::ClaimResult;
            match claims.try_claim(port) {
                ClaimResult::Owner(_) => { /* fall through to real bind */ }
                ClaimResult::Follower(_) => {
                    // Allocate a local server_id; user JS uses it
                    // for `server.close()` accounting. No bind, no
                    // task spawn - the kernel's listener is owned
                    // by the winning shard.
                    let server_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
                    self.alive_servers.fetch_add(1, Ordering::Release);
                    return server_id;
                }
            }
        }

        let server_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
        let bind = format!("{host}:{port}");
        let evt_tx = self.events_tx.clone();
        let coord = Arc::clone(self);

        let abort = self
            .runtime
            .spawn(server_task(server_id, bind, evt_tx, coord))
            .abort_handle();

        self.servers.insert(server_id, ListenerHandle { abort });
        // Track the port so close_server can release the shared
        // claim. Only owners enter this map.
        if self.shared_claims.is_some() {
            self.owned_listener_ports.insert(server_id, port);
        }
        self.alive_servers.fetch_add(1, Ordering::Release);
        server_id
    }

    pub fn close_server(&self, server_id: ServerId) -> i32 {
        if let Some(handle) = self.servers.remove(&server_id) {
            handle.abort.abort();
            self.alive_servers.fetch_sub(1, Ordering::Release);
            // Owner: release the shared claim so a future
            // `listen(same_port)` from any shard can bind again.
            if let Some(claims) = &self.shared_claims
                && let Some(port) = self.owned_listener_ports.remove(&server_id)
            {
                claims.release(port);
            }
            return 0;
        }
        // Not in `servers`. Two cases:
        //   * Single-shard mode: stale / unknown id - historical
        //     behavior is no-op return 0. Preserve that.
        //   * Multi-shard mode: a follower stub closing. The
        //     follower never inserted into `servers` in `listen`,
        //     so we decrement here to keep alive_servers accurate.
        if self.shared_claims.is_some() && self.alive_servers.load(Ordering::Acquire) > 0 {
            self.alive_servers.fetch_sub(1, Ordering::Release);
        }
        0
    }

    /// Called from the daemon event loop after dispatching `Close` to
    /// JS. Drops the registry entry so subsequent `write` / `end`
    /// calls correctly return `E_BAD_ID` and `has_refs()` flips.
    pub fn mark_closed(&self, conn_id: ConnId) {
        if self.conns.remove(&conn_id).is_some() {
            self.alive_conns.fetch_sub(1, Ordering::Release);
        }
    }

    // ----- internals --------------------------------------------------

    /// Spawn the per-connection task for a client-side `connect`.
    fn spawn_client_socket(
        self: &Arc<Self>,
        conn_id: ConnId,
        host: String,
        port: u16,
    ) -> ConnHandle {
        let (write_tx, write_rx) = unbounded_channel::<WriteCmd>();
        let pending = Arc::new(AtomicUsize::new(0));
        let half_closed = Arc::new(AtomicBool::new(false));
        let wake = Arc::new(Notify::new());
        let evt_tx = self.events_tx.clone();
        let coord = Arc::clone(self);

        let abort = self
            .runtime
            .spawn(client_task(
                coord,
                conn_id,
                host,
                port,
                write_rx,
                Arc::clone(&wake),
                Arc::clone(&pending),
                evt_tx,
            ))
            .abort_handle();

        ConnHandle {
            write_tx,
            wake,
            pending_bytes: pending,
            abort,
            half_closed,
        }
    }

    /// Spawn the per-connection task for a server-accepted socket.
    /// Inserts the handle into `conns` so `__host_net_write` /
    /// `__host_net_end` from JS can find this connection.
    fn register_accepted(
        self: &Arc<Self>,
        stream: TcpStream,
    ) -> (ConnId, Option<SocketAddr>, Option<SocketAddr>) {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (write_tx, write_rx) = unbounded_channel::<WriteCmd>();
        let pending = Arc::new(AtomicUsize::new(0));
        let half_closed = Arc::new(AtomicBool::new(false));
        let wake = Arc::new(Notify::new());
        let evt_tx = self.events_tx.clone();
        let local = stream.local_addr().ok();
        let remote = stream.peer_addr().ok();

        let abort = self
            .runtime
            .spawn(drive_socket(
                conn_id,
                stream,
                write_rx,
                Arc::clone(&wake),
                Arc::clone(&pending),
                evt_tx,
            ))
            .abort_handle();

        let handle = ConnHandle {
            write_tx,
            wake,
            pending_bytes: pending,
            abort,
            half_closed,
        };
        self.conns.insert(conn_id, handle);
        self.alive_conns.fetch_add(1, Ordering::Release);
        (conn_id, local, remote)
    }
}

/// Manifold gate. `OutboundHttp` is HTTP-only by design; raw TCP
/// must use `OutboundFull` (with optional host allow-list).
/// Allow-list entries are `host` or `host:port` patterns - see
/// [`afterburner_node_compat::http_host::split_host_port_pattern`]
/// for the shared grammar. `port` here is the literal connect port.
fn net_outbound_allowed(m: &Manifold, host: &str, port: u16) -> bool {
    match &m.net {
        NetAccess::None => false,
        NetAccess::OutboundHttp(_) => false,
        NetAccess::OutboundFull(None) => true,
        NetAccess::OutboundFull(Some(allow)) => host_allowed(host, port, allow),
    }
}

fn host_allowed(host: &str, port: u16, allow: &[String]) -> bool {
    if allow.is_empty() {
        return true;
    }
    let host_lc = host.to_ascii_lowercase();
    allow.iter().any(|pat| {
        // `host:port` entries constrain the port; port-less entries
        // match any port. The split grammar is shared with the HTTP
        // gate so `--allow-net 127.0.0.1:9000` means the same thing
        // for fetch and net.connect.
        let (pat_host, pat_port) = afterburner_node_compat::http_host::split_host_port_pattern(pat);
        if let Some(pp) = pat_port
            && !pp.matches(port)
        {
            return false;
        }
        let p = pat_host.to_ascii_lowercase();
        if p == "*" {
            return true;
        }
        if let Some(suffix) = p.strip_prefix("*.") {
            // *.example.com matches api.example.com (and deeper) but
            // not example.com itself.
            return host_lc.ends_with(&format!(".{suffix}"));
        }
        p == host_lc
    })
}

// ---------------------------------------------------------------------
// Per-connection / per-listener tokio tasks.
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn client_task(
    _coord: Arc<DaemonNet>,
    conn_id: ConnId,
    host: String,
    port: u16,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<NetEvent>,
) {
    let stream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            evt_tx.send(NetEvent::Error {
                conn_id,
                message: e.to_string(),
                code: io_error_code(&e),
            });
            evt_tx.send(NetEvent::Close {
                conn_id,
                had_error: true,
            });
            return;
        }
    };
    let local = stream.local_addr().ok();
    let remote = stream.peer_addr().ok();
    evt_tx.send(NetEvent::Connect {
        conn_id,
        local,
        remote,
    });
    drive_socket(conn_id, stream, write_rx, wake, pending, evt_tx).await;
}

async fn server_task(
    server_id: ServerId,
    bind: String,
    evt_tx: BoundedTx<NetEvent>,
    coord: Arc<DaemonNet>,
) {
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            evt_tx.send(NetEvent::ServerError {
                server_id,
                message: format!("bind {bind}: {e}"),
            });
            return;
        }
    };
    let bound_port = listener
        .local_addr()
        .ok()
        .map(|a| a.port())
        // Fall through to the requested port if local_addr fails (it
        // basically can't, post-bind, but we never want to lie to JS
        // about the bound port).
        .unwrap_or(0);
    evt_tx.send(NetEvent::Listening {
        server_id,
        port: bound_port,
    });

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let (conn_id, local, remote) = coord.register_accepted(stream);
                evt_tx.send(NetEvent::Connection {
                    server_id,
                    conn_id,
                    local,
                    remote,
                });
            }
            Err(e) => {
                // Listener-level errors (FD exhaustion, etc.) are
                // typically fatal. Surface and exit so the server's
                // 'error' listener fires.
                evt_tx.send(NetEvent::ServerError {
                    server_id,
                    message: format!("accept: {e}"),
                });
                return;
            }
        }
    }
}

/// Drive both halves of an established TCP socket. Reader posts
/// `Data`/`End`/`Error`; writer drains the queue and posts `Drain`.
/// Single task with `tokio::select!` - no polling, no Mutex.
async fn drive_socket(
    conn_id: ConnId,
    stream: TcpStream,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<NetEvent>,
) {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut read_buf = vec![0u8; READ_CHUNK];
    let mut had_error = false;
    let mut writer_open = true;
    let mut was_over_hwm = false;

    'outer: loop {
        // Drain the write queue first - gives writes a chance to flush
        // before we block on the next select.
        while let Some(cmd) = write_rx.try_recv() {
            match cmd {
                WriteCmd::Bytes(buf) => {
                    let n = buf.len();
                    if let Err(e) = write_half.write_all(&buf).await {
                        evt_tx.send(NetEvent::Error {
                            conn_id,
                            message: e.to_string(),
                            code: io_error_code(&e),
                        });
                        had_error = true;
                        break 'outer;
                    }
                    let prev = pending.fetch_sub(n, Ordering::AcqRel);
                    let now = prev.saturating_sub(n);
                    if was_over_hwm && now < WRITE_HWM {
                        evt_tx.send(NetEvent::Drain { conn_id });
                        was_over_hwm = false;
                    } else if !was_over_hwm && now >= WRITE_HWM {
                        was_over_hwm = true;
                    }
                }
                WriteCmd::End => {
                    let _ = write_half.shutdown().await;
                    writer_open = false;
                }
                WriteCmd::SetNoDelay(enable) => {
                    // tokio's TcpStream exposes set_nodelay; we get
                    // back to the underlying stream via OwnedWriteHalf::as_ref.
                    if let Err(e) = write_half.as_ref().set_nodelay(enable) {
                        // Log via error event but don't tear the
                        // connection down - `setNoDelay` is advisory
                        // in Node and shouldn't kill the socket.
                        evt_tx.send(NetEvent::Error {
                            conn_id,
                            message: format!("set_nodelay({enable}): {e}"),
                            code: io_error_code(&e),
                        });
                    }
                }
                WriteCmd::SetKeepAlive { enable, delay_ms } => {
                    use socket2::{SockRef, TcpKeepalive};
                    use std::time::Duration;
                    let sock = SockRef::from(write_half.as_ref());
                    let result: std::io::Result<()> = if enable {
                        // Build a keepalive config with the requested
                        // initial idle. Node's `setKeepAlive(true, ms)`
                        // documents `ms` as the time before the first
                        // probe - that maps to TCP_KEEPIDLE on Linux,
                        // which is what `with_time` controls.
                        let mut ka = TcpKeepalive::new();
                        if delay_ms > 0 {
                            ka = ka.with_time(Duration::from_millis(delay_ms as u64));
                        }
                        sock.set_tcp_keepalive(&ka)
                    } else {
                        // Disable: clear SO_KEEPALIVE.
                        sock.set_keepalive(false)
                    };
                    if let Err(e) = result {
                        evt_tx.send(NetEvent::Error {
                            conn_id,
                            message: format!("set_keepalive({enable}, {delay_ms}): {e}"),
                            code: io_error_code(&e),
                        });
                    }
                }
            }
        }

        if !writer_open && pending.load(Ordering::Acquire) == 0 {
            // Half-closed and queue drained - keep the reader half
            // alive until the peer closes too. The select below
            // simply won't have a writer arm to wake.
        }

        tokio::select! {
            // Inbound bytes.
            res = read_half.read(&mut read_buf) => {
                match res {
                    Ok(0) => {
                        evt_tx.send(NetEvent::End { conn_id });
                        break 'outer;
                    }
                    Ok(n) => {
                        let payload_b64 = base64_encode(&read_buf[..n]);
                        evt_tx.send(NetEvent::Data { conn_id, payload_b64 });
                    }
                    Err(e) => {
                        evt_tx.send(NetEvent::Error {
                            conn_id,
                            message: e.to_string(),
                            code: io_error_code(&e),
                        });
                        had_error = true;
                        break 'outer;
                    }
                }
            }
            // Pending writes.
            _ = wake.notified() => {
                // Loop back to drain the write queue.
            }
        }
    }

    evt_tx.send(NetEvent::Close { conn_id, had_error });
}

fn io_error_code(e: &std::io::Error) -> String {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => "ECONNREFUSED".into(),
        ConnectionAborted => "ECONNABORTED".into(),
        ConnectionReset => "ECONNRESET".into(),
        TimedOut => "ETIMEDOUT".into(),
        AddrInUse => "EADDRINUSE".into(),
        AddrNotAvailable => "EADDRNOTAVAIL".into(),
        NotConnected => "ENOTCONN".into(),
        BrokenPipe => "EPIPE".into(),
        Interrupted => "EINTR".into(),
        WouldBlock => "EAGAIN".into(),
        UnexpectedEof => "EUNEXPECTEDEOF".into(),
        _ => String::new(),
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode a base64 payload that arrived as a string from JS via the
/// `__host_net_write` import.
pub fn decode_payload(b64: &str, last_error: &mut String) -> Option<Vec<u8>> {
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(v) => Some(v),
        Err(e) => {
            *last_error = format!("net: payload base64: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_full_no_allowlist_permits_anything() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(None);
        assert!(net_outbound_allowed(&m, "example.com", 80));
        assert!(net_outbound_allowed(&m, "127.0.0.1", 9000));
    }

    #[test]
    fn outbound_full_allowlist_filters_hosts() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["api.example.com".into()]));
        assert!(net_outbound_allowed(&m, "api.example.com", 80));
        // Port-less entry: any port.
        assert!(net_outbound_allowed(&m, "api.example.com", 12345));
        assert!(!net_outbound_allowed(&m, "evil.com", 80));
    }

    #[test]
    fn allowlist_host_port_entries() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["127.0.0.1:9000".into()]));
        assert!(net_outbound_allowed(&m, "127.0.0.1", 9000));
        assert!(!net_outbound_allowed(&m, "127.0.0.1", 9001));
        assert!(!net_outbound_allowed(&m, "127.0.0.2", 9000));
    }

    #[test]
    fn outbound_http_blocks_raw_tcp() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundHttp(None);
        assert!(!net_outbound_allowed(&m, "example.com", 80));
    }

    #[test]
    fn sealed_blocks_everything() {
        let m = Manifold::sealed();
        assert!(!net_outbound_allowed(&m, "anything", 80));
    }

    #[test]
    fn wildcard_subdomain_match() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["*.trusted.io".into()]));
        assert!(net_outbound_allowed(&m, "api.trusted.io", 80));
        assert!(net_outbound_allowed(&m, "deeply.nested.trusted.io", 443));
        assert!(!net_outbound_allowed(&m, "trusted.io", 80));
        assert!(!net_outbound_allowed(&m, "evil.com", 80));
    }

    #[test]
    fn wildcard_with_port_constrains_port() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["*.trusted.io:8443".into()]));
        assert!(net_outbound_allowed(&m, "api.trusted.io", 8443));
        assert!(!net_outbound_allowed(&m, "api.trusted.io", 443));
    }

    #[test]
    fn wildcard_alone_matches_anything() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["*".into()]));
        assert!(net_outbound_allowed(&m, "x.y.z", 80));
    }
}
