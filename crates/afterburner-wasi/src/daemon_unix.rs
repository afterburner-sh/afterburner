// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(unix)]

//! `unix` - AF_UNIX socket host coordinator.
//!
//! Backs `AF_UNIX SOCK_STREAM` and `AF_UNIX SOCK_DGRAM` socket syscalls
//! from the Emscripten Python runtime. Mirrors the architecture of
//! `daemon_net` but uses `tokio::net::{UnixListener, UnixStream, UnixDatagram}`.
//!
//! ## Architecture
//!
//! ```text
//!   client_task ── UnixStream::connect ──►  Connect event
//!   server_task ── UnixListener::accept ──►  Connection events
//!   drive_socket ── select(read, write) ──►  Data / End / Error events
//!   dgram recv  ── UnixDatagram::recv_from ──►  DgramMessage events
//!   dgram send  ── one-shot send_to ──────►  fire-and-forget
//! ```
//!
//! ## Lock-free
//!
//! `HopscotchMap<ConnId, ConnHandle>`, `HopscotchMap<ServerId, ListenerHandle>`,
//! `HopscotchMap<i32, DgramHandle>` for active sockets, atomics for counters,
//! kovan channels for events. **No `Mutex` anywhere.**

use kovan_channel::flavors::bounded::{
    Receiver as BoundedRx, Sender as BoundedTx, channel as bounded_channel,
};
use kovan_channel::flavors::unbounded::{
    Receiver as UnboundedRx, Sender as UnboundedTx, channel as unbounded_channel,
};
use kovan_map::HopscotchMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixDatagram, UnixListener, UnixStream};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::AbortHandle;

pub type ConnId = i32;
pub type ServerId = i32;

/// 64 KiB write high-water mark, matching `daemon_net`.
pub const WRITE_HWM: usize = 64 * 1024;

/// 64 KiB read chunk granularity, matching `daemon_net`.
pub const READ_CHUNK: usize = 64 * 1024;

/// 64 KiB max datagram buffer.
pub const MAX_DGRAM: usize = 65 * 1024;

pub mod errors {
    pub const E_NO_DAEMON: i32 = -1;
    pub const E_PERMISSION: i32 = -2;
    pub const E_BAD_ID: i32 = -3;
    pub const E_BAD_PATH: i32 = -4;
    pub const E_BAD_PAYLOAD: i32 = -5;
    pub const E_OTHER: i32 = -6;
}

/// Events surfaced to the blocking socket bridge.
#[derive(Debug, Clone)]
pub enum UnixEvent {
    /// Client-side connect completed.
    Connect { conn_id: ConnId },
    /// Server accepted an incoming connection.
    Connection {
        server_id: ServerId,
        conn_id: ConnId,
    },
    /// Inbound stream bytes (base64-encoded).
    Data {
        conn_id: ConnId,
        payload_b64: String,
    },
    /// Peer performed a half-close (EOF on read).
    End { conn_id: ConnId },
    /// Write queue drained below the high-water mark.
    Drain { conn_id: ConnId },
    /// Connection fully closed.
    Close { conn_id: ConnId, had_error: bool },
    /// Per-connection error (non-fatal stream error).
    Error { conn_id: ConnId, message: String },
    /// Server is listening on `path`.
    Listening { server_id: ServerId },
    /// Listener-level error.
    ServerError {
        server_id: ServerId,
        message: String,
    },
    /// Inbound datagram (SOCK_DGRAM).
    DgramMessage { socket_id: i32, payload_b64: String },
    /// Datagram socket bound and recv loop running.
    DgramBound { socket_id: i32 },
}

/// Per-connection state kept in the lock-free registry.
#[derive(Clone)]
struct ConnHandle {
    write_tx: UnboundedTx<WriteCmd>,
    wake: Arc<Notify>,
    pending_bytes: Arc<AtomicUsize>,
    abort: AbortHandle,
    half_closed: Arc<AtomicBool>,
}

#[derive(Clone)]
struct ListenerHandle {
    abort: AbortHandle,
}

/// Handle for an AF_UNIX SOCK_DGRAM bound socket.
#[derive(Clone)]
struct DgramHandle {
    socket: Arc<UnixDatagram>,
    /// Held to cancel the recv task via `close_dgram`.
    abort: AbortHandle,
}

enum WriteCmd {
    Bytes(Vec<u8>),
    End,
    /// TCP-specific options forwarded from Python `setsockopt`. Unix streams
    /// have no `TCP_NODELAY` / `SO_KEEPALIVE`; silently ignored.
    #[expect(dead_code)]
    SetNoDelay(bool),
    /// See [`WriteCmd::SetNoDelay`].
    #[expect(dead_code)]
    SetKeepAlive {
        enable: bool,
        delay_ms: i32,
    },
}

/// Unix-domain socket coordinator for AF_UNIX SOCK_STREAM and SOCK_DGRAM.
pub struct DaemonUnix {
    runtime: Handle,
    next_conn_id: AtomicI32,
    next_server_id: AtomicI32,
    next_dgram_id: AtomicI32,
    conns: HopscotchMap<ConnId, ConnHandle>,
    servers: HopscotchMap<ServerId, ListenerHandle>,
    dgrams: HopscotchMap<i32, DgramHandle>,
    alive_conns: AtomicUsize,
    alive_servers: AtomicUsize,
    events_tx: BoundedTx<UnixEvent>,
    events_rx: BoundedRx<UnixEvent>,
}

impl std::fmt::Debug for DaemonUnix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonUnix")
            .field("alive_conns", &self.alive_conns.load(Ordering::Relaxed))
            .field("alive_servers", &self.alive_servers.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl DaemonUnix {
    pub fn new(runtime: Handle) -> Arc<Self> {
        let (tx, rx) = bounded_channel::<UnixEvent>(4096);
        Arc::new(Self {
            runtime,
            next_conn_id: AtomicI32::new(1),
            next_server_id: AtomicI32::new(1),
            next_dgram_id: AtomicI32::new(1),
            conns: HopscotchMap::new(),
            servers: HopscotchMap::new(),
            dgrams: HopscotchMap::new(),
            alive_conns: AtomicUsize::new(0),
            alive_servers: AtomicUsize::new(0),
            events_tx: tx,
            events_rx: rx,
        })
    }

    pub fn try_recv_event(&self) -> Option<UnixEvent> {
        self.events_rx.try_recv()
    }

    pub fn runtime(&self) -> &Handle {
        &self.runtime
    }

    pub fn has_refs(&self) -> bool {
        self.alive_conns.load(Ordering::Acquire) > 0
            || self.alive_servers.load(Ordering::Acquire) > 0
    }

    // ---- SOCK_STREAM client side -------------------------------------------

    /// Connect an AF_UNIX SOCK_STREAM socket to `path`. Returns the new
    /// `conn_id` on success or a negative error from [`errors`]. The actual
    /// connect happens async; the result appears as `Connect` / `Error` events.
    pub fn connect_stream(self: &Arc<Self>, path: &str) -> i32 {
        if path.is_empty() {
            return errors::E_BAD_PATH;
        }
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let handle = self.spawn_client_task(conn_id, path.to_string());
        self.conns.insert(conn_id, handle);
        self.alive_conns.fetch_add(1, Ordering::Release);
        conn_id
    }

    /// Enqueue bytes to send on `conn_id`. Returns 0 or a negative error.
    pub fn write(&self, conn_id: ConnId, data: Vec<u8>, last_error: &mut String) -> i32 {
        let Some(handle) = self.conns.get(&conn_id) else {
            *last_error = format!("unix.write: unknown conn_id {conn_id}");
            return errors::E_BAD_ID;
        };
        if handle.half_closed.load(Ordering::Acquire) {
            *last_error = format!("unix.write: conn {conn_id} already half-closed");
            return errors::E_BAD_ID;
        }
        let n = data.len();
        handle.pending_bytes.fetch_add(n, Ordering::AcqRel);
        handle.write_tx.send(WriteCmd::Bytes(data));
        handle.wake.notify_one();
        0
    }

    /// Perform a half-close (FIN) on `conn_id`.
    pub fn end(&self, conn_id: ConnId, last_error: &mut String) -> i32 {
        let Some(handle) = self.conns.get(&conn_id) else {
            *last_error = format!("unix.end: unknown conn_id {conn_id}");
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

    /// Abort `conn_id` immediately, emitting a synthetic `Close`.
    pub fn destroy(&self, conn_id: ConnId) -> i32 {
        if let Some(handle) = self.conns.get(&conn_id) {
            handle.abort.abort();
            self.events_tx.send(UnixEvent::Close {
                conn_id,
                had_error: false,
            });
        }
        0
    }

    /// Called after the `Close` event has been dispatched. Frees the registry
    /// entry and decrements the live counter.
    pub fn mark_closed(&self, conn_id: ConnId) {
        if self.conns.remove(&conn_id).is_some() {
            self.alive_conns.fetch_sub(1, Ordering::Release);
        }
    }

    // ---- SOCK_STREAM server side -------------------------------------------

    /// Bind and listen on a Unix-domain path. Returns the new `server_id` or
    /// a negative error from [`errors`].
    ///
    /// Binds synchronously (via `block_on`) so that the caller can connect
    /// immediately after `listen()` returns without a race. The accept loop
    /// runs in a detached task after the bind succeeds.
    pub fn listen(self: &Arc<Self>, path: &str, last_error: &mut String) -> i32 {
        if path.is_empty() {
            *last_error = "unix.listen: empty path".into();
            return errors::E_BAD_PATH;
        }
        // Remove stale socket file first (mirrors Python's os.unlink before bind).
        let _ = std::fs::remove_file(path);

        // UnixListener::bind is synchronous. No block_on needed.
        // It must be called from within a tokio context so the listener
        // can be moved into the spawned accept-loop task below.
        let listener = match self.runtime.block_on(async { UnixListener::bind(path) }) {
            Ok(l) => l,
            Err(e) => {
                *last_error = format!("unix.listen({path}): {e}");
                return errors::E_OTHER;
            }
        };

        let server_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
        let evt_tx = self.events_tx.clone();
        let coord = Arc::clone(self);

        let abort = self
            .runtime
            .spawn(accept_loop(server_id, listener, evt_tx, coord))
            .abort_handle();
        self.servers.insert(server_id, ListenerHandle { abort });
        self.alive_servers.fetch_add(1, Ordering::Release);
        // Announce listening so the JS `'listening'` event fires. The envelope
        // translation (unix-listening) and the JS dispatcher already exist;
        // without this send, `server.listen({path})`'s callback never runs.
        // Mirrors daemon_net.listen and bind_dgram's DgramBound emit.
        self.events_tx.send(UnixEvent::Listening { server_id });
        server_id
    }

    /// Abort the listener for `server_id`.
    pub fn close_server(&self, server_id: ServerId) -> i32 {
        if let Some(handle) = self.servers.remove(&server_id) {
            handle.abort.abort();
            self.alive_servers.fetch_sub(1, Ordering::Release);
        }
        0
    }

    // ---- SOCK_DGRAM --------------------------------------------------------

    /// Bind a Unix datagram socket to `path`, spawn the recv loop, return the
    /// new `socket_id` or a negative error.
    pub fn bind_dgram(self: &Arc<Self>, path: &str, last_error: &mut String) -> i32 {
        if path.is_empty() {
            *last_error = "unix.bind_dgram: empty path".into();
            return errors::E_BAD_PATH;
        }
        let socket_id = self.next_dgram_id.fetch_add(1, Ordering::Relaxed);
        let sock = match UnixDatagram::bind(path) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                *last_error = format!("unix.bind_dgram({path}): {e}");
                return errors::E_OTHER;
            }
        };
        let abort = self.spawn_dgram_recv(socket_id, sock.clone());
        self.dgrams.insert(
            socket_id,
            DgramHandle {
                socket: sock,
                abort,
            },
        );
        self.events_tx.send(UnixEvent::DgramBound { socket_id });
        socket_id
    }

    /// Send a datagram to `dest_path` from the socket identified by `socket_id`.
    pub fn send_dgram(
        &self,
        socket_id: i32,
        dest_path: &str,
        payload: &[u8],
        last_error: &mut String,
    ) -> i32 {
        let Some(handle) = self.dgrams.get(&socket_id) else {
            *last_error = format!("unix.send_dgram: unknown socket_id {socket_id}");
            return errors::E_BAD_ID;
        };
        if dest_path.is_empty() {
            *last_error = "unix.send_dgram: empty dest path".into();
            return errors::E_BAD_PATH;
        }
        let socket = handle.socket.clone();
        let dest = dest_path.to_string();
        let payload_owned = payload.to_vec();
        let result = self
            .runtime
            .block_on(async move { socket.send_to(&payload_owned, dest).await });
        match result {
            Ok(n) => n as i32,
            Err(e) => {
                *last_error = format!("unix.send_dgram({dest_path}): {e}");
                errors::E_OTHER
            }
        }
    }

    /// Close and remove a Unix datagram socket by `socket_id`.
    pub fn close_dgram(&self, socket_id: i32) {
        if let Some(handle) = self.dgrams.remove(&socket_id) {
            handle.abort.abort();
            drop(handle);
        }
    }

    // ---- internals ---------------------------------------------------------

    fn spawn_client_task(self: &Arc<Self>, conn_id: ConnId, path: String) -> ConnHandle {
        let (write_tx, write_rx) = unbounded_channel::<WriteCmd>();
        let pending = Arc::new(AtomicUsize::new(0));
        let half_closed = Arc::new(AtomicBool::new(false));
        let wake = Arc::new(Notify::new());
        let evt_tx = self.events_tx.clone();

        let abort = self
            .runtime
            .spawn(client_task(
                conn_id,
                path,
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

    /// Register an accepted server-side stream connection.
    fn register_accepted(self: &Arc<Self>, stream: UnixStream) -> ConnId {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (write_tx, write_rx) = unbounded_channel::<WriteCmd>();
        let pending = Arc::new(AtomicUsize::new(0));
        let half_closed = Arc::new(AtomicBool::new(false));
        let wake = Arc::new(Notify::new());
        let evt_tx = self.events_tx.clone();

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
        conn_id
    }

    fn spawn_dgram_recv(&self, socket_id: i32, socket: Arc<UnixDatagram>) -> AbortHandle {
        let evt_tx = self.events_tx.clone();
        self.runtime
            .spawn(async move {
                let mut buf = vec![0u8; MAX_DGRAM];
                while let Ok((n, _sender)) = socket.recv_from(&mut buf).await {
                    let payload_b64 = base64_encode(&buf[..n]);
                    evt_tx.send(UnixEvent::DgramMessage {
                        socket_id,
                        payload_b64,
                    });
                }
                // Recv error on a Unix datagram socket typically means the
                // socket was closed; the task exits.
            })
            .abort_handle()
    }
}

// ---- tokio tasks -----------------------------------------------------------

async fn client_task(
    conn_id: ConnId,
    path: String,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<UnixEvent>,
) {
    let stream = match UnixStream::connect(&path).await {
        Ok(s) => s,
        Err(e) => {
            evt_tx.send(UnixEvent::Error {
                conn_id,
                message: format!("connect({path}): {e}"),
            });
            evt_tx.send(UnixEvent::Close {
                conn_id,
                had_error: true,
            });
            return;
        }
    };
    evt_tx.send(UnixEvent::Connect { conn_id });
    drive_socket(conn_id, stream, write_rx, wake, pending, evt_tx).await;
}

/// Accept-loop task for a Unix-domain SOCK_STREAM listener. The listener is
/// already bound (binding was done synchronously in `DaemonUnix::listen`).
async fn accept_loop(
    server_id: ServerId,
    listener: UnixListener,
    evt_tx: BoundedTx<UnixEvent>,
    coord: Arc<DaemonUnix>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let conn_id = coord.register_accepted(stream);
                evt_tx.send(UnixEvent::Connection { server_id, conn_id });
            }
            Err(e) => {
                evt_tx.send(UnixEvent::ServerError {
                    server_id,
                    message: format!("accept: {e}"),
                });
                return;
            }
        }
    }
}

/// Drive both halves of an established Unix stream socket. Identical logic
/// to `daemon_net::drive_socket` but with `UnixStream`; `SetNoDelay` and
/// `SetKeepAlive` commands are silently ignored because Unix streams have no
/// TCP options.
async fn drive_socket(
    conn_id: ConnId,
    stream: UnixStream,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<UnixEvent>,
) {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut read_buf = vec![0u8; READ_CHUNK];
    let mut had_error = false;
    let mut writer_open = true;
    let mut was_over_hwm = false;
    // The peer can half-close its write side (we read EOF) while our writer
    // still has a queued echo to flush. Track read-EOF separately so we drain
    // pending writes before tearing the connection down.
    let mut read_eof = false;

    'outer: loop {
        while let Some(cmd) = write_rx.try_recv() {
            match cmd {
                WriteCmd::Bytes(buf) => {
                    let n = buf.len();
                    if let Err(e) = write_half.write_all(&buf).await {
                        evt_tx.send(UnixEvent::Error {
                            conn_id,
                            message: e.to_string(),
                        });
                        had_error = true;
                        break 'outer;
                    }
                    let prev = pending.fetch_sub(n, Ordering::AcqRel);
                    let now = prev.saturating_sub(n);
                    if was_over_hwm && now < WRITE_HWM {
                        evt_tx.send(UnixEvent::Drain { conn_id });
                        was_over_hwm = false;
                    } else if !was_over_hwm && now >= WRITE_HWM {
                        was_over_hwm = true;
                    }
                }
                WriteCmd::End => {
                    let _ = write_half.shutdown().await;
                    writer_open = false;
                }
                // Unix streams have no TCP options; silently no-op both.
                WriteCmd::SetNoDelay(_) | WriteCmd::SetKeepAlive { .. } => {}
            }
        }

        // Break only once the peer half-closed our read AND our writer is
        // done (sock.end() processed above), so an echo queued *after* read-EOF
        // still flushes. `writer_open` flips false only after every pending
        // WriteCmd::Bytes drained and the half-close shut the writer down.
        if read_eof && !writer_open {
            break 'outer;
        }

        if read_eof {
            // Read half is closed; just wait for the writer to drain.
            wake.notified().await;
        } else {
            tokio::select! {
                res = read_half.read(&mut read_buf) => {
                    match res {
                        Ok(0) => {
                            evt_tx.send(UnixEvent::End { conn_id });
                            read_eof = true;
                        }
                        Ok(n) => {
                            let payload_b64 = base64_encode(&read_buf[..n]);
                            evt_tx.send(UnixEvent::Data { conn_id, payload_b64 });
                        }
                        Err(e) => {
                            evt_tx.send(UnixEvent::Error {
                                conn_id,
                                message: e.to_string(),
                            });
                            had_error = true;
                            break 'outer;
                        }
                    }
                }
                _ = wake.notified() => {}
            }
        }
    }

    evt_tx.send(UnixEvent::Close { conn_id, had_error });
}

// ---- helpers ---------------------------------------------------------------

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}
