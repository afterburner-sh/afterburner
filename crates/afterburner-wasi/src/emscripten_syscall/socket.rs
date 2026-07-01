// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Real socket syscall implementations for the Python runtime (CPython on Emscripten).
//!
//! Translates Emscripten `__syscall_socket` / `__syscall_connect` /
//! `__syscall_bind` / `__syscall_listen` / `__syscall_accept4` /
//! `__syscall_sendmsg` / `__syscall_recvmsg` / `__syscall_sendto` /
//! `__syscall_recvfrom` into calls on the existing `DaemonNet` coordinator.
//!
//! ## Blocking bridge
//!
//! CPython's socket module is synchronous (blocking `connect`, `recv`, etc.).
//! Each syscall bridges to the async `DaemonNet` coordinator by entering the
//! tokio runtime (`Handle::block_on`) so the calling Wasm instance parks on
//! real I/O without spinning. Because the Python runtime is single-instance
//! per run (no shared linear memory across guest threads), one blocking
//! syscall does not stall other guests - they each own their own instance.
//!
//! ## Per-run state
//!
//! `SocketState` is box-allocated in `EmbedderState` on first socket syscall.
//! It holds a synthetic fd allocator, fd -> `ConnId`/`ServerId` maps, and
//! per-connection received-data buffers.
//!
//! ## Errno values
//!
//! Returned directly as negative Linux errno (Emscripten wasm32 convention):
//! - EPERM  (-1): denied by manifold (no `--allow-net` grant).
//! - EBADF  (-9): unknown fd.
//! - EINVAL (-22): bad address / argument.
//! - ENOTSUP (-95): unsupported domain/type combination.
//! - ECONNREFUSED (-111): connection refused.

// The real implementation is compiled only when the `daemon` feature is active,
// because `DaemonNet` and the tokio runtime live behind that feature gate.

use std::collections::{HashMap, VecDeque};

// ---- AF / SOCK constants --------------------------------------------------------

/// AF_UNIX (Unix-domain sockets).
pub const AF_UNIX: i32 = 1;
/// AF_INET (IPv4 sockets).
pub const AF_INET: i32 = 2;
/// SOCK_STREAM (TCP / Unix stream).
pub const SOCK_STREAM: i32 = 1;
/// SOCK_DGRAM (UDP / Unix datagram).
pub const SOCK_DGRAM: i32 = 2;
/// Mask to strip SOCK_NONBLOCK / SOCK_CLOEXEC from the type argument.
pub const SOCK_TYPE_MASK: i32 = 0xF;

/// Synthetic socket fd base - well above the FS fd range so that a socket fd
/// never aliases a real file fd.
pub const SOCK_FD_BASE: i32 = 1024;

// ---- Linux errno constants (Emscripten wasm32 ABI) ----------------------------

pub const EPERM: i32 = -1;
pub const EBADF: i32 = -9;
pub const EINVAL: i32 = -22;
pub const ENOTSUP: i32 = -95;
pub const ECONNREFUSED: i32 = -111;
pub const EAGAIN: i32 = -11;

// ---- Socket kind ---------------------------------------------------------------

/// The protocol a file descriptor was created for (set at `socket()` time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockKind {
    /// AF_INET SOCK_STREAM (TCP).
    TcpStream,
    /// AF_INET SOCK_DGRAM (UDP).
    UdpDgram,
    /// AF_UNIX SOCK_STREAM.
    UnixStream,
    /// AF_UNIX SOCK_DGRAM.
    UnixDgram,
}

// ---- SocketState ---------------------------------------------------------------

/// Per-run socket state stored in `EmbedderState`.
///
/// Box-allocated on first socket syscall; `None` in sealed / non-network runs.
/// The store is owned by one thread at a time (single-threaded wasmtime execution),
/// so plain `HashMap` / `VecDeque` are correct here - no locking needed.
pub struct SocketState {
    /// Next synthetic socket fd to hand out.
    next_fd: i32,
    /// Synthetic sockfd -> DaemonNet ConnId (connected / accepted sockets).
    /// Also used for AF_UNIX SOCK_STREAM conn_ids (kind differentiates).
    pub conn_fds: HashMap<i32, i32>,
    /// Synthetic sockfd -> DaemonNet ServerId (or -(port) placeholder before listen).
    /// Also used for AF_UNIX SOCK_STREAM server_ids (kind differentiates).
    pub server_fds: HashMap<i32, i32>,
    /// Per ConnId / socket_id: buffered incoming bytes not yet consumed by `recv`.
    pub recv_bufs: HashMap<i32, VecDeque<Vec<u8>>>,
    /// Per ServerId: accepted ConnIds not yet consumed by `accept4`.
    pub accept_queues: HashMap<i32, VecDeque<i32>>,
    /// Per-fd socket kind (set at socket() time).
    pub fd_kinds: HashMap<i32, SockKind>,
    /// Per-fd UDP socket_id in DaemonDgram (for AF_INET SOCK_DGRAM fds).
    pub udp_fds: HashMap<i32, i32>,
    /// Per-fd Unix dgram socket_id in DaemonUnix (for AF_UNIX SOCK_DGRAM fds).
    pub unix_dgram_fds: HashMap<i32, i32>,
    /// Per-fd UDP connected remote address (set by connect() on a SOCK_DGRAM fd).
    pub udp_connected: HashMap<i32, (String, u16)>,
    /// Per-fd Unix stream bind path (set by bind() before listen()).
    pub unix_stream_bind_paths: HashMap<i32, String>,
    /// Per-fd Unix dgram default remote path (set by connect() on AF_UNIX SOCK_DGRAM).
    pub unix_dgram_connected: HashMap<i32, String>,
    /// Pending TLS SNI: maps (resolved_ip, port) -> original hostname.
    ///
    /// Populated by `getaddrinfo` when it resolves a hostname. Consumed by
    /// `__syscall_connect` to initiate a host-side TLS handshake when the
    /// connection is to port 443, forwarding the original hostname as the SNI.
    pub pending_tls_sni: HashMap<(String, u16), String>,
}

impl SocketState {
    pub fn new() -> Box<Self> {
        Box::new(Self {
            next_fd: SOCK_FD_BASE,
            conn_fds: HashMap::new(),
            server_fds: HashMap::new(),
            recv_bufs: HashMap::new(),
            accept_queues: HashMap::new(),
            fd_kinds: HashMap::new(),
            udp_fds: HashMap::new(),
            unix_dgram_fds: HashMap::new(),
            udp_connected: HashMap::new(),
            unix_stream_bind_paths: HashMap::new(),
            unix_dgram_connected: HashMap::new(),
            pending_tls_sni: HashMap::new(),
        })
    }

    /// Returns the kind for a fd, or `None`.
    pub fn fd_kind(&self, fd: i32) -> Option<SockKind> {
        self.fd_kinds.get(&fd).copied()
    }

    /// Allocate a fresh synthetic socket fd.
    pub fn alloc_fd(&mut self) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        fd
    }

    /// Enqueue incoming bytes for `conn_id`.
    pub fn push_data(&mut self, conn_id: i32, bytes: Vec<u8>) {
        self.recv_bufs.entry(conn_id).or_default().push_back(bytes);
    }

    /// Drain up to `max` bytes from the receive buffer for `conn_id`.
    pub fn drain_recv(&mut self, conn_id: i32, max: usize) -> Vec<u8> {
        let q = match self.recv_bufs.get_mut(&conn_id) {
            Some(q) => q,
            None => return Vec::new(),
        };
        let mut out = Vec::with_capacity(max);
        while out.len() < max {
            let front = match q.front_mut() {
                Some(v) => v,
                None => break,
            };
            let take = (max - out.len()).min(front.len());
            out.extend_from_slice(&front[..take]);
            if take == front.len() {
                q.pop_front();
            } else {
                front.drain(..take);
            }
        }
        out
    }

    /// Whether `conn_id` has any buffered incoming bytes.
    pub fn has_buffered(&self, conn_id: i32) -> bool {
        self.recv_bufs
            .get(&conn_id)
            .map(|q| !q.is_empty())
            .unwrap_or(false)
    }
}

// ---- fd close helper -----------------------------------------------------------

/// Release all coordinator resources for a socket fd and remove it from
/// `SocketState`. Called by both the WASI `fd_close` and the Emscripten
/// `__syscall_close` handlers so neither duplicates the release logic.
///
/// Returns 0 always; the callers return early with 0 after calling this.
/// Only compiled under the `daemon` feature because it touches `socket_state`,
/// `daemon_net`, `daemon_dgram_py`, and `daemon_unix`, all of which are
/// daemon-only fields on `EmbedderState`.
#[cfg(feature = "daemon")]
pub(crate) fn release_socket_fd(
    caller: &mut wasmtime::Caller<'_, crate::embedder_vm::EmbedderState>,
    fd: i32,
) {
    let kind = caller
        .data()
        .socket_state
        .as_deref()
        .and_then(|s| s.fd_kind(fd));

    match kind {
        Some(SockKind::TcpStream) => {
            let conn_id = caller
                .data()
                .socket_state
                .as_deref()
                .and_then(|s| s.conn_fds.get(&fd).copied());
            let server_id = caller
                .data()
                .socket_state
                .as_deref()
                .and_then(|s| s.server_fds.get(&fd).copied());
            if let Some(cid) = conn_id {
                if let Some(net) = caller.data().daemon_net.clone() {
                    net.destroy(cid);
                }
                caller
                    .data_mut()
                    .socket_state
                    .as_deref_mut()
                    .map(|s| s.conn_fds.remove(&fd));
            } else if let Some(sid) = server_id {
                if sid > 0
                    && let Some(net) = caller.data().daemon_net.clone()
                {
                    net.close_server(sid);
                }
                caller
                    .data_mut()
                    .socket_state
                    .as_deref_mut()
                    .map(|s| s.server_fds.remove(&fd));
            }
        }
        Some(SockKind::UdpDgram) => {
            let socket_id = caller
                .data()
                .socket_state
                .as_deref()
                .and_then(|s| s.udp_fds.get(&fd).copied());
            if let Some(sid) = socket_id {
                if let Some(dgram) = caller.data().daemon_dgram_py.clone() {
                    dgram.close(sid);
                }
                caller
                    .data_mut()
                    .socket_state
                    .as_deref_mut()
                    .map(|s| s.udp_fds.remove(&fd));
            }
        }
        #[cfg(unix)]
        Some(SockKind::UnixStream) => {
            let conn_id = caller
                .data()
                .socket_state
                .as_deref()
                .and_then(|s| s.conn_fds.get(&fd).copied());
            let server_id = caller
                .data()
                .socket_state
                .as_deref()
                .and_then(|s| s.server_fds.get(&fd).copied());
            if let Some(cid) = conn_id {
                if let Some(unix) = caller.data().daemon_unix.clone() {
                    unix.destroy(cid);
                }
                caller
                    .data_mut()
                    .socket_state
                    .as_deref_mut()
                    .map(|s| s.conn_fds.remove(&fd));
            } else if let Some(sid) = server_id {
                if sid > 0
                    && let Some(unix) = caller.data().daemon_unix.clone()
                {
                    unix.close_server(sid);
                }
                caller
                    .data_mut()
                    .socket_state
                    .as_deref_mut()
                    .map(|s| s.server_fds.remove(&fd));
            }
        }
        #[cfg(unix)]
        Some(SockKind::UnixDgram) => {
            let socket_id = caller
                .data()
                .socket_state
                .as_deref()
                .and_then(|s| s.unix_dgram_fds.get(&fd).copied());
            if let Some(sid) = socket_id {
                if let Some(unix) = caller.data().daemon_unix.clone() {
                    unix.close_dgram(sid);
                }
                caller
                    .data_mut()
                    .socket_state
                    .as_deref_mut()
                    .map(|s| s.unix_dgram_fds.remove(&fd));
            }
        }
        None => {}
        #[cfg(not(unix))]
        Some(SockKind::UnixStream | SockKind::UnixDgram) => {}
    }

    // Remove kind tag regardless so repeated close is a no-op.
    caller
        .data_mut()
        .socket_state
        .as_deref_mut()
        .map(|s| s.fd_kinds.remove(&fd));
}

// ---- sockaddr helpers ----------------------------------------------------------

/// Parse `(host, port)` from a wasm32 `sockaddr_in` at `addr_ptr` in `mem`.
///
/// `struct sockaddr_in` layout (wasm32, little-endian):
///   offset 0: sa_family (u16, AF_INET = 2)
///   offset 2: sin_port  (u16, big-endian network order)
///   offset 4: sin_addr  (u32, big-endian network order)
///
/// Returns `None` if the pointer is out of bounds or the family is not `AF_INET`.
pub fn parse_sockaddr_in(mem: &[u8], addr_ptr: usize) -> Option<(String, u16)> {
    if addr_ptr
        .checked_add(8)
        .map(|e| e > mem.len())
        .unwrap_or(true)
    {
        return None;
    }
    let family = u16::from_le_bytes([mem[addr_ptr], mem[addr_ptr + 1]]);
    if family as i32 != AF_INET {
        return None;
    }
    let port = u16::from_be_bytes([mem[addr_ptr + 2], mem[addr_ptr + 3]]);
    let a = [
        mem[addr_ptr + 4],
        mem[addr_ptr + 5],
        mem[addr_ptr + 6],
        mem[addr_ptr + 7],
    ];
    let host = format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
    Some((host, port))
}

/// Write an IPv4 `sockaddr_in` into guest memory at `addr_ptr`.
pub fn write_sockaddr_in(mem: &mut [u8], addr_ptr: usize, host: &str, port: u16) {
    if addr_ptr
        .checked_add(16)
        .map(|e| e > mem.len())
        .unwrap_or(true)
    {
        return;
    }
    let fam = (AF_INET as u16).to_le_bytes();
    mem[addr_ptr] = fam[0];
    mem[addr_ptr + 1] = fam[1];
    let pb = port.to_be_bytes();
    mem[addr_ptr + 2] = pb[0];
    mem[addr_ptr + 3] = pb[1];
    // Parse dotted-quad; fall back to loopback.
    let parts: Vec<u8> = host.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() == 4 {
        mem[addr_ptr + 4] = parts[0];
        mem[addr_ptr + 5] = parts[1];
        mem[addr_ptr + 6] = parts[2];
        mem[addr_ptr + 7] = parts[3];
    } else {
        mem[addr_ptr + 4] = 127;
        mem[addr_ptr + 5] = 0;
        mem[addr_ptr + 6] = 0;
        mem[addr_ptr + 7] = 1;
    }
    // Zero the 8 padding bytes.
    for i in 8..16 {
        mem[addr_ptr + i] = 0;
    }
}

/// Parse a Unix-domain path from a wasm32 `sockaddr_un` at `addr_ptr` in `mem`.
///
/// `struct sockaddr_un` layout (wasm32, little-endian):
///   offset 0: sa_family (i16, AF_UNIX = 1)
///   offset 2: sun_path  (up to 108 bytes, null-terminated)
///
/// Returns `None` if out-of-bounds or the family is not `AF_UNIX`.
pub fn parse_sockaddr_un(mem: &[u8], addr_ptr: usize) -> Option<String> {
    // Minimum: 2 bytes for family + at least 1 byte of path.
    if addr_ptr
        .checked_add(3)
        .map(|e| e > mem.len())
        .unwrap_or(true)
    {
        return None;
    }
    let family = u16::from_le_bytes([mem[addr_ptr], mem[addr_ptr + 1]]);
    if family as i32 != AF_UNIX {
        return None;
    }
    let path_start = addr_ptr + 2;
    // sun_path is at most 108 bytes; clamp to what remains in memory.
    let max_path_end = (path_start + 108).min(mem.len());
    // Find the NUL terminator.
    let nul = mem[path_start..max_path_end]
        .iter()
        .position(|&b| b == 0)
        .map(|p| path_start + p)
        .unwrap_or(max_path_end);
    let path_bytes = &mem[path_start..nul];
    std::str::from_utf8(path_bytes).ok().map(|s| s.to_owned())
}

/// Write a minimal AF_UNIX `sockaddr_un` (family only, empty path) into guest
/// memory at `addr_ptr`. Used when accepting a Unix-stream connection and the
/// caller does not need the peer path.
pub fn write_sockaddr_un_empty(mem: &mut [u8], addr_ptr: usize) {
    if addr_ptr
        .checked_add(2)
        .map(|e| e > mem.len())
        .unwrap_or(true)
    {
        return;
    }
    let fam = (AF_UNIX as u16).to_le_bytes();
    mem[addr_ptr] = fam[0];
    mem[addr_ptr + 1] = fam[1];
    // NUL-terminate path immediately.
    if addr_ptr + 2 < mem.len() {
        mem[addr_ptr + 2] = 0;
    }
}

// ---- iovec helpers -------------------------------------------------------------

/// Read iov pointer + iovlen from `iov_field_ptr` (two i32 words), gather
/// all buffers into one `Vec<u8>`. Returns `Err(EINVAL)` if out of bounds.
pub fn gather_iov(mem: &[u8], iov_field_ptr: usize) -> Result<Vec<u8>, i32> {
    if iov_field_ptr
        .checked_add(8)
        .map(|e| e > mem.len())
        .unwrap_or(true)
    {
        return Err(EINVAL);
    }
    let iov_ptr =
        i32::from_le_bytes(mem[iov_field_ptr..iov_field_ptr + 4].try_into().unwrap()) as usize;
    let iovlen = i32::from_le_bytes(
        mem[iov_field_ptr + 4..iov_field_ptr + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut out = Vec::new();
    for i in 0..iovlen {
        let off = iov_ptr + i * 8;
        if off.checked_add(8).map(|e| e > mem.len()).unwrap_or(true) {
            return Err(EINVAL);
        }
        let base = i32::from_le_bytes(mem[off..off + 4].try_into().unwrap()) as usize;
        let len = i32::from_le_bytes(mem[off + 4..off + 8].try_into().unwrap()) as usize;
        if base.checked_add(len).map(|e| e > mem.len()).unwrap_or(true) {
            return Err(EINVAL);
        }
        out.extend_from_slice(&mem[base..base + len]);
    }
    Ok(out)
}

/// Total byte capacity of iovec buffers pointed to by the iov field at `iov_field_ptr`.
pub fn iov_capacity(mem: &[u8], iov_field_ptr: usize) -> usize {
    if iov_field_ptr
        .checked_add(8)
        .map(|e| e > mem.len())
        .unwrap_or(true)
    {
        return 0;
    }
    let iov_ptr = i32::from_le_bytes(
        mem[iov_field_ptr..iov_field_ptr + 4]
            .try_into()
            .unwrap_or_default(),
    ) as usize;
    let iovlen = i32::from_le_bytes(
        mem[iov_field_ptr + 4..iov_field_ptr + 8]
            .try_into()
            .unwrap_or_default(),
    ) as usize;
    let mut total = 0usize;
    for i in 0..iovlen {
        let off = iov_ptr + i * 8;
        if off.checked_add(8).map(|e| e > mem.len()).unwrap_or(true) {
            break;
        }
        let len = i32::from_le_bytes(mem[off + 4..off + 8].try_into().unwrap_or_default()) as usize;
        total = total.saturating_add(len);
    }
    total
}

/// Scatter `bytes` into iovec buffers; returns total bytes written.
pub fn scatter_iov(mem: &mut [u8], iov_field_ptr: usize, bytes: &[u8]) -> i32 {
    if iov_field_ptr
        .checked_add(8)
        .map(|e| e > mem.len())
        .unwrap_or(true)
    {
        return EINVAL;
    }
    let iov_ptr = i32::from_le_bytes(
        mem[iov_field_ptr..iov_field_ptr + 4]
            .try_into()
            .unwrap_or_default(),
    ) as usize;
    let iovlen = i32::from_le_bytes(
        mem[iov_field_ptr + 4..iov_field_ptr + 8]
            .try_into()
            .unwrap_or_default(),
    ) as usize;
    let mut written = 0usize;
    for i in 0..iovlen {
        if written >= bytes.len() {
            break;
        }
        let off = iov_ptr + i * 8;
        if off.checked_add(8).map(|e| e > mem.len()).unwrap_or(true) {
            break;
        }
        let base = i32::from_le_bytes(mem[off..off + 4].try_into().unwrap_or_default()) as usize;
        let len = i32::from_le_bytes(mem[off + 4..off + 8].try_into().unwrap_or_default()) as usize;
        let take = (bytes.len() - written).min(len);
        if base
            .checked_add(take)
            .map(|e| e <= mem.len())
            .unwrap_or(false)
        {
            mem[base..base + take].copy_from_slice(&bytes[written..written + take]);
            written += take;
        }
    }
    written as i32
}

// ---- daemon-feature-gated blocking helpers ------------------------------------

#[cfg(feature = "daemon")]
pub mod blocking {
    //! Blocking bridge from Emscripten host functions (sync) to async `DaemonNet`.

    use crate::daemon_net::{ConnId, DaemonNet, NetEvent, ServerId};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{EAGAIN, EBADF, ECONNREFUSED};

    const TIMEOUT: Duration = Duration::from_secs(30);

    fn decode_b64(s: &str) -> Option<Vec<u8>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD.decode(s).ok()
    }

    /// Block until the `Connect` or `Error`/`Close` event for `conn_id` arrives.
    ///
    /// Returns `0` on success or an errno value on failure. Data events for
    /// other connections that arrive while waiting are dropped; they will
    /// be re-emitted by the coordinator on the next `try_recv_event` call.
    pub fn wait_connect(
        net: &Arc<DaemonNet>,
        conn_id: ConnId,
        _state: &mut super::SocketState,
    ) -> i32 {
        let handle = net.runtime().clone();
        let net2 = Arc::clone(net);
        let result: i32 = handle.block_on(async move {
            match tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(ev) = net2.try_recv_event() {
                        match ev {
                            NetEvent::Connect { conn_id: cid, .. } if cid == conn_id => {
                                return 0i32;
                            }
                            NetEvent::Error { conn_id: cid, .. } if cid == conn_id => {
                                return ECONNREFUSED;
                            }
                            NetEvent::Close { conn_id: cid, .. } if cid == conn_id => {
                                return EBADF;
                            }
                            NetEvent::Data { .. } => {
                                // Data arriving before connect is confirmed is rare;
                                // it will arrive again via try_recv_event on the next
                                // recv syscall. Drop here to stay lock-free.
                            }
                            _ => {}
                        }
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            {
                Ok(rc) => rc,
                Err(_) => ECONNREFUSED,
            }
        });
        result
    }

    /// Block until `conn_id` has at least one byte or the connection closes.
    ///
    /// Data events for other connections are discarded (they should be buffered
    /// in a separate call or handled by a dedicated thread model; with
    /// single-instance Python this is not an issue in practice).
    pub fn wait_data(
        net: &Arc<DaemonNet>,
        conn_id: ConnId,
        state: &mut super::SocketState,
        max: usize,
    ) -> Result<Vec<u8>, i32> {
        if state.has_buffered(conn_id) {
            return Ok(state.drain_recv(conn_id, max));
        }
        let handle = net.runtime().clone();
        let net2 = Arc::clone(net);
        let maybe = handle.block_on(async move {
            tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(ev) = net2.try_recv_event() {
                        return ev;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .ok()
        });
        let ev = match maybe {
            None => return Err(EAGAIN),
            Some(ev) => ev,
        };
        match ev {
            NetEvent::Data {
                conn_id: cid,
                payload_b64,
            } => {
                if let Some(bytes) = decode_b64(&payload_b64) {
                    state.push_data(cid, bytes);
                }
            }
            NetEvent::End { conn_id: cid } | NetEvent::Close { conn_id: cid, .. }
                if cid == conn_id =>
            {
                return Ok(Vec::new()); // EOF
            }
            NetEvent::Connection {
                server_id,
                conn_id: cid,
                ..
            } => {
                state
                    .accept_queues
                    .entry(server_id)
                    .or_default()
                    .push_back(cid);
            }
            _ => {}
        }
        Ok(state.drain_recv(conn_id, max))
    }

    /// Block until an accepted connection is available on `server_id`.
    pub fn wait_accept(
        net: &Arc<DaemonNet>,
        server_id: ServerId,
        state: &mut super::SocketState,
    ) -> Result<ConnId, i32> {
        if let Some(cid) = state
            .accept_queues
            .entry(server_id)
            .or_default()
            .pop_front()
        {
            return Ok(cid);
        }
        let handle = net.runtime().clone();
        let net2 = Arc::clone(net);
        let maybe = handle.block_on(async move {
            tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(ev) = net2.try_recv_event() {
                        return ev;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .ok()
        });
        match maybe {
            None => Err(EAGAIN),
            Some(NetEvent::Connection {
                server_id: sid,
                conn_id,
                ..
            }) if sid == server_id => Ok(conn_id),
            Some(NetEvent::Data {
                conn_id,
                payload_b64,
            }) => {
                if let Some(bytes) = decode_b64(&payload_b64) {
                    state.push_data(conn_id, bytes);
                }
                Err(EAGAIN)
            }
            Some(_) => Err(EAGAIN),
        }
    }

    // ---- UDP (AF_INET SOCK_DGRAM) blocking helpers -------------------------

    /// Block until a UDP datagram arrives for `socket_id` in `DaemonDgram`.
    ///
    /// Datagram payloads are stored in `state.recv_bufs` keyed by `socket_id`
    /// (same map as TCP, different key space).
    pub fn wait_dgram(
        dgram: &Arc<crate::daemon_dgram::DaemonDgram>,
        socket_id: i32,
        state: &mut super::SocketState,
        max: usize,
    ) -> Result<Vec<u8>, i32> {
        use crate::daemon_dgram::DgramEvent;
        if state.has_buffered(socket_id) {
            return Ok(state.drain_recv(socket_id, max));
        }
        // Drive the event loop until we have buffered data for this socket_id.
        // Messages for OTHER socket_ids are buffered by sid; Close events for
        // other sockets are silently discarded so they do not cut the wait short.
        // A Close for THIS socket_id (or a timeout) ends the loop.
        // Each `block_on` fetches exactly one event so `state` is not borrowed
        // across await points.
        let handle = dgram.runtime().clone();
        let deadline = std::time::Instant::now() + TIMEOUT;
        loop {
            if state.has_buffered(socket_id) {
                return Ok(state.drain_recv(socket_id, max));
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(EAGAIN);
            }
            let dgram2 = Arc::clone(dgram);
            let maybe_ev = handle.block_on(async move {
                tokio::time::timeout(remaining, async move {
                    loop {
                        if let Some(ev) = dgram2.try_recv_event() {
                            return ev;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .ok()
            });
            let Some(ev) = maybe_ev else {
                return Err(EAGAIN); // deadline reached
            };
            match ev {
                DgramEvent::Message {
                    socket_id: sid,
                    payload_b64,
                    ..
                } => {
                    if let Some(bytes) = decode_b64(&payload_b64) {
                        state.push_data(sid, bytes);
                    }
                }
                DgramEvent::Close {
                    socket_id: closed_sid,
                } if closed_sid == socket_id => {
                    return Ok(Vec::new()); // our socket was closed
                }
                DgramEvent::Close { .. } => {
                    // Another socket's close - discard and keep waiting.
                }
                _ => {}
            }
        }
    }

    // ---- AF_UNIX SOCK_STREAM blocking helpers (unix-only) ------------------

    #[cfg(unix)]
    /// Block until a Unix stream `Connect` or error event arrives for `conn_id`.
    pub fn wait_unix_connect(
        unix: &Arc<crate::daemon_unix::DaemonUnix>,
        conn_id: crate::daemon_unix::ConnId,
        _state: &mut super::SocketState,
    ) -> i32 {
        use crate::daemon_unix::UnixEvent;
        let handle = unix.runtime().clone();
        let unix2 = Arc::clone(unix);
        handle.block_on(async move {
            match tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(ev) = unix2.try_recv_event() {
                        match ev {
                            UnixEvent::Connect { conn_id: cid } if cid == conn_id => {
                                return 0i32;
                            }
                            UnixEvent::Error { conn_id: cid, .. } if cid == conn_id => {
                                return ECONNREFUSED;
                            }
                            UnixEvent::Close { conn_id: cid, .. } if cid == conn_id => {
                                return EBADF;
                            }
                            _ => {}
                        }
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            {
                Ok(rc) => rc,
                Err(_) => ECONNREFUSED,
            }
        })
    }

    #[cfg(unix)]
    /// Block until Unix stream data arrives for `conn_id`.
    pub fn wait_unix_data(
        unix: &Arc<crate::daemon_unix::DaemonUnix>,
        conn_id: crate::daemon_unix::ConnId,
        state: &mut super::SocketState,
        max: usize,
    ) -> Result<Vec<u8>, i32> {
        use crate::daemon_unix::UnixEvent;
        if state.has_buffered(conn_id) {
            return Ok(state.drain_recv(conn_id, max));
        }
        let handle = unix.runtime().clone();
        let unix2 = Arc::clone(unix);
        let maybe = handle.block_on(async move {
            tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(ev) = unix2.try_recv_event() {
                        return ev;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .ok()
        });
        let ev = match maybe {
            None => return Err(EAGAIN),
            Some(ev) => ev,
        };
        match ev {
            UnixEvent::Data {
                conn_id: cid,
                payload_b64,
            } => {
                if let Some(bytes) = decode_b64(&payload_b64) {
                    state.push_data(cid, bytes);
                }
            }
            UnixEvent::End { conn_id: cid } | UnixEvent::Close { conn_id: cid, .. }
                if cid == conn_id =>
            {
                return Ok(Vec::new());
            }
            UnixEvent::Connection {
                server_id,
                conn_id: cid,
            } => {
                state
                    .accept_queues
                    .entry(server_id)
                    .or_default()
                    .push_back(cid);
            }
            _ => {}
        }
        Ok(state.drain_recv(conn_id, max))
    }

    #[cfg(unix)]
    /// Block until a Unix stream connection is accepted on `server_id`.
    pub fn wait_unix_accept(
        unix: &Arc<crate::daemon_unix::DaemonUnix>,
        server_id: crate::daemon_unix::ServerId,
        state: &mut super::SocketState,
    ) -> Result<crate::daemon_unix::ConnId, i32> {
        use crate::daemon_unix::UnixEvent;
        if let Some(cid) = state
            .accept_queues
            .entry(server_id)
            .or_default()
            .pop_front()
        {
            return Ok(cid);
        }
        let handle = unix.runtime().clone();
        let unix2 = Arc::clone(unix);
        let maybe = handle.block_on(async move {
            tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(ev) = unix2.try_recv_event() {
                        return ev;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .ok()
        });
        match maybe {
            None => Err(EAGAIN),
            Some(UnixEvent::Connection {
                server_id: sid,
                conn_id,
            }) if sid == server_id => Ok(conn_id),
            Some(UnixEvent::Data {
                conn_id,
                payload_b64,
            }) => {
                if let Some(bytes) = decode_b64(&payload_b64) {
                    state.push_data(conn_id, bytes);
                }
                Err(EAGAIN)
            }
            Some(_) => Err(EAGAIN),
        }
    }

    #[cfg(unix)]
    /// Block until a Unix datagram arrives for `socket_id` in `DaemonUnix`.
    pub fn wait_unix_dgram(
        unix: &Arc<crate::daemon_unix::DaemonUnix>,
        socket_id: i32,
        state: &mut super::SocketState,
        max: usize,
    ) -> Result<Vec<u8>, i32> {
        use crate::daemon_unix::UnixEvent;
        if state.has_buffered(socket_id) {
            return Ok(state.drain_recv(socket_id, max));
        }
        let handle = unix.runtime().clone();
        let unix2 = Arc::clone(unix);
        let maybe = handle.block_on(async move {
            tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(ev) = unix2.try_recv_event() {
                        return ev;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .ok()
        });
        let ev = match maybe {
            None => return Err(EAGAIN),
            Some(ev) => ev,
        };
        if let UnixEvent::DgramMessage {
            socket_id: sid,
            payload_b64,
        } = ev
            && let Some(bytes) = decode_b64(&payload_b64)
        {
            state.push_data(sid, bytes);
        }
        Ok(state.drain_recv(socket_id, max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sockaddr_in_af_inet() {
        // Construct a sockaddr_in for 127.0.0.1:8080
        // sa_family = 2 (AF_INET), little-endian
        // sin_port = 8080 big-endian = 0x1F90
        // sin_addr = 127.0.0.1 big-endian
        let mut mem = vec![0u8; 32];
        let family: u16 = 2;
        mem[0..2].copy_from_slice(&family.to_le_bytes());
        let port: u16 = 8080;
        mem[2..4].copy_from_slice(&port.to_be_bytes());
        mem[4] = 127;
        mem[5] = 0;
        mem[6] = 0;
        mem[7] = 1;
        let r = parse_sockaddr_in(&mem, 0);
        assert_eq!(r, Some(("127.0.0.1".into(), 8080)));
    }

    #[test]
    fn parse_sockaddr_in_wrong_family() {
        let mut mem = vec![0u8; 32];
        let family: u16 = 10; // AF_INET6
        mem[0..2].copy_from_slice(&family.to_le_bytes());
        assert!(parse_sockaddr_in(&mem, 0).is_none());
    }

    #[test]
    fn parse_sockaddr_in_oob() {
        let mem = vec![0u8; 4]; // too short
        assert!(parse_sockaddr_in(&mem, 0).is_none());
    }

    #[test]
    fn write_and_parse_roundtrip() {
        let mut mem = vec![0u8; 32];
        write_sockaddr_in(&mut mem, 0, "192.168.1.100", 9000);
        let r = parse_sockaddr_in(&mem, 0);
        assert_eq!(r, Some(("192.168.1.100".into(), 9000)));
    }

    #[test]
    fn socket_state_alloc_fd() {
        let mut s = SocketState::new();
        let fd1 = s.alloc_fd();
        let fd2 = s.alloc_fd();
        assert_eq!(fd1, SOCK_FD_BASE);
        assert_eq!(fd2, SOCK_FD_BASE + 1);
    }

    #[test]
    fn socket_state_push_and_drain() {
        let mut s = SocketState::new();
        s.push_data(1, b"hello ".to_vec());
        s.push_data(1, b"world".to_vec());
        assert!(s.has_buffered(1));
        let got = s.drain_recv(1, 8);
        assert_eq!(got, b"hello wo");
        // "rld" remains
        let rest = s.drain_recv(1, 100);
        assert_eq!(rest, b"rld");
        assert!(!s.has_buffered(1));
    }

    #[test]
    fn gather_iov_collects_buffers() {
        // Build a memory with two iovec entries pointing at "hello" and "world".
        // Layout:
        //   mem[0..4]  = iov_ptr (32 as u32 LE) - points to iov array at offset 32
        //   mem[4..8]  = iovlen (2 as i32 LE)
        //   mem[32..40] = iovec[0]: base=48, len=5
        //   mem[40..48] = iovec[1]: base=53, len=5
        //   mem[48..53] = "hello"
        //   mem[53..58] = "world"
        let mut mem = vec![0u8; 64];
        mem[0..4].copy_from_slice(&32u32.to_le_bytes());
        mem[4..8].copy_from_slice(&2i32.to_le_bytes());
        mem[32..36].copy_from_slice(&48i32.to_le_bytes());
        mem[36..40].copy_from_slice(&5i32.to_le_bytes());
        mem[40..44].copy_from_slice(&53i32.to_le_bytes());
        mem[44..48].copy_from_slice(&5i32.to_le_bytes());
        mem[48..53].copy_from_slice(b"hello");
        mem[53..58].copy_from_slice(b"world");
        let got = gather_iov(&mem, 0).expect("gather_iov");
        assert_eq!(got, b"helloworld");
    }

    #[test]
    fn scatter_iov_writes_bytes() {
        // Single iovec: base=16, len=10.
        let mut mem = vec![0u8; 32];
        mem[0..4].copy_from_slice(&8u32.to_le_bytes()); // iov_ptr = 8
        mem[4..8].copy_from_slice(&1i32.to_le_bytes()); // iovlen = 1
        mem[8..12].copy_from_slice(&16i32.to_le_bytes()); // base = 16
        mem[12..16].copy_from_slice(&10i32.to_le_bytes()); // len = 10
        let n = scatter_iov(&mut mem, 0, b"hello");
        assert_eq!(n, 5);
        assert_eq!(&mem[16..21], b"hello");
    }
}
