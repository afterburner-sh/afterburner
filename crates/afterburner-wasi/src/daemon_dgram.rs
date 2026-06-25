// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `dgram` - UDP socket host coordinator.
//!
//! Backs the `dgram.createSocket` polyfill in `polyfills/dgram.js`. The
//! host owns every `tokio::net::UdpSocket`; the JS-side `Socket` is a
//! thin EventEmitter façade that crosses into Rust through `__host_dgram_*`
//! imports. Per socket, one tokio task drives the recv loop and posts
//! `Message` / `Error` / `Close` events to the daemon event channel.
//!
//! ## Architecture
//!
//! ```text
//!   recv loop ── socket.recv_from ──►  Message events
//!   send      ── one-shot host call ─► socket.send_to (no queue,
//!                                       UDP is fire-and-forget)
//! ```
//!
//! Send is synchronous from the JS perspective: `__host_dgram_send`
//! schedules the `send_to` on the runtime, blocks the host import
//! until completion, returns the byte count. UDP doesn't need a
//! writer task or backpressure queue - the kernel either accepts the
//! packet or drops it; either outcome is observable in microseconds.
//!
//! ## Lock-free
//!
//! `HopscotchMap<SocketId, DgramHandle>` for active sockets, atomics
//! for counters, kovan_channel for events. **No `Mutex` anywhere.**
//!
//! ## Manifold
//!
//! Same posture as raw TCP (`net`): `dgram.bind`/`send` requires
//! `NetAccess::OutboundFull`. UDP escapes URL-shaped policy so
//! `OutboundHttp` is rejected. The library API never installs a
//! `DaemonDgram` so polyfill calls cleanly error in non-daemon mode.

use afterburner_core::{Manifold, NetAccess};
use kovan_channel::flavors::bounded::{
    Receiver as BoundedRx, Sender as BoundedTx, channel as bounded_channel,
};
use kovan_map::HopscotchMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::runtime::Handle;
use tokio::task::AbortHandle;

pub type SocketId = i32;

/// 64 KiB max datagram payload - covers IPv4 / IPv6 datagrams (theoretical
/// max ~65507 bytes for IPv4 UDP, slightly less for v6). Larger reads truncate
/// and surface as truncated `Message` events; matches Node's behavior on
/// oversized packets.
pub const MAX_DATAGRAM: usize = 65 * 1024;

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
/// into `{kind:"dgram-..."}` envelopes for the daemon-event dispatcher
/// to route into `__ab_dgram_handlers[socket_id]`.
#[derive(Debug, Clone)]
pub enum DgramEvent {
    /// Socket bound + recv loop running. Polyfill emits `'listening'`.
    Listening { socket_id: SocketId, port: u16 },
    /// Inbound datagram. `payload_b64` is base64 - UDP is a binary
    /// pipeline so we never assume utf8.
    Message {
        socket_id: SocketId,
        from: SocketAddr,
        payload_b64: String,
    },
    /// Recv-loop encountered an error. Polyfill emits `'error'`.
    Error {
        socket_id: SocketId,
        message: String,
        code: String,
    },
    /// Socket closed. Polyfill emits `'close'`.
    Close { socket_id: SocketId },
}

#[derive(Clone)]
struct DgramHandle {
    socket: Arc<UdpSocket>,
    abort: AbortHandle,
    bound_addr: SocketAddr,
}

pub struct DaemonDgram {
    runtime: Handle,
    manifold: Manifold,
    next_socket_id: AtomicI32,
    sockets: HopscotchMap<SocketId, DgramHandle>,
    alive: AtomicUsize,
    events_tx: BoundedTx<DgramEvent>,
    events_rx: BoundedRx<DgramEvent>,
    /// Multi-shard port arbiter. `None` in single-shard mode. See
    /// `daemon_port_claims` for the owner / follower contract.
    shared_claims: Option<Arc<crate::daemon_port_claims::SharedPortClaims>>,
    /// `socket_id` → port for owners, so `close()` releases the
    /// shared claim. Followers are NOT in this map. `port == 0`
    /// (OS-picked) is also tracked: claims keys on the *bound*
    /// port; a 0-bind gets a real OS-assigned port that we register.
    owned_socket_ports: HopscotchMap<SocketId, u16>,
}

impl std::fmt::Debug for DaemonDgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonDgram")
            .field("alive", &self.alive.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl DaemonDgram {
    pub fn new(runtime: Handle, manifold: Manifold) -> Arc<Self> {
        Self::new_inner(runtime, manifold, None)
    }

    /// Construct with a shared port-claim arbiter for multi-shard
    /// mode. See `daemon_port_claims` for the contract.
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
        let (tx, rx) = bounded_channel::<DgramEvent>(4096);
        Arc::new(Self {
            runtime,
            manifold,
            next_socket_id: AtomicI32::new(1),
            sockets: HopscotchMap::new(),
            alive: AtomicUsize::new(0),
            events_tx: tx,
            events_rx: rx,
            shared_claims,
            owned_socket_ports: HopscotchMap::new(),
        })
    }

    pub fn try_recv_event(&self) -> Option<DgramEvent> {
        self.events_rx.try_recv()
    }

    pub fn has_refs(&self) -> bool {
        self.alive.load(Ordering::Acquire) > 0
    }

    /// Bind a UDP socket to `host:port`. `port == 0` lets the OS pick.
    /// Returns the new `socket_id` (≥1) on success or one of [`errors`]
    /// on Manifold rejection / bind failure.
    pub fn bind(self: &Arc<Self>, host: &str, port: u16, last_error: &mut String) -> i32 {
        if !udp_allowed(&self.manifold) {
            *last_error = "dgram.bind: not granted by manifold".into();
            return errors::E_PERMISSION;
        }
        if host.is_empty() {
            *last_error = "dgram.bind: empty host".into();
            return errors::E_BAD_HOST;
        }

        // Multi-shard arbitration. Skip for `port == 0` (OS-picked)
        // - each shard gets its own OS-assigned port; the user's
        // intent is "any port", so racing shards each binding their
        // own is the correct semantics. For non-zero ports, the
        // first shard to claim wins; followers stub the bind.
        if port != 0
            && let Some(claims) = &self.shared_claims
        {
            use crate::daemon_port_claims::ClaimResult;
            match claims.try_claim(port) {
                ClaimResult::Owner(_) => { /* fall through to real bind */ }
                ClaimResult::Follower(_) => {
                    let socket_id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);
                    self.alive.fetch_add(1, Ordering::Release);
                    // Emit a Listening event so the JS bind() callback
                    // fires symmetrically with the owner shard.
                    self.events_tx
                        .send(DgramEvent::Listening { socket_id, port });
                    return socket_id;
                }
            }
        }

        let addr = format!("{host}:{port}");
        let socket_id = self.next_socket_id.fetch_add(1, Ordering::Relaxed);
        let this = self.clone();

        // Bind synchronously inside the runtime so we can return the
        // bound port to JS immediately. JS callers do
        //   sock.bind(0, () => { sock.address(); ... })
        // and expect the address to be populated on the listening
        // callback - that requires a synchronous bind.
        let result = this
            .runtime
            .block_on(async move { UdpSocket::bind(addr.clone()).await });
        let socket = match result {
            Ok(s) => Arc::new(s),
            Err(e) => {
                *last_error = format!("dgram.bind({host}:{port}): {e}");
                return errors::E_OTHER;
            }
        };
        let bound_addr = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => {
                *last_error = format!("dgram.bind: local_addr: {e}");
                return errors::E_OTHER;
            }
        };

        let abort = self.spawn_recv_loop(socket_id, socket.clone());

        self.sockets.insert(
            socket_id,
            DgramHandle {
                socket,
                abort,
                bound_addr,
            },
        );
        if self.shared_claims.is_some() && port != 0 {
            self.owned_socket_ports.insert(socket_id, port);
        }
        self.alive.fetch_add(1, Ordering::Release);

        // Emit the listening event asynchronously so the JS-side bind
        // callback fires through the standard handler dispatcher.
        self.events_tx.send(DgramEvent::Listening {
            socket_id,
            port: bound_addr.port(),
        });
        socket_id
    }

    fn spawn_recv_loop(&self, socket_id: SocketId, socket: Arc<UdpSocket>) -> AbortHandle {
        let events_tx = self.events_tx.clone();
        self.runtime
            .spawn(async move {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((n, from)) => {
                            let payload_b64 = base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &buf[..n],
                            );
                            // kovan bounded `send` blocks if full. UDP
                            // is best-effort, so we accept that
                            // backpressure here - the daemon event
                            // pump drains the channel each tick.
                            events_tx.send(DgramEvent::Message {
                                socket_id,
                                from,
                                payload_b64,
                            });
                        }
                        Err(e) => {
                            events_tx.send(DgramEvent::Error {
                                socket_id,
                                message: format!("dgram.recv: {e}"),
                                code: io_error_code(&e).into(),
                            });
                            // Stop the loop on recv error - the JS side
                            // will close the socket.
                            break;
                        }
                    }
                }
            })
            .abort_handle()
    }

    /// Send a datagram. Returns the byte count on success or one of
    /// [`errors`] on failure.
    pub fn send(
        &self,
        socket_id: SocketId,
        host: &str,
        port: u16,
        payload: &[u8],
        last_error: &mut String,
    ) -> i32 {
        if !udp_allowed(&self.manifold) {
            *last_error = "dgram.send: not granted by manifold".into();
            return errors::E_PERMISSION;
        }
        let Some(handle) = self.sockets.get(&socket_id) else {
            *last_error = format!("dgram.send: unknown socket id {socket_id}");
            return errors::E_BAD_ID;
        };
        if host.is_empty() {
            *last_error = "dgram.send: empty host".into();
            return errors::E_BAD_HOST;
        }
        if port == 0 {
            *last_error = "dgram.send: port must be > 0".into();
            return errors::E_BAD_PORT;
        }
        let addr = format!("{host}:{port}");
        let socket = handle.socket.clone();
        let payload_owned = payload.to_vec();
        let result = self
            .runtime
            .block_on(async move { socket.send_to(&payload_owned, addr).await });
        match result {
            Ok(n) => n as i32,
            Err(e) => {
                *last_error = format!("dgram.send({host}:{port}): {e}");
                errors::E_OTHER
            }
        }
    }

    /// Returns the bound (host, port) tuple for a socket. Used by
    /// `socket.address()` JS calls.
    pub fn address(&self, socket_id: SocketId) -> Option<(String, u16)> {
        self.sockets
            .get(&socket_id)
            .map(|h| (h.bound_addr.ip().to_string(), h.bound_addr.port()))
    }

    pub fn close(&self, socket_id: SocketId) {
        let Some(handle) = self.sockets.remove(&socket_id) else {
            // Possible follower stub (multi-shard only). In
            // single-shard mode, closing an unknown id is
            // historically a no-op - preserve.
            if self.shared_claims.is_some() && self.alive.load(Ordering::Acquire) > 0 {
                self.alive.fetch_sub(1, Ordering::Release);
                self.events_tx.send(DgramEvent::Close { socket_id });
            }
            return;
        };
        handle.abort.abort();
        // Drop the Arc<UdpSocket> by dropping the handle below; tokio
        // closes the underlying fd when the last Arc goes away.
        drop(handle);
        // Owner: release the shared claim if any.
        if let Some(claims) = &self.shared_claims
            && let Some(port) = self.owned_socket_ports.remove(&socket_id)
        {
            claims.release(port);
        }
        self.alive.fetch_sub(1, Ordering::Release);
        self.events_tx.send(DgramEvent::Close { socket_id });
    }
}

fn udp_allowed(m: &Manifold) -> bool {
    matches!(m.net, NetAccess::OutboundFull(_))
}

fn io_error_code(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::*;
    match e.kind() {
        AddrInUse => "EADDRINUSE",
        AddrNotAvailable => "EADDRNOTAVAIL",
        ConnectionRefused => "ECONNREFUSED",
        TimedOut => "ETIMEDOUT",
        WouldBlock => "EAGAIN",
        Interrupted => "EINTR",
        PermissionDenied => "EACCES",
        _ => "EOTHER",
    }
}
