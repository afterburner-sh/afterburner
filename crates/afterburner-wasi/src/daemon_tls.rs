// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `tls` - raw TLS host coordinator (B7).
//!
//! Backs the `tls.connect` / `tls.createServer` polyfill in
//! `polyfills/tls.js`. Architecture is the per-connection-task model
//! borrowed from `daemon_net`, with `tokio_rustls::TlsStream<TcpStream>`
//! standing in for the bare `TcpStream`. After the TLS handshake
//! completes we use `tokio::io::split` so the read and write halves
//! can be driven independently inside the connection task.
//!
//! ## Architecture
//!
//! ```text
//!   reader  ── stream.read() ────────────►  Data / End / Error events
//!   writer  ── tokio::sync::Notify ───────►  drain queue & write
//!                  ▲
//!                  │ wake on every send
//!   producer  ── kovan unbounded queue ───  __host_tls_write
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
//! `HopscotchMap<TlsConnId, ConnHandle>` for active connections,
//! `HopscotchMap<TlsServerId, ListenerHandle>` for listeners, atomics
//! for counters, kovan_channel for events. **No `Mutex` anywhere.**
//!
//! ## Manifold
//!
//! `tls.connect` requires `NetAccess::OutboundFull` (TLS over raw
//! TCP escapes URL-shaped policy, so `OutboundHttp` is **rejected**).
//! Hostname allow-lists support exact matches, `*`, and `*.suffix`
//! wildcards - same shape as `daemon_net`. Inbound listening is
//! daemon-mode-only; the library API never installs a `DaemonTls`
//! so `tls.createServer().listen()` cleanly errors.
//!
//! ## Certificate handling
//!
//! * **Client** - defaults to the Mozilla root CA bundle bundled by
//!   `webpki-roots`. Callers can pass `rejectUnauthorized: false` to
//!   bypass verification (test/dev-only); the polyfill is responsible
//!   for warning. Custom CA PEM bytes (`ca:`) are honored.
//! * **Server** - the polyfill passes `cert` and `key` PEM strings;
//!   we parse them with `rustls-pemfile` and build a single-cert
//!   `ServerConfig`. SNI / multi-cert routing isn't part of the
//!   minimum viable subset.

use crate::daemon_net_gate::net_outbound_allowed;
use afterburner_core::Manifold;
use kovan_channel::flavors::bounded::{
    Receiver as BoundedRx, Sender as BoundedTx, channel as bounded_channel,
};
use kovan_channel::flavors::unbounded::{
    Receiver as UnboundedRx, Sender as UnboundedTx, channel as unbounded_channel,
};
use kovan_map::HopscotchMap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore, ServerConfig, SignatureScheme};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub type TlsConnId = i32;
pub type TlsServerId = i32;

/// 64 KiB write high-water mark - matches `daemon_net`.
pub const WRITE_HWM: usize = 64 * 1024;

/// 64 KiB read chunk granularity.
pub const READ_CHUNK: usize = 64 * 1024;

pub mod errors {
    pub const E_NO_DAEMON: i32 = -1;
    pub const E_PERMISSION: i32 = -2;
    pub const E_BAD_ID: i32 = -3;
    pub const E_BAD_HOST: i32 = -4;
    pub const E_BAD_PORT: i32 = -5;
    pub const E_BAD_PAYLOAD: i32 = -6;
    pub const E_BAD_CERT: i32 = -7;
    pub const E_OTHER: i32 = -8;
}

/// Events surfaced to the daemon event loop. The CLI converts these
/// into `{kind:"tls-..."}` envelopes.
#[derive(Debug, Clone)]
pub enum TlsEvent {
    Connect {
        conn_id: TlsConnId,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        alpn_protocol: Option<String>,
        protocol: Option<String>,
        authorized: bool,
        /// IANA cipher-suite name (e.g. `TLS_AES_256_GCM_SHA384`).
        /// `None` if rustls couldn't supply one (shouldn't happen
        /// post-handshake but defensively typed).
        cipher: Option<String>,
        /// Server's certificate chain, leaf-first, DER-encoded.
        /// Empty for client-cert-not-presented or
        /// `rejectUnauthorized: false` paths that didn't populate it.
        peer_cert_chain_der: Vec<Vec<u8>>,
    },
    Connection {
        server_id: TlsServerId,
        conn_id: TlsConnId,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        alpn_protocol: Option<String>,
        protocol: Option<String>,
        cipher: Option<String>,
        /// Client cert chain when the server requested one. Empty
        /// when no client auth was configured (the default).
        peer_cert_chain_der: Vec<Vec<u8>>,
    },
    Data {
        conn_id: TlsConnId,
        payload_b64: String,
    },
    End {
        conn_id: TlsConnId,
    },
    Drain {
        conn_id: TlsConnId,
    },
    Close {
        conn_id: TlsConnId,
        had_error: bool,
    },
    Error {
        conn_id: TlsConnId,
        message: String,
        code: String,
    },
    Listening {
        server_id: TlsServerId,
        port: u16,
    },
    ServerError {
        server_id: TlsServerId,
        message: String,
    },
}

/// Connect-side options carried from JS to the host. The polyfill
/// validates user-supplied shapes; here we only check what we need
/// to drive rustls.
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// Disables certificate verification. Test/dev only - the
    /// polyfill emits a `console.warn` whenever this is set.
    pub reject_unauthorized: bool,
    /// SNI override (defaults to `host` if empty).
    pub servername: String,
    /// Optional ALPN protocol list (e.g. `["h2","http/1.1"]`).
    pub alpn: Vec<String>,
    /// Optional CA PEM blob for custom-root verification. When set,
    /// supplements the default Mozilla bundle.
    pub ca_pem: String,
    /// Client certificate PEM for mutual TLS. Both `cert_pem` and
    /// `key_pem` must be non-empty to present a client cert.
    pub cert_pem: String,
    /// Client private key PEM for mutual TLS. Both `cert_pem` and
    /// `key_pem` must be non-empty to present a client cert.
    pub key_pem: String,
}

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

enum WriteCmd {
    Bytes(Vec<u8>),
    End,
}

pub struct DaemonTls {
    runtime: Handle,
    manifold: Manifold,
    next_conn_id: AtomicI32,
    next_server_id: AtomicI32,
    conns: HopscotchMap<TlsConnId, ConnHandle>,
    servers: HopscotchMap<TlsServerId, ListenerHandle>,
    alive_conns: AtomicUsize,
    alive_servers: AtomicUsize,
    events_tx: BoundedTx<TlsEvent>,
    events_rx: BoundedRx<TlsEvent>,
    /// Multi-shard port arbiter - see `daemon_port_claims` for the
    /// owner / follower contract. `None` in single-shard mode.
    shared_claims: Option<Arc<crate::daemon_port_claims::SharedPortClaims>>,
    /// `server_id` → port for owners, so `close_server` releases
    /// the shared claim. Followers are NOT in this map.
    owned_listener_ports: HopscotchMap<TlsServerId, u16>,
}

impl std::fmt::Debug for DaemonTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonTls")
            .field("alive_conns", &self.alive_conns.load(Ordering::Relaxed))
            .field("alive_servers", &self.alive_servers.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Tuple returned by `register_accepted`: the new conn id plus the
/// post-handshake metadata pulled off the rustls connection (alpn,
/// protocol version, cipher suite name, peer cert chain DER bytes).
type AcceptedConn = (
    TlsConnId,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<Vec<u8>>,
);

impl DaemonTls {
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
        let (tx, rx) = bounded_channel::<TlsEvent>(4096);
        Arc::new(Self {
            runtime,
            manifold,
            next_conn_id: AtomicI32::new(1),
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

    pub fn try_recv_event(&self) -> Option<TlsEvent> {
        self.events_rx.try_recv()
    }

    pub fn has_refs(&self) -> bool {
        self.alive_conns.load(Ordering::Acquire) > 0
            || self.alive_servers.load(Ordering::Acquire) > 0
    }

    pub fn pending_bytes(&self, conn_id: TlsConnId) -> i32 {
        self.conns
            .get(&conn_id)
            .map(|h| h.pending_bytes.load(Ordering::Acquire) as i32)
            .unwrap_or(0)
    }

    pub fn connect(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        opts: ConnectOptions,
        last_error: &mut String,
    ) -> i32 {
        if !net_outbound_allowed(&self.manifold, host, port) {
            *last_error = format!("tls.connect: not granted by manifold (host {host}:{port})");
            return errors::E_PERMISSION;
        }
        if host.is_empty() {
            *last_error = "tls.connect: empty host".into();
            return errors::E_BAD_HOST;
        }
        if port == 0 {
            *last_error = "tls.connect: port must be > 0".into();
            return errors::E_BAD_PORT;
        }
        let client_config = match build_client_config(&opts, last_error) {
            Some(c) => c,
            None => return errors::E_BAD_CERT,
        };

        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let handle = self.spawn_client(conn_id, host.to_string(), port, opts, client_config);
        self.conns.insert(conn_id, handle);
        self.alive_conns.fetch_add(1, Ordering::Release);
        conn_id
    }

    pub fn write(&self, conn_id: TlsConnId, data: Vec<u8>, last_error: &mut String) -> i32 {
        let Some(handle) = self.conns.get(&conn_id) else {
            *last_error = format!("tls.write: unknown conn id {conn_id}");
            return errors::E_BAD_ID;
        };
        if handle.half_closed.load(Ordering::Acquire) {
            *last_error = format!("tls.write: conn {conn_id} already half-closed");
            return errors::E_BAD_ID;
        }
        let n = data.len();
        handle.pending_bytes.fetch_add(n, Ordering::AcqRel);
        handle.write_tx.send(WriteCmd::Bytes(data));
        handle.wake.notify_one();
        0
    }

    pub fn end(&self, conn_id: TlsConnId, last_error: &mut String) -> i32 {
        let Some(handle) = self.conns.get(&conn_id) else {
            *last_error = format!("tls.end: unknown conn id {conn_id}");
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

    pub fn destroy(&self, conn_id: TlsConnId) -> i32 {
        // Same shape as daemon_net: keep the entry in `conns` so
        // `mark_closed` can observe it post-dispatch; emit Close from
        // here since aborting the task means it can't.
        if let Some(handle) = self.conns.get(&conn_id) {
            handle.abort.abort();
            self.events_tx.send(TlsEvent::Close {
                conn_id,
                had_error: false,
            });
        }
        0
    }

    // The TLS listen params mirror the host-import ABI one-to-one (host/port +
    // the cert/key/SNI/client-CA/verify config + the error out-param); grouping
    // them into a struct would just be repacked at the wasm boundary. Same
    // convention as the other daemon host imports.
    #[allow(clippy::too_many_arguments)]
    pub fn listen(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        cert_pem: &str,
        key_pem: &str,
        sni_map_json: &str,
        client_ca_pem: &str,
        request_client_cert: bool,
        last_error: &mut String,
    ) -> i32 {
        if host.is_empty() {
            *last_error = "tls.listen: empty host".into();
            return errors::E_BAD_HOST;
        }

        // Multi-shard arbitration. Same contract as DaemonNet:
        // first shard to claim port `p` becomes the kernel-level
        // owner, others become followers (no real bind; JS sees a
        // live listener; events flow only to the owner). The cert
        // build still happens for followers so a malformed PEM
        // surfaces consistently across shards rather than only
        // on the binding shard.
        let server_config = match build_server_config(
            cert_pem,
            key_pem,
            sni_map_json,
            client_ca_pem,
            request_client_cert,
            last_error,
        ) {
            Some(c) => c,
            None => return errors::E_BAD_CERT,
        };

        if let Some(claims) = &self.shared_claims {
            use crate::daemon_port_claims::ClaimResult;
            match claims.try_claim(port) {
                ClaimResult::Owner(_) => { /* fall through to real bind */ }
                ClaimResult::Follower(_) => {
                    let server_id = self.next_server_id.fetch_add(1, Ordering::Relaxed);
                    self.alive_servers.fetch_add(1, Ordering::Release);
                    let _ = server_config; // dropped; only owner uses it
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
            .spawn(server_task(server_id, bind, server_config, evt_tx, coord))
            .abort_handle();

        self.servers.insert(server_id, ListenerHandle { abort });
        if self.shared_claims.is_some() {
            self.owned_listener_ports.insert(server_id, port);
        }
        self.alive_servers.fetch_add(1, Ordering::Release);
        server_id
    }

    pub fn close_server(&self, server_id: TlsServerId) -> i32 {
        if let Some(handle) = self.servers.remove(&server_id) {
            handle.abort.abort();
            self.alive_servers.fetch_sub(1, Ordering::Release);
            if let Some(claims) = &self.shared_claims
                && let Some(port) = self.owned_listener_ports.remove(&server_id)
            {
                claims.release(port);
            }
            return 0;
        }
        // Follower stub close (multi-shard only). In single-shard
        // mode an unknown id is historically a no-op; preserve.
        if self.shared_claims.is_some() && self.alive_servers.load(Ordering::Acquire) > 0 {
            self.alive_servers.fetch_sub(1, Ordering::Release);
        }
        0
    }

    pub fn mark_closed(&self, conn_id: TlsConnId) {
        if self.conns.remove(&conn_id).is_some() {
            self.alive_conns.fetch_sub(1, Ordering::Release);
        }
    }

    fn spawn_client(
        self: &Arc<Self>,
        conn_id: TlsConnId,
        host: String,
        port: u16,
        opts: ConnectOptions,
        client_config: Arc<ClientConfig>,
    ) -> ConnHandle {
        let (write_tx, write_rx) = unbounded_channel::<WriteCmd>();
        let pending = Arc::new(AtomicUsize::new(0));
        let half_closed = Arc::new(AtomicBool::new(false));
        let wake = Arc::new(Notify::new());
        let evt_tx = self.events_tx.clone();

        let abort = self
            .runtime
            .spawn(client_task(
                conn_id,
                host,
                port,
                opts,
                client_config,
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

    fn register_accepted(
        self: &Arc<Self>,
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
    ) -> AcceptedConn {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (write_tx, write_rx) = unbounded_channel::<WriteCmd>();
        let pending = Arc::new(AtomicUsize::new(0));
        let half_closed = Arc::new(AtomicBool::new(false));
        let wake = Arc::new(Notify::new());
        let evt_tx = self.events_tx.clone();

        let (_, conn_state) = stream.get_ref();
        let alpn = conn_state
            .alpn_protocol()
            .map(|b| String::from_utf8_lossy(b).into_owned());
        let protocol = conn_state.protocol_version().map(protocol_label);
        let cipher = conn_state
            .negotiated_cipher_suite()
            .and_then(|cs| cs.suite().as_str())
            .map(normalize_cipher_name);
        let peer_certs = conn_state
            .peer_certificates()
            .map(|chain| {
                chain
                    .iter()
                    .map(|c| c.as_ref().to_vec())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let abort = self
            .runtime
            .spawn(drive_server_socket(
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
        let _ = (local, remote);
        (conn_id, alpn, protocol, cipher, peer_certs)
    }
}

// net_outbound_allowed and host_allowed live in daemon_net_gate (one canonical copy).

// ---------------------------------------------------------------------
// rustls config builders
// ---------------------------------------------------------------------

fn build_client_config(
    opts: &ConnectOptions,
    last_error: &mut String,
) -> Option<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if !opts.ca_pem.is_empty() {
        let mut cursor = std::io::Cursor::new(opts.ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut cursor) {
            match cert {
                Ok(c) => {
                    if let Err(e) = roots.add(c) {
                        *last_error = format!("tls.connect: ca_pem add: {e}");
                        return None;
                    }
                }
                Err(e) => {
                    *last_error = format!("tls.connect: ca_pem parse: {e}");
                    return None;
                }
            }
        }
    }

    // Determine whether the caller wants to present a client cert.
    let has_client_cert = !opts.cert_pem.is_empty() && !opts.key_pem.is_empty();

    let builder = ClientConfig::builder();
    let mut cfg = if opts.reject_unauthorized {
        let wants_cert = builder.with_root_certificates(roots);
        if has_client_cert {
            let pair = match parse_certified_key(&opts.cert_pem, &opts.key_pem) {
                Ok(p) => p,
                Err(e) => {
                    *last_error = format!("tls.connect: client cert/key: {e}");
                    return None;
                }
            };
            match wants_cert.with_client_auth_cert(pair.cert, pair.key) {
                Ok(c) => c,
                Err(e) => {
                    *last_error = format!("tls.connect: client auth cert: {e}");
                    return None;
                }
            }
        } else {
            wants_cert.with_no_client_auth()
        }
    } else {
        let wants_cert = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify));
        if has_client_cert {
            let pair = match parse_certified_key(&opts.cert_pem, &opts.key_pem) {
                Ok(p) => p,
                Err(e) => {
                    *last_error = format!("tls.connect: client cert/key: {e}");
                    return None;
                }
            };
            match wants_cert.with_client_auth_cert(pair.cert, pair.key) {
                Ok(c) => c,
                Err(e) => {
                    *last_error = format!("tls.connect: client auth cert: {e}");
                    return None;
                }
            }
        } else {
            wants_cert.with_no_client_auth()
        }
    };
    if !opts.alpn.is_empty() {
        cfg.alpn_protocols = opts.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    }
    Some(Arc::new(cfg))
}

fn build_server_config(
    cert_pem: &str,
    key_pem: &str,
    sni_map_json: &str,
    client_ca_pem: &str,
    request_client_cert: bool,
    last_error: &mut String,
) -> Option<Arc<ServerConfig>> {
    let default_certified = match parse_certified_key(cert_pem, key_pem) {
        Ok(k) => k,
        Err(e) => {
            *last_error = format!("tls.listen: default cert/key: {e}");
            return None;
        }
    };

    // Parse the SNI map: a JSON object mapping `servername` →
    // `{cert, key}`. Empty / missing means "no SNI routing - every
    // ClientHello gets the default cert."
    let sni_map = if sni_map_json.is_empty() {
        Vec::new()
    } else {
        let parsed: serde_json::Value = match serde_json::from_str(sni_map_json) {
            Ok(v) => v,
            Err(e) => {
                *last_error = format!("tls.listen: SNI map JSON parse: {e}");
                return None;
            }
        };
        let entries = match parsed {
            serde_json::Value::Array(arr) => arr,
            _ => {
                *last_error =
                    "tls.listen: SNI map must be a JSON array of {servername,cert,key}".into();
                return None;
            }
        };
        let mut out = Vec::with_capacity(entries.len());
        for ent in entries {
            let server_name = ent.get("servername").and_then(|x| x.as_str()).ok_or("");
            let cert = ent.get("cert").and_then(|x| x.as_str()).unwrap_or("");
            let key = ent.get("key").and_then(|x| x.as_str()).unwrap_or("");
            if server_name.is_err() || cert.is_empty() || key.is_empty() {
                *last_error = "tls.listen: each SNI entry needs servername+cert+key".into();
                return None;
            }
            let server_name = server_name.unwrap().to_lowercase();
            let certified = match parse_certified_key(cert, key) {
                Ok(k) => k,
                Err(e) => {
                    *last_error = format!("tls.listen: SNI {server_name}: {e}");
                    return None;
                }
            };
            out.push((server_name, Arc::new(certified)));
        }
        out
    };

    // Build the client verifier: either mTLS (when requestCert is true
    // and a client CA PEM is supplied) or no-client-auth (the default,
    // one-way TLS path preserved exactly as before).
    let client_auth = if request_client_cert && !client_ca_pem.is_empty() {
        let mut ca_roots = RootCertStore::empty();
        let mut cursor = std::io::Cursor::new(client_ca_pem.as_bytes());
        for item in rustls_pemfile::certs(&mut cursor) {
            match item {
                Ok(c) => {
                    if let Err(e) = ca_roots.add(c) {
                        *last_error = format!("tls.listen: client CA add: {e}");
                        return None;
                    }
                }
                Err(e) => {
                    *last_error = format!("tls.listen: client CA parse: {e}");
                    return None;
                }
            }
        }
        let verifier =
            match rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_roots)).build() {
                Ok(v) => v,
                Err(e) => {
                    *last_error = format!("tls.listen: client verifier build: {e}");
                    return None;
                }
            };
        Some(verifier)
    } else {
        None
    };

    if sni_map.is_empty() {
        // Single-cert path - keep the simpler with_single_cert builder
        // so error messages stay clean for the most common shape.
        let builder = ServerConfig::builder();
        let wants_cert = match client_auth {
            Some(v) => builder.with_client_cert_verifier(v),
            None => builder.with_no_client_auth(),
        };
        return wants_cert
            .with_single_cert(
                default_certified.cert.clone(),
                default_certified.key.clone_key(),
            )
            .map(Arc::new)
            .map_err(|e| {
                *last_error = format!("tls.listen: cert/key mismatch: {e}");
            })
            .ok();
    }

    // SNI path - install a `ResolvesServerCert` impl that maps the
    // ClientHello's `server_name` to the right certified key.
    let resolver = SniResolver {
        default: Arc::new(default_certified),
        by_name: sni_map.into_iter().collect(),
    };
    let builder = ServerConfig::builder();
    let wants_cert = match client_auth {
        Some(v) => builder.with_client_cert_verifier(v),
        None => builder.with_no_client_auth(),
    };
    let cfg = wants_cert.with_cert_resolver(Arc::new(resolver));
    Some(Arc::new(cfg))
}

/// Cert + key parsed out of two PEM blobs and packaged for rustls'
/// `CertifiedKey`. Stored in the SNI map so the resolver can hand
/// the right one to each ClientHello.
struct CertifiedPair {
    cert: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn parse_certified_key(
    cert_pem: &str,
    key_pem: &str,
) -> std::result::Result<CertifiedPair, String> {
    let mut cert_cursor = std::io::Cursor::new(cert_pem.as_bytes());
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("cert PEM parse: {e}"))?;
    if cert_chain.is_empty() {
        return Err("cert PEM contains no certificates".into());
    }
    let mut key_cursor = std::io::Cursor::new(key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|e| format!("key PEM parse: {e}"))?
        .ok_or_else(|| "key PEM contains no private key".to_string())?;
    Ok(CertifiedPair {
        cert: cert_chain,
        key,
    })
}

/// rustls `ResolvesServerCert` impl - the SNI router.
struct SniResolver {
    default: Arc<CertifiedPair>,
    by_name: std::collections::HashMap<String, Arc<CertifiedPair>>,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver")
            .field("default", &"<cert+key>")
            .field("by_name", &self.by_name.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let pair = match client_hello.server_name() {
            Some(name) => {
                let name_lc = name.to_ascii_lowercase();
                if let Some(p) = self.by_name.get(&name_lc) {
                    p.clone()
                } else if let Some(p) = wildcard_match(&self.by_name, &name_lc) {
                    p
                } else {
                    self.default.clone()
                }
            }
            None => self.default.clone(),
        };
        // Build the runtime CertifiedKey. rustls 0.23 needs a
        // `SigningKey` derived from the private key bytes; the helper
        // chooses the algorithm matching the key.
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&pair.key).ok()?;
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            pair.cert.clone(),
            signing_key,
        )))
    }
}

/// Match `requested` against keys with a leading `*.` wildcard.
/// `*.example.com` matches `api.example.com` but not `example.com`
/// itself or `nested.api.example.com` (single label only -
/// `tls.createServer` callers wanting deep wildcards register them
/// explicitly).
fn wildcard_match(
    map: &std::collections::HashMap<String, Arc<CertifiedPair>>,
    requested: &str,
) -> Option<Arc<CertifiedPair>> {
    let dot = requested.find('.')?;
    let suffix = &requested[dot + 1..];
    let wild_key = format!("*.{suffix}");
    map.get(&wild_key).cloned()
}

/// Permissive verifier used when the polyfill passes
/// `rejectUnauthorized: false`. Marked `Debug` for rustls' bound; the
/// type carries no state.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Translate rustls' internal cipher-suite identifier into the
/// IANA-standard name that Node's `socket.getCipher()` returns.
/// rustls names TLS 1.3 suites as `TLS13_AES_256_GCM_SHA384` etc.;
/// the canonical IANA / Node form drops the `13` prefix to
/// `TLS_AES_256_GCM_SHA384`. TLS 1.2 names already match.
fn normalize_cipher_name(rustls_name: &'static str) -> String {
    if let Some(rest) = rustls_name.strip_prefix("TLS13_") {
        format!("TLS_{rest}")
    } else {
        rustls_name.to_string()
    }
}

fn protocol_label(v: rustls::ProtocolVersion) -> String {
    use rustls::ProtocolVersion::*;
    match v {
        TLSv1_3 => "TLSv1.3".into(),
        TLSv1_2 => "TLSv1.2".into(),
        other => format!("{other:?}"),
    }
}

// ---------------------------------------------------------------------
// Per-connection / per-listener tokio tasks.
// ---------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn client_task(
    conn_id: TlsConnId,
    host: String,
    port: u16,
    opts: ConnectOptions,
    client_config: Arc<ClientConfig>,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<TlsEvent>,
) {
    // 1. TCP connect.
    let tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            evt_tx.send(TlsEvent::Error {
                conn_id,
                message: e.to_string(),
                code: io_error_code(&e),
            });
            evt_tx.send(TlsEvent::Close {
                conn_id,
                had_error: true,
            });
            return;
        }
    };
    let local = tcp.local_addr().ok();
    let remote = tcp.peer_addr().ok();

    // 2. TLS handshake - `servername` falls back to `host`.
    let sni_label = if opts.servername.is_empty() {
        host.as_str()
    } else {
        opts.servername.as_str()
    };
    let server_name = match ServerName::try_from(sni_label.to_string()) {
        Ok(n) => n,
        Err(_) => {
            evt_tx.send(TlsEvent::Error {
                conn_id,
                message: format!("tls.connect: invalid servername {sni_label}"),
                code: "ERR_INVALID_HOSTNAME".into(),
            });
            evt_tx.send(TlsEvent::Close {
                conn_id,
                had_error: true,
            });
            return;
        }
    };
    let connector = TlsConnector::from(client_config);
    let stream = match connector.connect(server_name, tcp).await {
        Ok(s) => s,
        Err(e) => {
            evt_tx.send(TlsEvent::Error {
                conn_id,
                message: format!("tls handshake: {e}"),
                code: tls_error_code(&e),
            });
            evt_tx.send(TlsEvent::Close {
                conn_id,
                had_error: true,
            });
            return;
        }
    };

    let alpn_protocol;
    let protocol;
    let cipher;
    let peer_cert_chain_der;
    {
        let (_, conn_state) = stream.get_ref();
        alpn_protocol = conn_state
            .alpn_protocol()
            .map(|b| String::from_utf8_lossy(b).into_owned());
        protocol = conn_state.protocol_version().map(protocol_label);
        cipher = conn_state
            .negotiated_cipher_suite()
            .and_then(|cs| cs.suite().as_str())
            .map(normalize_cipher_name);
        peer_cert_chain_der = conn_state
            .peer_certificates()
            .map(|chain| {
                chain
                    .iter()
                    .map(|c| c.as_ref().to_vec())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
    }
    evt_tx.send(TlsEvent::Connect {
        conn_id,
        local,
        remote,
        alpn_protocol,
        protocol,
        authorized: opts.reject_unauthorized,
        cipher,
        peer_cert_chain_der,
    });

    drive_client_socket(conn_id, stream, write_rx, wake, pending, evt_tx).await;
}

async fn server_task(
    server_id: TlsServerId,
    bind: String,
    server_config: Arc<ServerConfig>,
    evt_tx: BoundedTx<TlsEvent>,
    coord: Arc<DaemonTls>,
) {
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            evt_tx.send(TlsEvent::ServerError {
                server_id,
                message: format!("bind {bind}: {e}"),
            });
            return;
        }
    };
    let bound_port = listener.local_addr().ok().map(|a| a.port()).unwrap_or(0);
    evt_tx.send(TlsEvent::Listening {
        server_id,
        port: bound_port,
    });

    let acceptor = TlsAcceptor::from(server_config);

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                evt_tx.send(TlsEvent::ServerError {
                    server_id,
                    message: format!("accept: {e}"),
                });
                return;
            }
        };
        let local = stream.local_addr().ok();
        let remote = stream.peer_addr().ok();
        let acceptor = acceptor.clone();
        let evt_tx2 = evt_tx.clone();
        let coord2 = Arc::clone(&coord);
        tokio::spawn(async move {
            // Per-connection handshake - running it inline with
            // `accept` would let one slow client stall the loop.
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t,
                Err(e) => {
                    evt_tx2.send(TlsEvent::ServerError {
                        server_id,
                        message: format!("handshake: {e}"),
                    });
                    return;
                }
            };
            let (conn_id, alpn_protocol, protocol, cipher, peer_cert_chain_der) =
                coord2.register_accepted(tls, local, remote);
            evt_tx2.send(TlsEvent::Connection {
                server_id,
                conn_id,
                local,
                remote,
                alpn_protocol,
                protocol,
                cipher,
                peer_cert_chain_der,
            });
        });
    }
}

/// Drive both halves of an established TLS client stream.
async fn drive_client_socket(
    conn_id: TlsConnId,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<TlsEvent>,
) {
    let (read_half, write_half) = tokio::io::split(stream);
    drive_split(
        conn_id, read_half, write_half, write_rx, wake, pending, evt_tx,
    )
    .await;
}

/// Drive both halves of an established TLS server-accepted stream.
async fn drive_server_socket(
    conn_id: TlsConnId,
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<TlsEvent>,
) {
    let (read_half, write_half) = tokio::io::split(stream);
    drive_split(
        conn_id, read_half, write_half, write_rx, wake, pending, evt_tx,
    )
    .await;
}

/// Generic split-stream driver. Identical to `daemon_net::drive_socket`
/// but parameterized over the read/write halves so it works for both
/// client and server `TlsStream`s.
async fn drive_split<R, W>(
    conn_id: TlsConnId,
    mut read_half: R,
    mut write_half: W,
    write_rx: UnboundedRx<WriteCmd>,
    wake: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    evt_tx: BoundedTx<TlsEvent>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut read_buf = vec![0u8; READ_CHUNK];
    let mut had_error = false;
    let mut writer_open = true;
    let mut was_over_hwm = false;

    'outer: loop {
        while let Some(cmd) = write_rx.try_recv() {
            match cmd {
                WriteCmd::Bytes(buf) => {
                    let n = buf.len();
                    if let Err(e) = write_half.write_all(&buf).await {
                        evt_tx.send(TlsEvent::Error {
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
                        evt_tx.send(TlsEvent::Drain { conn_id });
                        was_over_hwm = false;
                    } else if !was_over_hwm && now >= WRITE_HWM {
                        was_over_hwm = true;
                    }
                }
                WriteCmd::End => {
                    let _ = write_half.shutdown().await;
                    writer_open = false;
                }
            }
        }

        if !writer_open && pending.load(Ordering::Acquire) == 0 {
            // Half-closed and queue drained - nothing the writer arm
            // could do; reader keeps running until peer closes.
        }

        tokio::select! {
            res = read_half.read(&mut read_buf) => {
                match res {
                    Ok(0) => {
                        evt_tx.send(TlsEvent::End { conn_id });
                        break 'outer;
                    }
                    Ok(n) => {
                        let payload_b64 = base64_encode(&read_buf[..n]);
                        evt_tx.send(TlsEvent::Data { conn_id, payload_b64 });
                    }
                    Err(e) => {
                        // rustls flags peers that drop the TCP socket
                        // without `close_notify` as `UnexpectedEof`.
                        // Node's tls treats that case as a clean end -
                        // mirror it: emit End, no `error`. Genuine I/O
                        // errors (resets, broken pipes) still surface
                        // through `Error`.
                        if matches!(e.kind(), std::io::ErrorKind::UnexpectedEof) {
                            evt_tx.send(TlsEvent::End { conn_id });
                            break 'outer;
                        }
                        evt_tx.send(TlsEvent::Error {
                            conn_id,
                            message: e.to_string(),
                            code: io_error_code(&e),
                        });
                        had_error = true;
                        break 'outer;
                    }
                }
            }
            _ = wake.notified() => {
                // Loop back to drain the write queue.
            }
        }
    }

    evt_tx.send(TlsEvent::Close { conn_id, had_error });
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

fn tls_error_code(_e: &std::io::Error) -> String {
    // rustls surfaces handshake failures as `io::Error` with kind
    // `InvalidData`; we only care that the JS side gets a stable code.
    "ERR_TLS_HANDSHAKE".into()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn decode_payload(b64: &str, last_error: &mut String) -> Option<Vec<u8>> {
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(v) => Some(v),
        Err(e) => {
            *last_error = format!("tls: payload base64: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::NetAccess;

    #[test]
    fn outbound_full_no_allowlist_permits_anything() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(None);
        assert!(net_outbound_allowed(&m, "example.com", 443));
        assert!(net_outbound_allowed(&m, "127.0.0.1", 8443));
    }

    #[test]
    fn outbound_full_allowlist_filters_hosts() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["api.example.com".into()]));
        assert!(net_outbound_allowed(&m, "api.example.com", 443));
        // Port-less entry: any port.
        assert!(net_outbound_allowed(&m, "api.example.com", 8443));
        assert!(!net_outbound_allowed(&m, "evil.com", 443));
    }

    #[test]
    fn allowlist_host_port_entries() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["db.example.com:5432".into()]));
        assert!(net_outbound_allowed(&m, "db.example.com", 5432));
        assert!(!net_outbound_allowed(&m, "db.example.com", 5433));
        assert!(!net_outbound_allowed(&m, "other.example.com", 5432));
    }

    #[test]
    fn outbound_http_blocks_raw_tls() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundHttp(None);
        assert!(!net_outbound_allowed(&m, "example.com", 443));
    }

    #[test]
    fn sealed_blocks_everything() {
        let m = Manifold::sealed();
        assert!(!net_outbound_allowed(&m, "anything", 443));
    }

    #[test]
    fn wildcard_subdomain_match() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["*.trusted.io".into()]));
        assert!(net_outbound_allowed(&m, "api.trusted.io", 443));
        assert!(!net_outbound_allowed(&m, "trusted.io", 443));
        assert!(!net_outbound_allowed(&m, "evil.io", 443));
    }

    #[test]
    fn build_server_config_round_trip() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();
        let mut err = String::new();
        let cfg = build_server_config(&cert_pem, &key_pem, "", "", false, &mut err);
        assert!(cfg.is_some(), "err: {err}");
    }

    #[test]
    fn build_server_config_with_sni_map() {
        // Generate three certs: a default + two SNI-keyed.
        let default =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("default");
        let alpha =
            rcgen::generate_simple_self_signed(vec!["alpha.example".into()]).expect("alpha");
        let beta = rcgen::generate_simple_self_signed(vec!["beta.example".into()]).expect("beta");
        let sni_json = serde_json::json!([
            {
                "servername": "alpha.example",
                "cert": alpha.cert.pem(),
                "key": alpha.signing_key.serialize_pem(),
            },
            {
                "servername": "beta.example",
                "cert": beta.cert.pem(),
                "key": beta.signing_key.serialize_pem(),
            },
        ])
        .to_string();
        let mut err = String::new();
        let cfg = build_server_config(
            &default.cert.pem(),
            &default.signing_key.serialize_pem(),
            &sni_json,
            "",
            false,
            &mut err,
        );
        assert!(cfg.is_some(), "err: {err}");
    }

    #[test]
    fn build_server_config_rejects_malformed_sni() {
        let default = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
        let mut err = String::new();
        let cfg = build_server_config(
            &default.cert.pem(),
            &default.signing_key.serialize_pem(),
            r#"[{"servername": "x", "cert": ""}]"#,
            "",
            false,
            &mut err,
        );
        assert!(cfg.is_none(), "should reject missing key");
        assert!(!err.is_empty());
    }

    #[test]
    fn wildcard_match_resolves_first_label() {
        use std::sync::Arc;
        let cert = rcgen::generate_simple_self_signed(vec!["*.example.com".into()]).expect("cert");
        let pair =
            parse_certified_key(&cert.cert.pem(), &cert.signing_key.serialize_pem()).expect("pair");
        let mut map = std::collections::HashMap::new();
        map.insert("*.example.com".to_string(), Arc::new(pair));
        // Single-label wildcard match.
        assert!(wildcard_match(&map, "api.example.com").is_some());
        // No match for the bare apex (single-label rule).
        assert!(wildcard_match(&map, "example.com").is_none());
        // Different domain - no match.
        assert!(wildcard_match(&map, "api.other.com").is_none());
    }

    // -----------------------------------------------------------------
    // mTLS in-process handshake tests
    //
    // These generate a tiny CA + leaf cert pair with rcgen 0.14, spin
    // up a real tokio_rustls server + client in-process, and verify:
    //
    //   (a) a client presenting a cert signed by the CA is accepted;
    //       both sides can see the peer cert chain.
    //   (b) a client presenting NO cert is rejected by the server
    //       (handshake fails).
    //   (c) a client presenting a cert signed by a DIFFERENT CA is
    //       rejected.
    //   (d) one-way TLS (no requestCert) is unaffected: a client with
    //       no client cert still connects fine.
    //
    // The CA cert is self-signed; the leaf cert is signed by that CA.
    // -----------------------------------------------------------------

    /// Generate a CA cert + key pair using rcgen 0.14's `CertifiedIssuer`
    /// which bundles both the `Certificate` and the `Issuer` needed to
    /// sign leaf certs.
    fn make_ca() -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().expect("CA key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rcgen::CertifiedIssuer::self_signed(params, ca_key).expect("CA cert")
    }

    /// Generate a leaf cert signed by the given CA issuer.
    fn make_leaf_signed_by(
        ca: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
        san: &str,
    ) -> (rcgen::Certificate, rcgen::KeyPair) {
        use rcgen::{CertificateParams, KeyPair};
        let leaf_key = KeyPair::generate().expect("leaf key");
        let params = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
        let leaf_cert = params.signed_by(&leaf_key, ca).expect("leaf cert");
        (leaf_cert, leaf_key)
    }

    /// Bind a TLS server, run one accept, and return the peer cert chain
    /// DER bytes from the completed handshake. `client_fn` receives the
    /// bound port and must drive the client connection to completion.
    /// Returns `Err` if the server-side accept or handshake failed.
    async fn run_mtls_handshake<F, Fut>(
        server_cfg: Arc<ServerConfig>,
        client_fn: F,
    ) -> Result<Vec<Vec<u8>>, String>
    where
        F: FnOnce(u16) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();

        // Drive the client on a separate task so server and client run
        // concurrently inside the same tokio runtime.
        tokio::spawn(client_fn(port));

        let acceptor = TlsAcceptor::from(server_cfg);
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let tls = acceptor.accept(stream).await.map_err(|e| e.to_string())?;

        let (_, conn) = tls.get_ref();
        let chain = conn
            .peer_certificates()
            .map(|c| c.iter().map(|d| d.as_ref().to_vec()).collect::<Vec<_>>())
            .unwrap_or_default();
        Ok(chain)
    }

    #[tokio::test]
    async fn mtls_authorized_client_accepted() {
        // CA + leaf cert for the server identity.
        let server_ca = make_ca();
        let (server_leaf, server_leaf_key) = make_leaf_signed_by(&server_ca, "localhost");

        // Separate CA + leaf cert for the client identity.
        let client_ca = make_ca();
        let (client_leaf, client_leaf_key) = make_leaf_signed_by(&client_ca, "client.test");

        let server_cert_pem = server_leaf.pem();
        let server_key_pem = server_leaf_key.serialize_pem();
        let client_ca_pem = client_ca.pem();

        // Build the mTLS server config: requires client cert verified against client_ca.
        let mut err = String::new();
        let server_cfg = build_server_config(
            &server_cert_pem,
            &server_key_pem,
            "",
            &client_ca_pem,
            true,
            &mut err,
        )
        .expect(&format!("server config: {err}"));

        // Build the mTLS client config: verifies server against server_ca,
        // presents client_leaf signed by client_ca.
        let server_ca_pem = server_ca.pem();
        let client_cert_pem = client_leaf.pem();
        let client_key_pem = client_leaf_key.serialize_pem();

        let client_opts = ConnectOptions {
            reject_unauthorized: true,
            servername: "localhost".into(),
            alpn: Vec::new(),
            ca_pem: server_ca_pem,
            cert_pem: client_cert_pem,
            key_pem: client_key_pem,
        };
        let mut client_err = String::new();
        let client_cfg = build_client_config(&client_opts, &mut client_err)
            .expect(&format!("client config: {client_err}"));

        let peer_chain = run_mtls_handshake(server_cfg, move |port| async move {
            use rustls::pki_types::ServerName;
            use tokio::io::AsyncWriteExt;
            use tokio_rustls::TlsConnector;

            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("TCP connect");
            let connector = TlsConnector::from(client_cfg);
            let sn = ServerName::try_from("localhost".to_string()).expect("sn");
            let mut stream = connector.connect(sn, tcp).await.expect("client handshake");
            // Send a byte so the server-side read doesn't stall.
            let _ = stream.write_all(b"ping").await;
            let _ = stream.shutdown().await;
        })
        .await
        .expect("server handshake");

        // The server must have received the client cert chain.
        assert!(!peer_chain.is_empty(), "server must see client cert chain");
    }

    #[tokio::test]
    async fn mtls_client_without_cert_rejected() {
        // CA + leaf for the server.
        let server_ca = make_ca();
        let (server_leaf, server_leaf_key) = make_leaf_signed_by(&server_ca, "localhost");

        // A separate CA is the expected client CA; the connecting
        // client presents no cert at all, so the handshake must fail.
        let client_ca = make_ca();

        let mut err = String::new();
        let server_cfg = build_server_config(
            &server_leaf.pem(),
            &server_leaf_key.serialize_pem(),
            "",
            &client_ca.pem(),
            true,
            &mut err,
        )
        .expect(&format!("server config: {err}"));

        let server_ca_pem = server_ca.pem();
        // Client that presents NO client cert.
        let client_opts = ConnectOptions {
            reject_unauthorized: true,
            servername: "localhost".into(),
            alpn: Vec::new(),
            ca_pem: server_ca_pem,
            cert_pem: String::new(),
            key_pem: String::new(),
        };
        let mut client_err = String::new();
        let client_cfg = build_client_config(&client_opts, &mut client_err)
            .expect(&format!("client config: {client_err}"));

        // The server should reject the connection; run_mtls_handshake
        // returns Err when the acceptor.accept() call fails.
        let result = run_mtls_handshake(server_cfg, move |port| async move {
            use rustls::pki_types::ServerName;
            use tokio_rustls::TlsConnector;

            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("TCP connect");
            let connector = TlsConnector::from(client_cfg);
            let sn = ServerName::try_from("localhost".to_string()).expect("sn");
            // This will fail; the client just tries and ignores the error.
            let _ = connector.connect(sn, tcp).await;
        })
        .await;

        assert!(
            result.is_err(),
            "server must reject a client with no cert; got Ok"
        );
    }

    #[tokio::test]
    async fn mtls_client_wrong_ca_rejected() {
        // CA + leaf for the server.
        let server_ca = make_ca();
        let (server_leaf, server_leaf_key) = make_leaf_signed_by(&server_ca, "localhost");

        // The server trusts client_ca_trusted. The client presents a
        // cert signed by a DIFFERENT CA (client_ca_untrusted).
        let client_ca_trusted = make_ca();
        let client_ca_untrusted = make_ca();
        let (client_leaf_bad, client_leaf_bad_key) =
            make_leaf_signed_by(&client_ca_untrusted, "bad.client");

        let mut err = String::new();
        let server_cfg = build_server_config(
            &server_leaf.pem(),
            &server_leaf_key.serialize_pem(),
            "",
            &client_ca_trusted.pem(),
            true,
            &mut err,
        )
        .expect(&format!("server config: {err}"));

        let server_ca_pem = server_ca.pem();
        let client_cert_pem = client_leaf_bad.pem();
        let client_key_pem = client_leaf_bad_key.serialize_pem();

        let client_opts = ConnectOptions {
            reject_unauthorized: true,
            servername: "localhost".into(),
            alpn: Vec::new(),
            ca_pem: server_ca_pem,
            cert_pem: client_cert_pem,
            key_pem: client_key_pem,
        };
        let mut client_err = String::new();
        let client_cfg = build_client_config(&client_opts, &mut client_err)
            .expect(&format!("client config: {client_err}"));

        let result = run_mtls_handshake(server_cfg, move |port| async move {
            use rustls::pki_types::ServerName;
            use tokio_rustls::TlsConnector;

            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("TCP connect");
            let connector = TlsConnector::from(client_cfg);
            let sn = ServerName::try_from("localhost".to_string()).expect("sn");
            let _ = connector.connect(sn, tcp).await;
        })
        .await;

        assert!(
            result.is_err(),
            "server must reject a client cert from an untrusted CA; got Ok"
        );
    }

    #[tokio::test]
    async fn one_way_tls_unaffected_by_mtls_option() {
        // Confirm that one-way TLS (request_client_cert: false) still
        // works when the client presents no cert. This is the regression
        // guard: mTLS changes must not break the existing TLS path.
        let server_ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("srv");
        let server_cert_pem = server_ck.cert.pem();
        let server_key_pem = server_ck.signing_key.serialize_pem();

        let mut err = String::new();
        // request_client_cert: false -> one-way TLS, client CA PEM ignored.
        let server_cfg =
            build_server_config(&server_cert_pem, &server_key_pem, "", "", false, &mut err)
                .expect(&format!("server config: {err}"));

        // Client verifies the server cert via ca_pem (the self-signed cert
        // is also its own CA).
        let client_opts = ConnectOptions {
            reject_unauthorized: true,
            servername: "localhost".into(),
            alpn: Vec::new(),
            ca_pem: server_cert_pem.clone(),
            cert_pem: String::new(),
            key_pem: String::new(),
        };
        let mut client_err = String::new();
        let client_cfg = build_client_config(&client_opts, &mut client_err)
            .expect(&format!("client config: {client_err}"));

        let peer_chain = run_mtls_handshake(server_cfg, move |port| async move {
            use rustls::pki_types::ServerName;
            use tokio::io::AsyncWriteExt;
            use tokio_rustls::TlsConnector;

            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("TCP connect");
            let connector = TlsConnector::from(client_cfg);
            let sn = ServerName::try_from("localhost".to_string()).expect("sn");
            let mut stream = connector.connect(sn, tcp).await.expect("client handshake");
            let _ = stream.write_all(b"hi").await;
            let _ = stream.shutdown().await;
        })
        .await
        .expect("handshake must succeed for one-way TLS");

        // Server did not request a client cert, so peer_chain is empty.
        assert!(
            peer_chain.is_empty(),
            "one-way TLS: server must not see a client cert chain"
        );
    }
}
