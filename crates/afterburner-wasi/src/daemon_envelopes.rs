// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Daemon-event-to-JSON-envelope converters, shared between the
//! single-runtime CLI loop and the multi-shard pool. Every kind of
//! daemon event the host can produce — HTTP request, worker
//! lifecycle, raw-TCP connection, TLS connection, UDP datagram —
//! gets translated into the `{kind: "...", ...}` shape the JS-side
//! `__ab_*` dispatchers expect.
//!
//! Lifted out of `cli/daemon.rs` (where it grew up) so the shard
//! pool's per-shard event loops can use the same converters without
//! a `cli`-crate dependency. cli/daemon.rs re-uses these from here.

use crate::daemon_http::DaemonEvent;
use crate::daemon_workers::WorkerEvent;
use std::collections::BTreeMap;

#[cfg(feature = "daemon")]
use crate::daemon_dgram::DgramEvent;
#[cfg(feature = "daemon")]
use crate::daemon_http_outbound::HttpOutboundResponseEvent;
#[cfg(feature = "daemon")]
use crate::daemon_net::NetEvent;
#[cfg(feature = "daemon")]
use crate::daemon_tls::TlsEvent;

/// Outbound HTTP response → daemon-event envelope. Carries the
/// originating `req_id` so the JS dispatcher can resolve the
/// matching `globalThis.__ab_http_pending[req_id]` Promise. Body
/// rides as base64 for binary safety (npm tarballs / image data
/// would corrupt through JSON's UTF-8 string slot otherwise) plus
/// a lossy text mirror for legacy JSON-only callers.
#[cfg(feature = "daemon")]
pub fn http_outbound_response_to_envelope(event: &HttpOutboundResponseEvent) -> serde_json::Value {
    let mut headers = serde_json::Map::new();
    for (k, v) in &event.headers {
        headers.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    serde_json::json!({
        "kind": "http-response",
        "req_id": event.req_id,
        "status": event.status,
        "headers": serde_json::Value::Object(headers),
        "body": event.body_text,
        "body_b64": event.body_b64,
        "error": event.error.as_deref().unwrap_or(""),
    })
}

/// HTTP request → daemon-event envelope. The body is utf8-decoded
/// (lossy) on the way in; binary bodies should base64-encode.
pub fn http_event_to_envelope(event: &DaemonEvent) -> serde_json::Value {
    serde_json::json!({
        "kind": "http-request",
        "server_id": event.server_id,
        "req_id": event.req_id,
        "req": {
            "method": event.method,
            "url": event.url,
            "headers": event.headers.iter().cloned().collect::<BTreeMap<_, _>>(),
            "body": String::from_utf8_lossy(&event.body).into_owned(),
        }
    })
}

/// Worker lifecycle → envelope. Returns the envelope plus the
/// `worker_id` the caller should reap (only `Some` for `Exit` —
/// the terminal lifecycle event).
pub fn worker_event_to_envelope(evt: &WorkerEvent) -> (serde_json::Value, Option<i32>) {
    match evt {
        WorkerEvent::Online { worker_id } => (
            serde_json::json!({"kind": "worker-online", "worker_id": worker_id}),
            None,
        ),
        WorkerEvent::Message { worker_id, payload } => (
            serde_json::json!({
                "kind": "worker-message",
                "worker_id": worker_id,
                "payload": payload,
            }),
            None,
        ),
        WorkerEvent::Error {
            worker_id,
            message,
            stack,
        } => (
            serde_json::json!({
                "kind": "worker-error",
                "worker_id": worker_id,
                "message": message,
                "stack": stack,
            }),
            None,
        ),
        WorkerEvent::Exit { worker_id, code } => (
            serde_json::json!({
                "kind": "worker-exit",
                "worker_id": worker_id,
                "code": code,
            }),
            Some(*worker_id),
        ),
        // Child-side events; never observed in parent's drain.
        WorkerEvent::ParentMessage { payload } => (
            serde_json::json!({
                "kind": "worker-parent-message",
                "payload": payload,
            }),
            None,
        ),
        WorkerEvent::TerminateRequested => (
            serde_json::json!({"kind": "worker-terminate-requested"}),
            None,
        ),
    }
}

/// Inspector / CDP event → JS envelope. The session lifecycle events
/// (`SessionOpened`, `SessionClosed`) flow as `inspector-session-*`
/// envelopes so the JS side can clean up per-session state when a
/// WebSocket disconnects mid-stream. CDP frames themselves come in
/// as `inspector-cmd` with `id`, `method`, `params` parsed from the
/// JSON-RPC payload — invalid frames are dropped on the host side.
#[cfg(feature = "daemon")]
pub fn inspector_event_to_envelope(
    evt: &crate::daemon_inspector::InspectorEvent,
) -> Option<serde_json::Value> {
    use crate::daemon_inspector::InspectorEventKind;
    match &evt.kind {
        InspectorEventKind::SessionOpened => Some(serde_json::json!({
            "kind": "inspector-session-opened",
            "session_id": evt.session_id,
        })),
        InspectorEventKind::SessionClosed => Some(serde_json::json!({
            "kind": "inspector-session-closed",
            "session_id": evt.session_id,
        })),
        InspectorEventKind::Message(payload) => {
            let v: serde_json::Value = serde_json::from_str(payload).ok()?;
            let id = v.get("id").and_then(|x| x.as_i64()).unwrap_or(0);
            let method = v.get("method").and_then(|x| x.as_str())?.to_string();
            let params = v.get("params").cloned().unwrap_or(serde_json::json!({}));
            Some(serde_json::json!({
                "kind": "inspector-cmd",
                "session_id": evt.session_id,
                "id": id,
                "method": method,
                "params": params,
            }))
        }
    }
}

/// Raw-TCP `net` event → envelope. The `Some(conn_id)` second tuple
/// is the conn_id to mark closed after JS has seen the event (only
/// `Close`, the terminal lifecycle event).
#[cfg(feature = "daemon")]
pub fn net_event_to_envelope(evt: &NetEvent) -> (serde_json::Value, Option<i32>) {
    match evt {
        NetEvent::Connect {
            conn_id,
            local,
            remote,
        } => (
            serde_json::json!({
                "kind": "net-connect",
                "conn_id": conn_id,
                "local": addr_json(local),
                "remote": addr_json(remote),
            }),
            None,
        ),
        NetEvent::Connection {
            server_id,
            conn_id,
            local,
            remote,
        } => (
            serde_json::json!({
                "kind": "net-connection",
                "server_id": server_id,
                "conn_id": conn_id,
                "local": addr_json(local),
                "remote": addr_json(remote),
            }),
            None,
        ),
        NetEvent::Data {
            conn_id,
            payload_b64,
        } => (
            serde_json::json!({
                "kind": "net-data",
                "conn_id": conn_id,
                "payload_b64": payload_b64,
            }),
            None,
        ),
        NetEvent::End { conn_id } => (
            serde_json::json!({"kind": "net-end", "conn_id": conn_id}),
            None,
        ),
        NetEvent::Drain { conn_id } => (
            serde_json::json!({"kind": "net-drain", "conn_id": conn_id}),
            None,
        ),
        NetEvent::Close { conn_id, had_error } => (
            serde_json::json!({
                "kind": "net-close",
                "conn_id": conn_id,
                "had_error": had_error,
            }),
            Some(*conn_id),
        ),
        NetEvent::Error {
            conn_id,
            message,
            code,
        } => (
            serde_json::json!({
                "kind": "net-error",
                "conn_id": conn_id,
                "message": message,
                "code": code,
            }),
            None,
        ),
        NetEvent::Listening { server_id, port } => (
            serde_json::json!({
                "kind": "net-listening",
                "server_id": server_id,
                "port": port,
            }),
            None,
        ),
        NetEvent::ServerError { server_id, message } => (
            serde_json::json!({
                "kind": "net-server-error",
                "server_id": server_id,
                "message": message,
            }),
            None,
        ),
    }
}

/// TLS event → envelope. Same shape as `net_event_to_envelope` plus
/// the TLS-specific fields (`alpn_protocol`, `protocol`,
/// `authorized`, `cipher`, peer cert chain).
#[cfg(feature = "daemon")]
pub fn tls_event_to_envelope(evt: &TlsEvent) -> (serde_json::Value, Option<i32>) {
    match evt {
        TlsEvent::Connect {
            conn_id,
            local,
            remote,
            alpn_protocol,
            protocol,
            authorized,
            cipher,
            peer_cert_chain_der,
        } => (
            serde_json::json!({
                "kind": "tls-connect",
                "conn_id": conn_id,
                "local": addr_json(local),
                "remote": addr_json(remote),
                "alpn_protocol": alpn_protocol,
                "protocol": protocol,
                "authorized": authorized,
                "cipher": cipher,
                "peer_cert_chain_der_b64": cert_chain_to_b64(peer_cert_chain_der),
            }),
            None,
        ),
        TlsEvent::Connection {
            server_id,
            conn_id,
            local,
            remote,
            alpn_protocol,
            protocol,
            cipher,
            peer_cert_chain_der,
        } => (
            serde_json::json!({
                "kind": "tls-connection",
                "server_id": server_id,
                "conn_id": conn_id,
                "local": addr_json(local),
                "remote": addr_json(remote),
                "alpn_protocol": alpn_protocol,
                "protocol": protocol,
                "cipher": cipher,
                "peer_cert_chain_der_b64": cert_chain_to_b64(peer_cert_chain_der),
            }),
            None,
        ),
        TlsEvent::Data {
            conn_id,
            payload_b64,
        } => (
            serde_json::json!({
                "kind": "tls-data",
                "conn_id": conn_id,
                "payload_b64": payload_b64,
            }),
            None,
        ),
        TlsEvent::End { conn_id } => (
            serde_json::json!({"kind": "tls-end", "conn_id": conn_id}),
            None,
        ),
        TlsEvent::Drain { conn_id } => (
            serde_json::json!({"kind": "tls-drain", "conn_id": conn_id}),
            None,
        ),
        TlsEvent::Close { conn_id, had_error } => (
            serde_json::json!({
                "kind": "tls-close",
                "conn_id": conn_id,
                "had_error": had_error,
            }),
            Some(*conn_id),
        ),
        TlsEvent::Error {
            conn_id,
            message,
            code,
        } => (
            serde_json::json!({
                "kind": "tls-error",
                "conn_id": conn_id,
                "message": message,
                "code": code,
            }),
            None,
        ),
        TlsEvent::Listening { server_id, port } => (
            serde_json::json!({
                "kind": "tls-listening",
                "server_id": server_id,
                "port": port,
            }),
            None,
        ),
        TlsEvent::ServerError { server_id, message } => (
            serde_json::json!({
                "kind": "tls-server-error",
                "server_id": server_id,
                "message": message,
            }),
            None,
        ),
    }
}

/// UDP datagram event → envelope.
#[cfg(feature = "daemon")]
pub fn dgram_event_to_envelope(evt: &DgramEvent) -> serde_json::Value {
    match evt {
        DgramEvent::Listening { socket_id, port } => serde_json::json!({
            "kind": "dgram-listening",
            "socketId": socket_id,
            "port": port,
        }),
        DgramEvent::Message {
            socket_id,
            from,
            payload_b64,
        } => {
            let family = if from.is_ipv4() { "IPv4" } else { "IPv6" };
            serde_json::json!({
                "kind": "dgram-message",
                "socketId": socket_id,
                "payload": payload_b64,
                "from": {
                    "address": from.ip().to_string(),
                    "port": from.port(),
                    "family": family,
                },
            })
        }
        DgramEvent::Error {
            socket_id,
            message,
            code,
        } => serde_json::json!({
            "kind": "dgram-error",
            "socketId": socket_id,
            "message": message,
            "code": code,
        }),
        DgramEvent::Close { socket_id } => serde_json::json!({
            "kind": "dgram-close",
            "socketId": socket_id,
        }),
    }
}

/// Format an `Option<SocketAddr>` as the JSON object the `net.Socket`
/// polyfill expects (`{address, family, port}` or `null`).
#[cfg(feature = "daemon")]
fn addr_json(addr: &Option<std::net::SocketAddr>) -> serde_json::Value {
    match addr {
        Some(a) => {
            let family = if a.is_ipv4() { "IPv4" } else { "IPv6" };
            serde_json::json!({
                "address": a.ip().to_string(),
                "family": family,
                "port": a.port(),
            })
        }
        None => serde_json::Value::Null,
    }
}

/// Encode a TLS peer-cert chain (each entry DER-encoded) as a JSON
/// array of base64 strings. The polyfill parses out subject /
/// fingerprint / etc to back `socket.getPeerCertificate()`.
#[cfg(feature = "daemon")]
fn cert_chain_to_b64(chain: &[Vec<u8>]) -> serde_json::Value {
    use base64::Engine as _;
    let arr: Vec<serde_json::Value> = chain
        .iter()
        .map(|der| serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(der)))
        .collect();
    serde_json::Value::Array(arr)
}
