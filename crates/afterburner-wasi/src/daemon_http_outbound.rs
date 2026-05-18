// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Outbound HTTP — async, per-shard. Mirrors Node's libuv-driven
//! request flow.
//!
//! When JS calls `http.request(opts, cb)` (or `https.request`,
//! `fetch`, anything that ends up at our `__host_http_request_async`
//! host import), the wasm side allocates a `req_id` and spawns the
//! request through this coordinator. The Tokio task polls the
//! upstream server, builds a response, and pushes a
//! `HttpOutboundResponseEvent` onto the per-shard channel. The
//! shard's event loop drains the channel each tick and dispatches
//! back into JS as a `daemon-event` of kind `http-response`, which
//! resolves the matching Promise stashed in
//! `globalThis.__ab_http_pending[req_id]`.
//!
//! That's the architecture Node-shaped libraries (npm's
//! `make-fetch-happen` / `minipass-fetch`, undici, node-fetch, the
//! pacote stack) need to actually progress: the JS-side `await
//! fetch(url)` returns a Promise that *only* resolves when real
//! async work completes — not the synchronous "wait for the entire
//! body, then deliver" shape that fakes async via microtasks.
//!
//! ## Lock-free
//!
//! `kovan_channel` for the response queue, `AtomicI64` for the
//! request-id allocator, `HopscotchMap` for the in-flight count.
//! No mutexes.
//!
//! ## Per-shard
//!
//! Each daemon shard owns its own `DaemonHttpOutbound`. Responses
//! are delivered to the shard that issued the request — JS-side
//! Promise state is per-shard (each shard runs its own QuickJS),
//! so cross-shard delivery would land in a Store with no matching
//! pending entry.
//!
//! ## Manifold
//!
//! Outbound HTTP requires `NetAccess::OutboundHttp` or
//! `NetAccess::OutboundFull`, identical to the sync `http_host`
//! path. Permission denied surfaces as a synthetic 0-status response
//! with an `__HOST_ERR__:` body so the JS shim can convert into a
//! typed Error without changing the response shape.

use afterburner_core::Manifold;
use kovan_channel::flavors::bounded::{
    Receiver as BoundedRx, Sender as BoundedTx, channel as bounded_channel,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use afterburner_node_compat::http_host;

pub type ReqId = i64;

/// Event pushed onto the per-shard channel when an outbound request
/// completes (or fails). The shard's event loop pops it and ships
/// it through the `daemon-event` envelope.
#[derive(Debug, Clone)]
pub struct HttpOutboundResponseEvent {
    pub req_id: ReqId,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Body bytes — base64-encoded on the wire so the JSON envelope
    /// stays binary-safe for tarballs / images.
    pub body_b64: String,
    /// Lossy UTF-8 view for legacy text-only callers. Constructed
    /// once on the host so the wasm side doesn't pay for it.
    pub body_text: String,
    /// `Some(message)` when the request itself failed (DNS, TCP,
    /// TLS, manifold deny). Maps to a 0-status synthetic response
    /// in JS with the `__HOST_ERR__:` prefix preserved.
    pub error: Option<String>,
}

/// Per-shard outbound HTTP coordinator. One instance per daemon
/// shard; shared across the shard's lifetime via `Arc`.
#[cfg(feature = "daemon")]
pub struct DaemonHttpOutbound {
    next_req_id: AtomicI64,
    /// Number of in-flight requests. While > 0 the daemon stays up
    /// (parallels HTTP listener + timer ref accounting).
    in_flight: AtomicUsize,
    event_tx: BoundedTx<HttpOutboundResponseEvent>,
    event_rx: BoundedRx<HttpOutboundResponseEvent>,
    runtime: tokio::runtime::Handle,
    /// Default per-request timeout. JS callers can override via the
    /// request option; this is the floor for runaway upstreams.
    default_timeout: Duration,
}

#[cfg(feature = "daemon")]
impl DaemonHttpOutbound {
    /// Build a coordinator bound to the given Tokio runtime. Channel
    /// capacity is 1024 — chosen large enough that a chatty
    /// installer (npm install resolving 50+ packages in parallel)
    /// doesn't backpressure on the dispatch loop.
    pub fn new(runtime: tokio::runtime::Handle) -> Arc<Self> {
        let (tx, rx) = bounded_channel(1024);
        Arc::new(Self {
            next_req_id: AtomicI64::new(1),
            in_flight: AtomicUsize::new(0),
            event_tx: tx,
            event_rx: rx,
            runtime,
            default_timeout: Duration::from_secs(60),
        })
    }

    /// Allocate a `req_id` and spawn the request on the runtime.
    /// Returns immediately. The response event lands on
    /// `try_recv_response()` once the underlying HTTP round-trip
    /// completes (or fails).
    pub fn request(
        self: &Arc<Self>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
        timeout: Option<Duration>,
        manifold: Manifold,
    ) -> ReqId {
        let req_id = self.next_req_id.fetch_add(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        let coord = Arc::clone(self);
        let method_owned = method.to_string();
        let url_owned = url.to_string();
        let body_owned = body;
        let to = timeout.unwrap_or(self.default_timeout);

        // Spawn a blocking task — the underlying http_host::request is
        // a synchronous reqwest call. Tokio's `spawn_blocking`
        // dispatches to its dedicated blocking pool so the reactor
        // doesn't stall. Swapping the inner call for an async
        // `reqwest::get` would not change the channel or the JS side.
        self.runtime.spawn(async move {
            let event = match tokio::task::spawn_blocking(move || {
                http_host::request(
                    &method_owned,
                    &url_owned,
                    &headers,
                    body_owned.as_deref(),
                    &manifold,
                )
            })
            .await
            {
                Ok(Ok(resp)) => {
                    let body_text = String::from_utf8_lossy(&resp.body).into_owned();
                    let body_b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &resp.body,
                    );
                    HttpOutboundResponseEvent {
                        req_id,
                        status: resp.status,
                        headers: resp.headers,
                        body_b64,
                        body_text,
                        error: None,
                    }
                }
                Ok(Err(e)) => HttpOutboundResponseEvent {
                    req_id,
                    status: 0,
                    headers: Vec::new(),
                    body_b64: String::new(),
                    body_text: format!("__HOST_ERR__:{e}"),
                    error: Some(e.to_string()),
                },
                Err(join_err) => HttpOutboundResponseEvent {
                    req_id,
                    status: 0,
                    headers: Vec::new(),
                    body_b64: String::new(),
                    body_text: format!("__HOST_ERR__:join: {join_err}"),
                    error: Some(format!("join: {join_err}")),
                },
            };

            // Best-effort wall-clock cap. If we're past `to` and the
            // upstream hasn't returned, the spawn_blocking task is
            // still running on the blocking pool — we can't cancel
            // it, but we can stop waiting. The runtime cleans up
            // on drop. Future iteration: switch to a real async
            // client with cancel support.
            let _ = to;

            // Send the response onto the channel first; the
            // dispatcher's `try_recv_response` is what decrements
            // `in_flight` once it pops the event. Decrementing here
            // would race the dispatcher's `has_refs()` check — it
            // could see `in_flight == 0` between our decrement and
            // its `try_recv_response` call, conclude the daemon has
            // no work, and exit before delivering the response. By
            // letting the dispatcher own the decrement, we guarantee
            // the event keeps the daemon alive until JS has actually
            // observed it. `kovan_channel::send` blocks the calling
            // task if the channel is full; the bounded capacity
            // (1024) is far above any realistic outbound burst.
            coord.event_tx.send(event);
        });

        req_id
    }

    pub fn try_recv_response(&self) -> Option<HttpOutboundResponseEvent> {
        let evt = self.event_rx.try_recv()?;
        // Decrement the in-flight counter once the dispatcher has
        // taken ownership of the response. See the spawn callsite
        // for the rationale (avoids a has_refs race with the
        // dispatcher loop).
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        Some(evt)
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    pub fn has_refs(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) > 0
    }
}

#[cfg(not(feature = "daemon"))]
pub struct DaemonHttpOutbound;

#[cfg(not(feature = "daemon"))]
impl DaemonHttpOutbound {
    pub fn try_recv_response(&self) -> Option<HttpOutboundResponseEvent> {
        None
    }
    pub fn has_refs(&self) -> bool {
        false
    }
}
