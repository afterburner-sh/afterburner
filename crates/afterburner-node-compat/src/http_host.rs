// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Outbound HTTP via `ureq`. Synchronous API — fits Afterburner's
//! single-threaded, no-event-loop execution model.
//!
//! Gated behind `Manifold::net`. Hosts outside the policy allow-list
//! (when present) are rejected before the request is even constructed.
//!
//! ### Per-call timeouts (configurable)
//!
//! Every call has a wall-clock deadline applied via `ureq::Request::timeout`.
//! The default is 30 s (`DEFAULT_HTTP_REQUEST_TIMEOUT`); callers can
//! override per-script via `Manifold::http_timeout_ms` so SLA-strict
//! scripts can tighten the budget and batch jobs can loosen it.
//!
//! This is the only thing between a slow upstream and a thrust hanging
//! beyond its `FuelGauge::timeout_ms` while host I/O blocks.

use afterburner_core::{AfterburnerError, Manifold, NetAccess, Result};
use std::time::Duration;

/// Default per-request wall-clock cap when `Manifold::http_timeout_ms`
/// is `None`.
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    m: &Manifold,
) -> Result<HttpResponse> {
    let host = extract_host(url).ok_or_else(|| {
        AfterburnerError::Host(format!("http.request: cannot parse host from {url}"))
    })?;

    match &m.net {
        NetAccess::None => {
            return Err(AfterburnerError::PermissionDenied(format!(
                "http.{method} {url}"
            )));
        }
        NetAccess::OutboundHttp(allow) | NetAccess::OutboundFull(allow) => {
            if let Some(list) = allow
                && !list.iter().any(|h| host_matches(&host, h))
            {
                return Err(AfterburnerError::PermissionDenied(format!(
                    "http.{method} {url}: host not in allow-list"
                )));
            }
        }
    }

    let timeout = m
        .http_timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_HTTP_REQUEST_TIMEOUT);
    let mut req = ureq::request(method, url).timeout(timeout);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let resp = match body {
        Some(b) => req.send_bytes(b),
        None => req.call(),
    };
    match resp {
        Ok(r) => {
            let status = r.status();
            let hdrs: Vec<(String, String)> = r
                .headers_names()
                .into_iter()
                .filter_map(|n| r.header(&n).map(|v| (n.clone(), v.to_string())))
                .collect();
            let mut buf = Vec::new();
            r.into_reader()
                .read_to_end(&mut buf)
                .map_err(|e| AfterburnerError::Host(format!("http read: {e}")))?;
            Ok(HttpResponse {
                status,
                headers: hdrs,
                body: buf,
            })
        }
        Err(ureq::Error::Status(code, r)) => {
            let mut buf = Vec::new();
            let _ = r.into_reader().read_to_end(&mut buf);
            Ok(HttpResponse {
                status: code,
                headers: Vec::new(),
                body: buf,
            })
        }
        Err(e) => Err(AfterburnerError::Host(format!("http: {e}"))),
    }
}

fn extract_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host_end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn host_matches(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Instant;

    #[test]
    fn extract_host_handles_common_shapes() {
        assert_eq!(
            extract_host("https://api.example.com/v1/x").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(
            extract_host("http://localhost:8080/foo").as_deref(),
            Some("localhost")
        );
        assert_eq!(extract_host("https://x.y.z?q=1").as_deref(), Some("x.y.z"));
        assert!(extract_host("not-a-url").is_some()); // best-effort
    }

    #[test]
    fn host_matches_handles_wildcards() {
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("example.com", "*.example.com"));
        assert!(!host_matches("api.example.org", "*.example.com"));
        assert!(host_matches("exact.host", "exact.host"));
    }

    #[test]
    fn http_timeout_ms_overrides_default() {
        // P4 gate: the per-call HTTP timeout knob on Manifold actually
        // wires through to ureq. We verify by:
        // 1. Spinning up a TCP listener that accepts but never responds.
        // 2. Requesting it with a 250ms Manifold-supplied timeout.
        // 3. Asserting the call returns Err in well under the default
        //    30s and within ~1.5s of the configured cap.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
        let port = listener.local_addr().unwrap().port();
        // Background acceptor that holds the connection open.
        // Detached: we don't join — the listener drops with the test.
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                let _ = stream; // hold open
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        });

        let mut m = Manifold::open();
        m.http_timeout_ms = Some(250);

        let url = format!("http://127.0.0.1:{port}/probe");
        let t0 = Instant::now();
        let result = request("GET", &url, &[], None, &m);
        let elapsed = t0.elapsed();

        assert!(
            result.is_err(),
            "expected timeout error, got Ok({result:?})"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "timeout fired late ({elapsed:?}) — Manifold knob not respected"
        );
    }
}
