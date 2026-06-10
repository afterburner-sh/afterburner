// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Outbound HTTP via `ureq`. Synchronous API — fits Afterburner's
//! single-threaded, no-event-loop execution model.
//!
//! Gated behind `Manifold::net`. Hosts outside the policy allow-list
//! (when present) are rejected before the request is even constructed.
//! Allow-list entries are `host` or `host:port` patterns (see
//! [`split_host_port_pattern`] for the full grammar): an entry
//! without a port matches that host on **any** port; an entry with a
//! port matches host **and** port exactly, where the request port is
//! the URL's explicit `:port` or the scheme default (80 for
//! `http`/schemeless, 443 for `https`).
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
    let (host, port) = extract_host_port(url).ok_or_else(|| {
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
                && !list.iter().any(|h| host_matches(&host, port, h))
            {
                return Err(AfterburnerError::PermissionDenied(format!(
                    "http.{method} {url}: {host}:{port} not in allow-list"
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

/// Extract `(host, effective_port)` from a URL.
///
/// The effective port is the explicit `:port` in the authority when
/// present, otherwise the scheme default: `https`/`wss` → 443, every
/// other (or absent) scheme → 80. IPv6 literals use the standard
/// bracket form (`https://[::1]:9000/x` → `("::1", 9000)`); the
/// returned host carries no brackets. Userinfo (`user:pass@host`) is
/// stripped. Returns `None` for an empty host or a non-numeric port.
pub fn extract_host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };
    let default_port: u16 = match scheme {
        Some(s) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") => 443,
        _ => 80,
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // Drop userinfo if present (`user:pass@host:port`).
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hp)| hp);
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return (!host.is_empty()).then(|| (host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, p)) => {
            let port = p.parse().ok()?;
            (!host.is_empty()).then(|| (host.to_string(), port))
        }
        None => (!authority.is_empty()).then(|| (authority.to_string(), default_port)),
    }
}

/// Split a net allow-list pattern into its host part and optional
/// port constraint.
///
/// Pattern grammar (shared by `--allow-net`, `Manifold::net`
/// allow-lists, and the raw TCP/TLS gates in `afterburner-wasi`):
///
/// * `host` — host match only; **any** port is allowed.
/// * `host:port` — host match **and** exact port. For HTTP the
///   request port is the URL's explicit port or the scheme default
///   (80 for `http`/schemeless, 443 for `https`/`wss`); for raw
///   TCP/TLS it is the literal connect port.
/// * `[v6]` / `[v6]:port` — IPv6 patterns use brackets; the host
///   part is compared without them. An *unbracketed* pattern
///   containing two or more colons is treated as a bare IPv6 host
///   (any port) since the port suffix would be ambiguous.
/// * A `:port` suffix that does not parse as a `u16` makes the
///   pattern match **nothing** (the CLI rejects such entries up
///   front with a clear error; library callers should validate).
pub fn split_host_port_pattern(pattern: &str) -> (&str, Option<PortPattern>) {
    if let Some(v6) = pattern.strip_prefix('[') {
        if let Some((host, after)) = v6.split_once(']') {
            return match after.strip_prefix(':') {
                Some(p) => (host, Some(PortPattern::parse(p))),
                None if after.is_empty() => (host, None),
                None => (host, Some(PortPattern::Invalid)),
            };
        }
        // Unterminated bracket — treat the raw text as a host so it
        // simply never matches a real (bracket-less) hostname.
        return (pattern, None);
    }
    if pattern.matches(':').count() >= 2 {
        // Bare IPv6 host, no port constraint expressible.
        return (pattern, None);
    }
    match pattern.rsplit_once(':') {
        Some((host, p)) => (host, Some(PortPattern::parse(p))),
        None => (pattern, None),
    }
}

/// Parsed `:port` suffix of an allow-list pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortPattern {
    /// A valid numeric port — matches exactly this port.
    Port(u16),
    /// A `:suffix` that is not a valid `u16`. Matches no port; the
    /// CLI rejects such entries at parse time.
    Invalid,
}

impl PortPattern {
    fn parse(s: &str) -> Self {
        s.parse().map_or(PortPattern::Invalid, PortPattern::Port)
    }

    /// Whether a request/connect `port` satisfies this constraint.
    pub fn matches(self, port: u16) -> bool {
        matches!(self, PortPattern::Port(p) if p == port)
    }
}

/// Case-insensitive host comparison with `*.suffix` wildcard support.
/// `*.example.com` matches `api.example.com` (and deeper) **and** the
/// apex `example.com` itself — the historical HTTP-gate semantics. `*`
/// matches every host.
pub fn host_part_matches(host: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

/// Port-aware allow-list match: `pattern` is `host` or `host:port`
/// per [`split_host_port_pattern`]; `host`/`port` are the effective
/// request target from [`extract_host_port`]. A pattern without a
/// port matches any port; a pattern with a port requires an exact
/// port match.
pub fn host_matches(host: &str, port: u16, pattern: &str) -> bool {
    let (pat_host, pat_port) = split_host_port_pattern(pattern);
    if let Some(pp) = pat_port
        && !pp.matches(port)
    {
        return false;
    }
    host_part_matches(host, pat_host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Instant;

    #[test]
    fn extract_host_port_handles_common_shapes() {
        assert_eq!(
            extract_host_port("https://api.example.com/v1/x"),
            Some(("api.example.com".to_string(), 443))
        );
        assert_eq!(
            extract_host_port("http://localhost:8080/foo"),
            Some(("localhost".to_string(), 8080))
        );
        assert_eq!(
            extract_host_port("https://x.y.z?q=1"),
            Some(("x.y.z".to_string(), 443))
        );
        // Schemeless: best-effort host, default port 80.
        assert_eq!(
            extract_host_port("not-a-url"),
            Some(("not-a-url".to_string(), 80))
        );
        // Explicit port on the default scheme.
        assert_eq!(
            extract_host_port("http://127.0.0.1:9000/api"),
            Some(("127.0.0.1".to_string(), 9000))
        );
        // IPv6 bracket form, with and without port.
        assert_eq!(
            extract_host_port("http://[::1]:9000/x"),
            Some(("::1".to_string(), 9000))
        );
        assert_eq!(
            extract_host_port("https://[::1]/x"),
            Some(("::1".to_string(), 443))
        );
        // Userinfo stripped.
        assert_eq!(
            extract_host_port("http://user:pass@host.example:81/"),
            Some(("host.example".to_string(), 81))
        );
        // Garbage port → unparseable.
        assert_eq!(extract_host_port("http://host:notaport/"), None);
        assert_eq!(extract_host_port("http:///nohost"), None);
    }

    #[test]
    fn host_matches_bare_host_any_port() {
        assert!(host_matches("exact.host", 80, "exact.host"));
        assert!(host_matches("exact.host", 8443, "exact.host"));
        assert!(host_matches("EXACT.host", 80, "exact.HOST")); // case-insensitive
        assert!(!host_matches("other.host", 80, "exact.host"));
    }

    #[test]
    fn host_matches_host_port_exact() {
        // The #13 regression spine: `--allow-net 127.0.0.1:9000` must
        // match a request to 127.0.0.1:9000 …
        assert!(host_matches("127.0.0.1", 9000, "127.0.0.1:9000"));
        // … including when the port comes from the scheme default.
        assert!(host_matches("api.example.com", 443, "api.example.com:443"));
        assert!(host_matches("api.example.com", 80, "api.example.com:80"));
    }

    #[test]
    fn host_matches_host_port_mismatch_denies() {
        assert!(!host_matches("127.0.0.1", 9001, "127.0.0.1:9000"));
        assert!(!host_matches("127.0.0.1", 80, "127.0.0.1:9000"));
        // Host mismatch with matching port still denies.
        assert!(!host_matches("127.0.0.2", 9000, "127.0.0.1:9000"));
        // Invalid port suffix matches nothing.
        assert!(!host_matches("127.0.0.1", 80, "127.0.0.1:nope"));
    }

    #[test]
    fn host_matches_handles_wildcards() {
        // Port-less wildcard: any port.
        assert!(host_matches("api.example.com", 80, "*.example.com"));
        assert!(host_matches("api.example.com", 8443, "*.example.com"));
        assert!(host_matches("example.com", 443, "*.example.com")); // apex included
        assert!(!host_matches("api.example.org", 80, "*.example.com"));
        // Wildcard + port: host wildcard, port exact.
        assert!(host_matches("api.example.com", 8443, "*.example.com:8443"));
        assert!(!host_matches("api.example.com", 443, "*.example.com:8443"));
        // `*` alone: everything.
        assert!(host_matches("anything.at.all", 1234, "*"));
    }

    #[test]
    fn host_matches_default_port_inference() {
        // https URL with no explicit port ⇒ 443 satisfies a :443 entry.
        let (h, p) = extract_host_port("https://secure.example.com/x").unwrap();
        assert!(host_matches(&h, p, "secure.example.com:443"));
        assert!(!host_matches(&h, p, "secure.example.com:80"));
        // http URL with no explicit port ⇒ 80.
        let (h, p) = extract_host_port("http://plain.example.com/x").unwrap();
        assert!(host_matches(&h, p, "plain.example.com:80"));
        assert!(!host_matches(&h, p, "plain.example.com:443"));
    }

    #[test]
    fn split_host_port_pattern_shapes() {
        assert_eq!(split_host_port_pattern("example.com"), ("example.com", None));
        assert_eq!(
            split_host_port_pattern("example.com:8080"),
            ("example.com", Some(PortPattern::Port(8080)))
        );
        assert_eq!(
            split_host_port_pattern("example.com:bad"),
            ("example.com", Some(PortPattern::Invalid))
        );
        // Bare IPv6 (≥2 colons, unbracketed): host only, any port.
        assert_eq!(split_host_port_pattern("::1"), ("::1", None));
        assert_eq!(
            split_host_port_pattern("[::1]:9000"),
            ("::1", Some(PortPattern::Port(9000)))
        );
        assert_eq!(split_host_port_pattern("[::1]"), ("::1", None));
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
