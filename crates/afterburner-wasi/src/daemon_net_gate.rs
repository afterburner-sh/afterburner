// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Shared outbound-network gate used by every transport coordinator.
//!
//! `net_outbound_allowed` was previously duplicated in `daemon_net.rs` and
//! `daemon_tls.rs`. This module is the one canonical copy; every coordinator
//! that needs to gate egress calls it here so they all enforce the same policy.
//!
//! `host_allowed` is also shared: the `host:port` allow-list pattern grammar
//! (wildcards, port constraints) is identical across TCP, TLS, and the Python
//! socket syscall layer.

use afterburner_core::{Manifold, NetAccess};

/// Whether `host:port` is permitted by the manifold's outbound net policy.
///
/// `OutboundHttp` is HTTP-only by design; raw TCP (and TLS over TCP) must
/// use `OutboundFull` with an optional host allow-list. Callers that only
/// need HTTP-level gating (the HTTP outbound coordinator) have their own
/// check; this function is for the transport-level check.
#[must_use]
pub fn net_outbound_allowed(m: &Manifold, host: &str, port: u16) -> bool {
    match &m.net {
        NetAccess::None => false,
        NetAccess::OutboundHttp(_) => false,
        NetAccess::OutboundFull(None) => true,
        NetAccess::OutboundFull(Some(allow)) => host_allowed(host, port, allow),
    }
}

/// Whether `host:port` matches any entry in `allow`.
///
/// Allow-list entries may be:
/// - `"*"` - any host.
/// - `"*.suffix"` - any host ending with `.suffix` (e.g. `*.example.com`).
/// - `"hostname"` - exact match (case-insensitive).
/// - `"hostname:port"` - exact match with port constraint.
/// - `"*:port"` or `"*.suffix:port"` - wildcard host with port constraint.
///
/// An empty allow list means "any host" (the caller used `OutboundFull(None)`
/// for that case; this arm is reached only via `OutboundFull(Some(vec![]))`
/// which is a user who explicitly passed an empty list - treated as
/// "any" to avoid a hard-to-diagnose silent block on a misconfigured allow-list).
#[must_use]
pub fn host_allowed(host: &str, port: u16, allow: &[String]) -> bool {
    if allow.is_empty() {
        return true;
    }
    let host_lc = host.to_ascii_lowercase();
    allow.iter().any(|pat| {
        // `host:port` entries constrain the port; port-less entries match any
        // port. The split grammar is shared with the HTTP gate so
        // `--allow-net 127.0.0.1:9000` means the same thing for fetch and
        // net.connect.
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
            // `*.example.com` matches `api.example.com` (and deeper) but not
            // `example.com` itself.
            return host_lc.ends_with(&format!(".{suffix}"));
        }
        p == host_lc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::{Manifold, NetAccess};

    #[test]
    fn sealed_denies_all() {
        let m = Manifold::sealed();
        assert!(!net_outbound_allowed(&m, "example.com", 80));
    }

    #[test]
    fn outbound_http_denies_raw_tcp() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundHttp(None);
        assert!(!net_outbound_allowed(&m, "example.com", 80));
    }

    #[test]
    fn outbound_full_no_allowlist_permits_any() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(None);
        assert!(net_outbound_allowed(&m, "example.com", 443));
    }

    #[test]
    fn allowlist_wildcard_permits() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["*.example.com".into()]));
        assert!(net_outbound_allowed(&m, "api.example.com", 443));
        assert!(!net_outbound_allowed(&m, "example.com", 443));
        assert!(!net_outbound_allowed(&m, "other.com", 443));
    }

    #[test]
    fn allowlist_exact_host_port() {
        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundFull(Some(vec!["api.example.com:443".into()]));
        assert!(net_outbound_allowed(&m, "api.example.com", 443));
        assert!(!net_outbound_allowed(&m, "api.example.com", 80));
    }
}
