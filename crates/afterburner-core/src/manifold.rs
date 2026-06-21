// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `Manifold` - capability gate controlling which Node.js-style built-in
//! modules (and which parts of them) are available to a running script.
//!
//! The metaphor: the intake manifold decides what air can enter the
//! combustion chamber. By default - [`Manifold::sealed`] - nothing enters.
//! Hosts that trust their scripts open specific flaps (FS roots, env
//! allow-lists, outbound HTTP allow-lists) explicitly.
//!
//! A `Manifold` rides alongside every call via `FuelGauge`, so different
//! scripts on the same engine can have different capability profiles.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Filesystem capability. Roots are resolved via `fs::canonicalize` at
/// call time; any path escape (via `..`, symlinks, etc.) outside the
/// listed roots is rejected with `AfterburnerError::PermissionDenied`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FsAccess {
    /// No FS access. Any call into `fs.*` from a script returns
    /// `PermissionDenied`.
    #[default]
    None,
    /// Read-only access rooted at the given paths. Writes return
    /// `PermissionDenied`.
    ReadOnly(Vec<PathBuf>),
    /// Read-write access rooted at the given paths.
    ReadWrite(Vec<PathBuf>),
}

/// Outbound networking capability. Inbound listening is governed
/// separately by [`ListenAccess`] - `net` models outbound only.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NetAccess {
    /// No network access.
    #[default]
    None,
    /// Outbound HTTP/HTTPS only. `Some(list)` is a host-allow-list of
    /// regexes/globs matched against the request host; `None` is
    /// "any host."
    OutboundHttp(Option<Vec<String>>),
    /// Outbound TCP + HTTP. Same allow-list semantics.
    OutboundFull(Option<Vec<String>>),
}

/// Inbound listening capability - which ports daemon-mode servers
/// (`http.createServer().listen(port)`, the HTTP/3 listener) may bind.
/// Checked by the listen host-calls before any socket bind; a denied
/// port surfaces as `PermissionDenied`, exactly like outbound `net`
/// and `fs` denials.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ListenAccess {
    /// No inbound listening. Any `.listen(port)` returns
    /// `PermissionDenied`.
    #[default]
    None,
    /// Only the listed ports may be bound.
    Ports(Vec<u16>),
    /// Any port in the inclusive range `[lo, hi]` may be bound.
    PortRange(u16, u16),
    /// Any port. Use only for trusted scripts ([`Manifold::open`]).
    Any,
}

impl ListenAccess {
    /// Whether binding `port` is permitted under this grant.
    #[must_use]
    pub fn allows(&self, port: u16) -> bool {
        match self {
            Self::None => false,
            Self::Ports(ports) => ports.contains(&port),
            Self::PortRange(lo, hi) => (*lo..=*hi).contains(&port),
            Self::Any => true,
        }
    }
}

/// Process-environment access for `process.env` and `getenv`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EnvAccess {
    /// `process.env` is an empty object. No env vars readable.
    #[default]
    None,
    /// Only the listed keys are readable. Unknown keys return `undefined`.
    AllowList(Vec<String>),
    /// Full process environment is visible. Use only for trusted scripts.
    Full,
}

/// A full capability profile for one script execution.
///
/// Construct via [`Manifold::sealed`] (safe default) or
/// [`Manifold::open`] (trusted admin contexts), then adjust individual
/// fields.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Manifold {
    pub fs: FsAccess,
    pub net: NetAccess,
    pub crypto: bool,
    pub child_process: bool,
    pub env: EnvAccess,
    /// Whether `process.exit()` terminates the script early. When `false`,
    /// `process.exit(code)` throws instead, so the host always receives
    /// a trap-or-value result.
    pub allow_exit: bool,
    /// Per-call HTTP-request wall-clock cap, in milliseconds. `None`
    /// uses the host implementation's default (currently 30 s). Lets
    /// callers tighten the budget for SLA-strict scripts or loosen
    /// it for batch jobs.
    pub http_timeout_ms: Option<u64>,
    /// Inbound listening grant for daemon-mode servers. `#[serde(default)]`
    /// so manifolds serialized before this axis existed deserialize
    /// unchanged (absent field = `ListenAccess::None` - sealed stays
    /// sealed, never widened).
    #[serde(default)]
    pub listen: ListenAccess,
}

impl Manifold {
    /// Zero-capability manifold. Safe for untrusted code - pure-JS
    /// modules (`path`, `url`, `buffer`, …) still work; host-backed
    /// modules (`fs`, `crypto`, `http`, …) return `PermissionDenied`.
    pub const fn sealed() -> Self {
        Self {
            fs: FsAccess::None,
            net: NetAccess::None,
            crypto: false,
            child_process: false,
            env: EnvAccess::None,
            allow_exit: false,
            http_timeout_ms: None,
            listen: ListenAccess::None,
        }
    }

    /// Returns `true` when every capability axis is at its sealed (no-grant)
    /// default: `fs None`, `net None`, `crypto false`, `child_process false`,
    /// `env None`, `allow_exit false`, `listen None`, and `http_timeout_ms`
    /// is `None`. This is the exact profile the self-contained WASM flavor
    /// (`wasm32-wasip1`) targets, so `burn compile` uses this predicate to
    /// decide whether ahead-of-time compilation is applicable.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        matches!(self.fs, FsAccess::None)
            && matches!(self.net, NetAccess::None)
            && !self.crypto
            && !self.child_process
            && matches!(self.env, EnvAccess::None)
            && !self.allow_exit
            && self.http_timeout_ms.is_none()
            && matches!(self.listen, ListenAccess::None)
    }

    /// Full capabilities - every flap open. Only appropriate for
    /// admin/trusted contexts; never expose to untrusted user JS.
    pub fn open() -> Self {
        Self {
            fs: FsAccess::ReadWrite(Vec::new()),
            net: NetAccess::OutboundFull(None),
            crypto: true,
            child_process: true,
            env: EnvAccess::Full,
            allow_exit: true,
            http_timeout_ms: None,
            listen: ListenAccess::Any,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_is_the_default() {
        assert_eq!(Manifold::default(), Manifold::sealed());
    }

    #[test]
    fn is_sealed_true_for_sealed_default() {
        assert!(Manifold::sealed().is_sealed());
        assert!(Manifold::default().is_sealed());
    }

    #[test]
    fn is_sealed_false_for_open() {
        assert!(!Manifold::open().is_sealed());
    }

    #[test]
    fn is_sealed_false_for_any_single_grant() {
        let mut m = Manifold::sealed();
        m.crypto = true;
        assert!(!m.is_sealed(), "crypto grant should unseal");

        let mut m = Manifold::sealed();
        m.child_process = true;
        assert!(!m.is_sealed(), "child_process grant should unseal");

        let mut m = Manifold::sealed();
        m.allow_exit = true;
        assert!(!m.is_sealed(), "allow_exit should unseal");

        let mut m = Manifold::sealed();
        m.fs = FsAccess::ReadOnly(vec!["/tmp".into()]);
        assert!(!m.is_sealed(), "fs ReadOnly should unseal");

        let mut m = Manifold::sealed();
        m.net = NetAccess::OutboundHttp(None);
        assert!(!m.is_sealed(), "net OutboundHttp should unseal");

        let mut m = Manifold::sealed();
        m.env = EnvAccess::AllowList(vec!["HOME".into()]);
        assert!(!m.is_sealed(), "env AllowList should unseal");

        let mut m = Manifold::sealed();
        m.listen = ListenAccess::Ports(vec![8080]);
        assert!(!m.is_sealed(), "listen Ports should unseal");

        let mut m = Manifold::sealed();
        m.http_timeout_ms = Some(5000);
        assert!(!m.is_sealed(), "http_timeout_ms should unseal");
    }

    #[test]
    fn sealed_has_no_capabilities() {
        let m = Manifold::sealed();
        assert!(matches!(m.fs, FsAccess::None));
        assert!(matches!(m.net, NetAccess::None));
        assert!(!m.crypto);
        assert!(!m.child_process);
        assert!(matches!(m.env, EnvAccess::None));
        assert!(!m.allow_exit);
        assert!(matches!(m.listen, ListenAccess::None));
    }

    #[test]
    fn open_grants_everything() {
        let m = Manifold::open();
        assert!(matches!(m.fs, FsAccess::ReadWrite(_)));
        assert!(matches!(m.net, NetAccess::OutboundFull(_)));
        assert!(m.crypto);
        assert!(m.child_process);
        assert!(matches!(m.env, EnvAccess::Full));
        assert!(m.allow_exit);
        assert!(matches!(m.listen, ListenAccess::Any));
    }

    #[test]
    fn listen_allows_matches_grant_shapes() {
        assert!(!ListenAccess::None.allows(80));
        let ports = ListenAccess::Ports(vec![8080, 9090]);
        assert!(ports.allows(8080));
        assert!(ports.allows(9090));
        assert!(!ports.allows(8081));
        let range = ListenAccess::PortRange(9000, 9100);
        assert!(range.allows(9000));
        assert!(range.allows(9100));
        assert!(!range.allows(8999));
        assert!(!range.allows(9101));
        assert!(ListenAccess::Any.allows(1));
        assert!(ListenAccess::Any.allows(65535));
    }

    #[test]
    fn listen_serde_roundtrips_every_variant() {
        for v in [
            ListenAccess::None,
            ListenAccess::Ports(vec![9090]),
            ListenAccess::Ports(vec![80, 443, 8080]),
            ListenAccess::PortRange(9000, 9100),
            ListenAccess::Any,
        ] {
            let json = serde_json::to_string(&v).expect("serialize");
            let back: ListenAccess = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, back, "roundtrip drift for {json}");
        }
    }

    #[test]
    fn listen_serde_is_externally_tagged_like_the_other_axes() {
        // The wire shapes are part of the `.afb` digest contract - pin them.
        assert_eq!(
            serde_json::to_string(&ListenAccess::None).expect("ser"),
            r#""None""#
        );
        assert_eq!(
            serde_json::to_string(&ListenAccess::Ports(vec![9090])).expect("ser"),
            r#"{"Ports":[9090]}"#
        );
        assert_eq!(
            serde_json::to_string(&ListenAccess::PortRange(9000, 9100)).expect("ser"),
            r#"{"PortRange":[9000,9100]}"#
        );
        assert_eq!(
            serde_json::to_string(&ListenAccess::Any).expect("ser"),
            r#""Any""#
        );
    }

    #[test]
    fn manifold_without_listen_field_parses_as_none() {
        // Manifolds serialized before the listen axis existed must
        // deserialize unchanged: absent field = None (never widened).
        let legacy = r#"{
            "fs": "None",
            "net": "None",
            "crypto": false,
            "child_process": false,
            "env": "None",
            "allow_exit": false,
            "http_timeout_ms": null
        }"#;
        let m: Manifold = serde_json::from_str(legacy).expect("legacy manifold parses");
        assert_eq!(m, Manifold::sealed());
        assert!(matches!(m.listen, ListenAccess::None));
    }

    #[test]
    fn manifold_listen_roundtrips_through_json() {
        let mut m = Manifold::sealed();
        m.listen = ListenAccess::PortRange(18200, 18210);
        let json = serde_json::to_string(&m).expect("serialize");
        let back: Manifold = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, back);
    }
}
