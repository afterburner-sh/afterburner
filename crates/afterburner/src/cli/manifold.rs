// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `--allow-*` flag translation into a [`Manifold`].
//!
//! * `--allow-all` / `-A` → `Manifold::open()` (every flap wide open).
//! * Each of `--allow-net`, `--allow-fs`, `--allow-env` grants exactly
//!   the capability it names. Absent flags stay at the `sealed()`
//!   default — `PermissionDenied` on use.
//! * `*` in the value = unrestricted for that capability. Otherwise
//!   the value is a comma-separated allow-list (hosts / paths / var
//!   names). Net entries may pin a port (`host:port`); see
//!   [`parse_allow_net_arg`].

use crate::{EnvAccess, FsAccess, Manifold, NetAccess};
use std::path::PathBuf;

use super::args::Cli;

/// Assemble the Manifold the CLI will run under, per Q1-D:
///
/// * No flags at all → `Manifold::open()` (CLI-only default — the
///   library API still defaults to `sealed`). [`banner::maybe_show`]
///   prints a one-time warning at startup.
/// * `--sandbox` or any `--allow-*` flag → start from `sealed()` and
///   apply the specific grants. Presence of `--allow-*` implicitly
///   sandboxes; you don't need to repeat `--sandbox` alongside it.
/// * `-A` / `--allow-all` → explicit `open()`; no banner (user opted
///   in).
pub fn build_manifold(cli: &Cli) -> Manifold {
    if cli.allow_all {
        return Manifold::open();
    }
    // The Permission Model flags (`--allow-fs-read` / `--allow-fs-write`
    // / `--allow-child-process` / `--allow-worker`) are first-class
    // sandbox triggers too — they imply `--sandbox` even when the
    // legacy `--allow-net` / `--allow-fs` / `--allow-env` flags are
    // absent.
    let any_allow = cli.allow_net.is_some()
        || cli.allow_fs.is_some()
        || cli.allow_env.is_some()
        || cli.allow_fs_read.is_some()
        || cli.allow_fs_write.is_some()
        || cli.allow_child_process
        || cli.allow_worker
        || cli.allow_crypto
        || cli.permission;
    let explicit_sandbox = cli.sandbox || any_allow;
    if !explicit_sandbox {
        // The CLI-flip: implicit open. Banner triggers separately in
        // `maybe_show_open_banner` when this path is taken.
        return Manifold::open();
    }
    let mut m = Manifold::sealed();

    if let Some(s) = cli.allow_net.as_deref() {
        let hosts = parse_allow_list(s);
        // Wildcard or empty list → unrestricted. We keep `OutboundFull`
        // rather than `OutboundHttp` so scripts that talk raw TCP in a
        // future host expansion don't need a migration.
        m.net = if hosts.is_empty() || has_wildcard(&hosts) {
            NetAccess::OutboundFull(None)
        } else {
            NetAccess::OutboundFull(Some(hosts))
        };
    }

    // Permission-Model flags collapse onto the existing FS gate:
    // burn doesn't model read-vs-write separately at the manifold
    // layer, so granting either implies ReadWrite on the named roots.
    // The granularity is preserved on the JS-side
    // `process.permission.has` map for libraries that introspect.
    let fs_paths: Option<Vec<String>> =
        if cli.allow_fs.is_some() || cli.allow_fs_read.is_some() || cli.allow_fs_write.is_some() {
            let mut combined: Vec<String> = Vec::new();
            for src in [
                cli.allow_fs.as_deref(),
                cli.allow_fs_read.as_deref(),
                cli.allow_fs_write.as_deref(),
            ]
            .iter()
            .flatten()
            {
                combined.extend(parse_allow_list(src));
            }
            // Deduplicate while preserving order.
            let mut seen = std::collections::BTreeSet::new();
            combined.retain(|p| seen.insert(p.clone()));
            Some(combined)
        } else {
            None
        };
    if let Some(paths) = fs_paths {
        let roots: Vec<PathBuf> = if paths.is_empty() || has_wildcard(&paths) {
            vec![PathBuf::from("/")]
        } else {
            paths.into_iter().map(PathBuf::from).collect()
        };
        m.fs = FsAccess::ReadWrite(roots);
    }

    if let Some(s) = cli.allow_env.as_deref() {
        let vars = parse_allow_list(s);
        m.env = if vars.is_empty() || has_wildcard(&vars) {
            EnvAccess::Full
        } else {
            EnvAccess::AllowList(vars)
        };
    }

    if cli.allow_crypto {
        m.crypto = true;
    }

    m
}

/// Clap value-parser for `--allow-net`: accept the comma-separated
/// host list, rejecting entries whose `:port` suffix is not a valid
/// port number. Without this gate a typo like `--allow-net
/// host:90o0` would produce an allow-list entry that can never match
/// — i.e. a silent deny-everything sandbox.
///
/// Entry grammar (shared with the runtime matcher,
/// `afterburner_node_compat::http_host::split_host_port_pattern`):
/// `host`, `host:port`, `*.suffix[:port]`, `*`, `[v6][:port]`, or a
/// bare IPv6 host (two or more colons, any port).
pub fn parse_allow_net_arg(s: &str) -> Result<String, String> {
    for entry in parse_allow_list(s) {
        // Bracketed IPv6 with a non-numeric port and `host:NaN` both
        // reduce to the same check: a declared port part must parse.
        let port_part = if let Some(v6) = entry.strip_prefix('[') {
            match v6.split_once(']') {
                Some((_, after)) => after.strip_prefix(':'),
                None => {
                    return Err(format!(
                        "invalid --allow-net entry '{entry}': unterminated '[' in IPv6 host"
                    ));
                }
            }
        } else if entry.matches(':').count() == 1 {
            entry.split_once(':').map(|(_, p)| p)
        } else {
            // No colon (bare host) or ≥2 colons (bare IPv6 host).
            None
        };
        if let Some(p) = port_part
            && p.parse::<u16>().is_err()
        {
            return Err(format!(
                "invalid --allow-net entry '{entry}': '{p}' is not a valid port \
                 (use host, host:port, *.suffix[:port], or [v6][:port])"
            ));
        }
    }
    Ok(s.to_string())
}

/// Split `"a,b, c"` into `["a", "b", "c"]`, trimming whitespace and
/// dropping empty segments. `""` returns `[]`.
pub fn parse_allow_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

pub fn has_wildcard(list: &[String]) -> bool {
    list.iter().any(|s| s == "*")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_net_accepts_hosts_and_host_port_entries() {
        for ok in [
            "api.example.com",
            "*.trusted.io",
            "*",
            "127.0.0.1:9000",
            "*.trusted.io:8443",
            "a.com,b.com:81, c.com",
            "[::1]:9000",
            "[::1]",
            "::1", // bare IPv6 host — colons are not a port suffix
        ] {
            assert!(
                parse_allow_net_arg(ok).is_ok(),
                "expected '{ok}' to be accepted"
            );
        }
    }

    #[test]
    fn allow_net_rejects_invalid_port_suffixes() {
        for bad in [
            "127.0.0.1:90o0",
            "host:",
            "host:-1",
            "host:65536",
            "good.com,host:nope",
            "[::1]:abc",
            "[::1",
        ] {
            assert!(
                parse_allow_net_arg(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }
}

/// True when the CLI is running under the implicit open-capabilities
/// default — i.e. the user supplied neither `--sandbox` nor any
/// `--allow-*` flag and didn't explicitly set `-A`. The banner shows
/// only in this case, so callers who set `-A` don't get warned twice.
pub fn is_implicit_open(cli: &Cli) -> bool {
    if cli.allow_all {
        return false;
    }
    let any_allow = cli.allow_net.is_some()
        || cli.allow_fs.is_some()
        || cli.allow_env.is_some()
        || cli.allow_fs_read.is_some()
        || cli.allow_fs_write.is_some()
        || cli.allow_child_process
        || cli.allow_worker
        || cli.allow_crypto
        || cli.permission;
    !(cli.sandbox || any_allow)
}
