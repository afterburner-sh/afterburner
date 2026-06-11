// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `Manifold` ↔ `burn` CLI-flag round-trip.
//!
//! Used by the worker-spawn path: when a parent script calls
//! `new Worker('./child.js')`, the host serializes the *current
//! runtime* `Manifold` into `--allow-*` / `--sandbox` flags and prepends
//! them to the child `burn` invocation. The child's clap parser feeds
//! the same flags back through `cli::manifold::build_manifold`,
//! producing a `Manifold` that's `==` to the parent's.
//!
//! **Security invariant**: this codec must never *widen* capabilities.
//! Unknown / unsupported manifold shapes downgrade to `--sandbox`
//! rather than fall through to "no flag → CLI default open." The
//! round-trip test in `tests/b10_security.rs` is the guardrail.
//!
//! The codec doesn't encode `crypto`, `child_process`, `allow_exit`,
//! or `http_timeout_ms` — those have no CLI surface today (the CLI
//! always sets them via `Manifold::open()` / `sealed()`). When a
//! child needs a manifold whose narrow caps aren't expressible in
//! flags (e.g. `crypto: true` but `fs: None`), the codec returns the
//! tightest expressible flags and the child gets a slightly *narrower*
//! manifold. Narrowing is safe; widening is not.

use afterburner_core::{EnvAccess, FsAccess, ListenAccess, Manifold, NetAccess};

/// Render `m` as `burn` CLI flags. The argument order is stable across
/// calls (handy for tests). An empty result means "fully open" — the
/// CLI's implicit-open default applies (matching `Manifold::open()`).
///
/// * `Manifold::open()` → `[]` (CLI's default-open posture).
/// * Anything else → `--sandbox` plus zero or more `--allow-*` flags.
pub fn manifold_to_cli_args(m: &Manifold) -> Vec<String> {
    if is_open(m) {
        return Vec::new();
    }
    let mut out = vec!["--sandbox".to_string()];
    if let Some(s) = encode_fs(&m.fs) {
        out.push(format!("--allow-fs={s}"));
    }
    if let Some(s) = encode_net(&m.net) {
        out.push(format!("--allow-net={s}"));
    }
    if let Some(s) = encode_env(&m.env) {
        out.push(format!("--allow-env={s}"));
    }
    if let Some(s) = encode_listen(&m.listen) {
        out.push(format!("--allow-listen={s}"));
    }
    out
}

/// `Manifold::open()` shape. The CLI translates "no flags at all" into
/// open, so this is the only case where we emit zero flags. Anything
/// else uses `--sandbox` as the base and grants explicitly.
fn is_open(m: &Manifold) -> bool {
    matches!(&m.fs, FsAccess::ReadWrite(roots) if roots.is_empty())
        && matches!(&m.net, NetAccess::OutboundFull(None))
        && matches!(&m.env, EnvAccess::Full)
        && matches!(&m.listen, ListenAccess::Any)
}

fn encode_fs(fs: &FsAccess) -> Option<String> {
    match fs {
        FsAccess::None => None,
        // `--allow-fs` only models ReadWrite today; ReadOnly downgrades to
        // a narrower ReadWrite-rooted-at-... and we accept that. Worth
        // noting for future flag expansion.
        FsAccess::ReadOnly(roots) | FsAccess::ReadWrite(roots) => {
            if roots.is_empty() {
                // ReadWrite-everywhere — CLI grammar is `--allow-fs=*`.
                Some("*".to_string())
            } else {
                Some(join_paths(roots))
            }
        }
    }
}

fn encode_net(net: &NetAccess) -> Option<String> {
    match net {
        NetAccess::None => None,
        NetAccess::OutboundHttp(None) | NetAccess::OutboundFull(None) => Some("*".to_string()),
        NetAccess::OutboundHttp(Some(hosts)) | NetAccess::OutboundFull(Some(hosts)) => {
            if hosts.is_empty() {
                Some("*".to_string())
            } else {
                Some(hosts.join(","))
            }
        }
    }
}

fn encode_env(env: &EnvAccess) -> Option<String> {
    match env {
        EnvAccess::None => None,
        EnvAccess::Full => Some("*".to_string()),
        EnvAccess::AllowList(keys) => {
            if keys.is_empty() {
                None
            } else {
                Some(keys.join(","))
            }
        }
    }
}

fn encode_listen(listen: &ListenAccess) -> Option<String> {
    match listen {
        ListenAccess::None => None,
        ListenAccess::Any => Some("*".to_string()),
        ListenAccess::Ports(ports) => {
            if ports.is_empty() {
                // An empty allow-list grants nothing — same as None.
                None
            } else {
                Some(
                    ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                )
            }
        }
        ListenAccess::PortRange(lo, hi) => Some(format!("{lo}-{hi}")),
    }
}

fn join_paths(roots: &[std::path::PathBuf]) -> String {
    let mut s = String::new();
    for (i, p) in roots.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&p.to_string_lossy());
    }
    s
}
