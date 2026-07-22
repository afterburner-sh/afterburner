// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Regression test for the `embed-ruby` LOUD build contract: `build.rs` must
//! FAIL THE BUILD (not a `cargo:warning`) when the feature is requested and
//! it cannot fetch the stock runtime. A binary built `--features embed-ruby`
//! that silently shipped without the runtime would be a dishonest "offline
//! Ruby" promise - see `assemble_embed_ruby_if_enabled` in `build.rs`.
//! `assemble_embed_core_if_enabled` (the `embed-core` sibling) follows the
//! identical pattern one function below it and is exercised by hand in the
//! same way; only `embed-ruby` is covered here to keep this already-heavy
//! test to one nested build.
//!
//! This spawns a NESTED `cargo build -p afterburner-wasi --features
//! embed-ruby` with network isolated (a Linux network namespace - see
//! `crates/afterburner/tests/embed_offline.rs` for the identical technique)
//! and asserts the build FAILS with the actionable message named in
//! `build.rs`. `#[ignore]`d by default: a nested `cargo build` costs real
//! minutes even from a warm cache (afterburner-wasi's own artifacts are
//! deliberately cleaned first, see below), so it must not slow the default
//! `cargo test` pass. Run explicitly:
//!
//! ```text
//! cargo test -p afterburner-wasi --test embed_build_honesty -- --ignored --nocapture
//! ```
//!
//! Skips loudly (prints exactly why, does not fail the suite) when this host
//! cannot create an isolated network namespace.

use std::path::PathBuf;
use std::process::Command;

fn netns_unavailable() -> Option<String> {
    match Command::new("unshare")
        .args(["--net", "--map-root-user", "--", "true"])
        .output()
    {
        Ok(o) if o.status.success() => None,
        Ok(o) => Some(format!(
            "`unshare --net --map-root-user` exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Some(format!("`unshare` is not runnable on this host: {e}")),
    }
}

/// The workspace root (two levels up from this crate's manifest dir), so the
/// nested `cargo` invocations work regardless of the CWD `cargo test` runs
/// this test with.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
#[ignore = "spawns a nested `cargo build` (real minutes even from a warm cache); run explicitly, see module docs"]
fn embed_ruby_build_fails_loudly_without_network() {
    if let Some(reason) = netns_unavailable() {
        eprintln!(
            "[embed_build_honesty] SKIP embed_ruby_build_fails_loudly_without_network: \
             cannot isolate network on this host ({reason}); the loud-build contract is \
             UNVERIFIED by this run (not proven broken - just not checked here)."
        );
        return;
    }

    // Force build.rs to re-run its embed-ruby assembly: a warm OUT_DIR from a
    // prior successful build would short-circuit on its own completeness
    // check (correctly - see `assemble_embed_ruby_if_enabled`) and never
    // touch the network, which would make this test vacuous.
    let clean = Command::new("cargo")
        .args(["clean", "-p", "afterburner-wasi", "--release"])
        .current_dir(workspace_root())
        .output()
        .expect("spawn cargo clean");
    assert!(
        clean.status.success(),
        "cargo clean -p afterburner-wasi failed: {}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let out = Command::new("unshare")
        .args([
            "--net",
            "--map-root-user",
            "--",
            "cargo",
            "build",
            "--release",
            "-p",
        ])
        .arg("afterburner-wasi")
        .args(["--features", "embed-ruby"])
        .current_dir(workspace_root())
        .output()
        .expect("spawn unshare+cargo build");

    assert!(
        !out.status.success(),
        "a network-less embed-ruby build must FAIL, never silently succeed with a hollow embed; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("embed-ruby: could not assemble the Ruby runtime"),
        "the build failure must name the actionable reason build.rs raises; stderr={stderr}"
    );
    assert!(
        stderr.contains("requires network access at build time"),
        "the build failure must tell the operator what to fix; stderr={stderr}"
    );
}
