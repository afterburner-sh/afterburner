// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B0 phase gate: the CLI-vs-library defaults contract
//! (Q1-D sandbox-default, Q2-A no-auto-daemon in library).
//!
//! Ensures that the CLI's `Manifold::open()` flip doesn't silently
//! leak into `Afterburner::builder()`, and that the library's UDF
//! envelope path (`register` + `run`) remains the supported shape for
//! programmatic callers.

#![cfg(feature = "bin")]

use afterburner::{Afterburner, EnvAccess, FsAccess, NetAccess};
use serde_json::json;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

#[test]
fn library_default_manifold_is_sealed() {
    // Library API defaults must NOT inherit the CLI's open flip.
    let defaults = Afterburner::new().expect("build").default_limits().clone();
    assert!(matches!(defaults.manifold.fs, FsAccess::None));
    assert!(matches!(defaults.manifold.net, NetAccess::None));
    assert!(matches!(defaults.manifold.env, EnvAccess::None));
}

#[test]
fn library_udf_envelope_still_works() {
    // Library's `register` + `run` path — the UDF envelope — is the
    // long-standing shape for programmatic callers. B0's script-mode
    // addition must not regress it.
    let ab = Afterburner::new().expect("build");
    let id = ab
        .register("module.exports = (d) => d.n * 2")
        .expect("compile");
    let out = ab.run(&id, &json!({ "n": 21 })).expect("run");
    assert_eq!(out, json!(42));
}

#[test]
fn library_run_script_separate_from_udf() {
    // Same `Afterburner` instance exposes both paths; neither
    // cross-contaminates the other's caches.
    let ab = Afterburner::new().expect("build");

    let udf_id = ab
        .register("module.exports = (d) => d + 1")
        .expect("compile udf");
    let udf_out = ab.run(&udf_id, &json!(40)).expect("run udf");
    assert_eq!(udf_out, json!(41));

    let script_out = ab
        .run_script(r#"console.log("script ran")"#)
        .expect("run_script");
    assert_eq!(script_out.exit_code, 0);
    let stdout = String::from_utf8_lossy(&script_out.stdout);
    assert!(stdout.contains("script ran"), "stdout = {stdout:?}");

    // UDF path is still callable after script path was exercised.
    let udf2 = ab.run(&udf_id, &json!(99)).expect("udf after script");
    assert_eq!(udf2, json!(100));
}

#[test]
fn cli_banner_silenced_by_burn_quiet() {
    // BURN_QUIET=1 must suppress the first-run open-capabilities
    // banner regardless of whether the ack-marker is set.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        // Isolated XDG so an existing marker on the host doesn't
        // mask a missing-silence bug.
        .env(
            "XDG_CACHE_HOME",
            std::env::temp_dir().join("burn-b0-silent"),
        )
        .arg("-e")
        .arg(r#"console.log("q")"#)
        .output()
        .expect("burn");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("running with open capabilities"),
        "banner leaked despite BURN_QUIET=1: stderr = {stderr:?}"
    );
}

#[test]
fn cli_banner_silenced_by_quiet_flag() {
    let marker = std::env::temp_dir().join("burn-b0-silent-flag");
    let _ = std::fs::remove_dir_all(&marker);
    let out = Command::new(BURN)
        .env_remove("BURN_QUIET")
        .env("XDG_CACHE_HOME", &marker)
        .arg("--quiet")
        .arg("-e")
        .arg(r#"console.log("q")"#)
        .output()
        .expect("burn");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("running with open capabilities"),
        "banner leaked despite --quiet: stderr = {stderr:?}"
    );
}

#[test]
fn cli_banner_appears_on_first_implicit_open() {
    // Fresh XDG_CACHE_HOME → no ack-marker → banner should print
    // (implicit open, no --sandbox, no --allow-*, no -A).
    let cache_dir = std::env::temp_dir().join(format!("burn-b0-banner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache_dir);
    let out = Command::new(BURN)
        .env_remove("BURN_QUIET")
        .env("XDG_CACHE_HOME", &cache_dir)
        .arg("-e")
        .arg(r#"console.log("first run")"#)
        .output()
        .expect("burn");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("running with open capabilities"),
        "banner missing on fresh cache dir: stderr = {stderr:?}"
    );

    // Second run — ack-marker now exists, banner should go silent.
    let out2 = Command::new(BURN)
        .env_remove("BURN_QUIET")
        .env("XDG_CACHE_HOME", &cache_dir)
        .arg("-e")
        .arg(r#"console.log("second run")"#)
        .output()
        .expect("burn");
    assert!(out2.status.success());
    let stderr2 = String::from_utf8_lossy(&out2.stderr);
    assert!(
        !stderr2.contains("running with open capabilities"),
        "banner repeated after ack: stderr = {stderr2:?}"
    );

    // Cleanup — best effort.
    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[test]
fn cli_banner_does_not_fire_with_sandbox_flag() {
    let cache_dir =
        std::env::temp_dir().join(format!("burn-b0-banner-sandbox-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache_dir);
    let out = Command::new(BURN)
        .env_remove("BURN_QUIET")
        .env("XDG_CACHE_HOME", &cache_dir)
        .arg("--sandbox")
        .arg("-e")
        .arg(r#"console.log("sb")"#)
        .output()
        .expect("burn");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("running with open capabilities"),
        "banner fired under --sandbox: stderr = {stderr:?}"
    );
}

#[test]
fn cli_banner_does_not_fire_with_allow_all() {
    let cache_dir = std::env::temp_dir().join(format!("burn-b0-banner-A-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache_dir);
    let out = Command::new(BURN)
        .env_remove("BURN_QUIET")
        .env("XDG_CACHE_HOME", &cache_dir)
        .arg("-A")
        .arg("-e")
        .arg(r#"console.log("A")"#)
        .output()
        .expect("burn");
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("running with open capabilities"),
        "banner fired under -A (explicit open): stderr = {stderr:?}"
    );
}
