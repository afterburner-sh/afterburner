// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B0 phase gate: `process.argv` + `process.env` behavior under the
//! various manifold modes the `burn` CLI supports.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_burn(code: &str, flags: &[&str], env_overrides: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(BURN);
    cmd.env("BURN_QUIET", "1");
    for (k, v) in env_overrides {
        cmd.env(k, v);
    }
    cmd.args(flags)
        .arg("-e")
        .arg(code)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("burn")
}

// ---- argv --------------------------------------------------------------

#[test]
fn argv0_is_burn() {
    let out = run_burn(r#"console.log(process.argv[0])"#, &[], &[]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "burn");
}

#[test]
fn argv1_is_eval_marker_for_dash_e() {
    let out = run_burn(r#"console.log(process.argv[1])"#, &[], &[]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[eval]");
}

#[test]
fn argv_captures_trailing_args() {
    let child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(r#"console.log(JSON.stringify(process.argv.slice(2)))"#)
        .arg("hello")
        .arg("world")
        .arg("42")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("burn");
    assert!(
        child.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    let stdout = String::from_utf8_lossy(&child.stdout);
    assert_eq!(stdout.trim(), r#"["hello","world","42"]"#);
}

#[test]
fn argv_after_double_dash_separator() {
    // The `--` separator is the portable way to pass hyphen-prefixed
    // values through any clap-style parser. Anything after it is
    // strictly positional.
    let child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(r#"console.log(JSON.stringify(process.argv.slice(2)))"#)
        .arg("--")
        .arg("--my-flag")
        .arg("plain")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("burn");
    assert!(
        child.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    let stdout = String::from_utf8_lossy(&child.stdout);
    assert!(
        stdout.contains("--my-flag") && stdout.contains("plain"),
        "stdout = {stdout:?}"
    );
}

// ---- env ---------------------------------------------------------------

#[test]
fn default_manifold_sees_env() {
    // Q1-D: CLI defaults to open, so process.env mirrors std::env.
    let out = run_burn(
        r#"console.log("X=" + process.env.TEST_B0_X)"#,
        &[],
        &[("TEST_B0_X", "abc123")],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "X=abc123");
}

#[test]
fn sandbox_sees_empty_env() {
    let out = run_burn(
        r#"console.log("X=" + (process.env.TEST_B0_X ?? "MISSING"))"#,
        &["--sandbox"],
        &[("TEST_B0_X", "should-be-hidden")],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "X=MISSING");
}

#[test]
fn allow_env_is_allow_list() {
    let out = run_burn(
        r#"
        console.log("X=" + (process.env.TEST_B0_X ?? "MISSING"));
        console.log("Y=" + (process.env.TEST_B0_Y ?? "MISSING"));
        "#,
        &["--sandbox", "--allow-env=TEST_B0_X"],
        &[("TEST_B0_X", "visible"), ("TEST_B0_Y", "hidden")],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("X=visible"), "stdout = {stdout:?}");
    assert!(stdout.contains("Y=MISSING"), "stdout = {stdout:?}");
}

#[test]
fn allow_env_wildcard_sees_all() {
    let out = run_burn(
        r#"console.log("X=" + (process.env.TEST_B0_X ?? "MISSING"))"#,
        &["--sandbox", "--allow-env=*"],
        &[("TEST_B0_X", "abc")],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "X=abc");
}

#[test]
fn allow_all_sees_env() {
    let out = run_burn(
        r#"console.log("X=" + process.env.TEST_B0_X)"#,
        &["-A"],
        &[("TEST_B0_X", "opened")],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "X=opened");
}
