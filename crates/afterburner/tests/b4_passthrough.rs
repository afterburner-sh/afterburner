// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B4 phase gate: `burn node foo.js` pass-through.
//!
//! Verification target #2 from IMPL_PLAN_BURN_RUNTIME.md §8:
//! `burn node -e 'console.log(1 + 2)'` prints `3`.
//!
//! Tests cover:
//! - `burn node -e` eval path
//! - `burn node <file>` script path
//! - `burn node` with trailing `process.argv` args
//! - `burn node` with no args (error)
//! - Q5-A existing-file-wins (file called "node" in cwd)
//! - All other pass-through targets (npm, npx, pnpm, yarn, bun) error
//! - Path-qualified names (`./node`) bypass pass-through
//! - `process.argv[0]` / `process.argv[1]` shape
//! - Exit code propagation through pass-through
//! - Nonexistent script file errors cleanly

#![cfg(feature = "bin")]

use std::fs;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Unique temp directory per test to avoid parallel collisions.
static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn tmp_dir(label: &str) -> std::path::PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_b4_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---- eval path ----------------------------------------------------------

#[test]
fn burn_node_eval_prints_result() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["node", "-e", "console.log(1 + 2)"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(
        out.status.success(),
        "exit {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "3");
}

#[test]
fn burn_node_eval_multiline() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "node",
            "-e",
            "var x = 10;\nvar y = 20;\nconsole.log(x + y);",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "30");
}

#[test]
fn burn_node_eval_with_require() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args([
            "node",
            "-e",
            "var path = require('path'); console.log(path.join('a', 'b'));",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "a/b");
}

#[test]
fn burn_node_eval_syntax_error_exits_nonzero() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["node", "-e", "function {{{ bad"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(!out.status.success(), "syntax error should fail");
}

// ---- script file path ---------------------------------------------------

#[test]
fn burn_node_runs_script_file() {
    let dir = tmp_dir("script");
    let script = dir.join("hello.js");
    fs::write(&script, "console.log('hello from node passthrough');").unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("node")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "exit {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("hello from node passthrough"));
}

#[test]
fn burn_node_nonexistent_script_errors() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["node", "/tmp/burn_b4_does_not_exist_99999.js"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(!out.status.success(), "nonexistent file should fail");
}

#[test]
fn burn_node_script_exit_code_propagates() {
    let dir = tmp_dir("exitcode");
    let script = dir.join("exit42.js");
    fs::write(&script, "process.exit(42);").unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("node")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        out.status.code(),
        Some(42),
        "exit code should propagate through pass-through"
    );
}

// ---- process.argv shape -------------------------------------------------

#[test]
fn burn_node_passes_trailing_args() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["node", "-e", "console.log(process.argv.slice(2).join(','))"])
        .args(["a", "b", "c"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "a,b,c");
}

#[test]
fn burn_node_argv0_is_burn() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["node", "-e", "console.log(process.argv[0])"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "burn");
}

#[test]
fn burn_node_argv1_is_script_label() {
    let dir = tmp_dir("argv1");
    let script = dir.join("check_argv.js");
    fs::write(&script, "console.log(process.argv[1]);").unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("node")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let _ = fs::remove_dir_all(&dir);
    assert!(out.status.success());
    // argv[1] is the resolved script path.
    assert!(
        stdout.trim().contains("check_argv.js"),
        "argv[1] should contain script name, got: {stdout}"
    );
}

#[test]
fn burn_node_eval_argv1_is_eval_marker() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["node", "-e", "console.log(process.argv[1])"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[eval]");
}

#[test]
fn burn_node_file_trailing_args_in_argv() {
    let dir = tmp_dir("file_args");
    let script = dir.join("args.js");
    fs::write(
        &script,
        "console.log(JSON.stringify(process.argv.slice(2)));",
    )
    .unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("node")
        .arg(&script)
        .args(["x", "y"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&dir);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), r#"["x","y"]"#);
}

// ---- no-args error ------------------------------------------------------

#[test]
fn burn_node_no_args_is_error() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("node")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("missing script") || stderr.contains("usage"),
        "stderr should show helpful message: {stderr}"
    );
}

// ---- Q5-A existing-file-wins --------------------------------------------

#[test]
fn existing_file_named_node_wins_over_passthrough() {
    let dir = tmp_dir("existing");
    let node_file = dir.join("node");
    fs::write(&node_file, "console.log('i am a file called node');").unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(&dir)
        .arg("node")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");

    let _ = fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "exit {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("i am a file called node"));
}

#[test]
fn path_qualified_node_bypasses_passthrough() {
    // `burn ./node` should try to read the file `./node`, not pass-through.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("./node")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    // Should fail because there's no file `./node`, but NOT with the
    // pass-through "missing script path" error.
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("missing script path"),
        "`./node` should not trigger pass-through, stderr: {stderr}"
    );
}

// Coverage for the non-`node` pass-through targets (npm/npx/pnpm/
// yarn/bun) lives in `b5_shim.rs` - those paths now *work* via the
// PATH shim rather than erroring out as "not yet implemented".
