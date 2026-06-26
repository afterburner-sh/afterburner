// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! Script failure → exit-code contract.
//!
//! A failing script must never exit 0: harnesses key off exit codes,
//! and a rejection that vanishes (exit 0, no output) is the worst
//! kind of false-green. The contract, matching Node's convention:
//!
//! * top-level sync `throw` → exit 1, message + stack on stderr;
//! * a rejected Promise assigned to `module.exports` → exit 1 - the
//!   script-mode envelope awaits an exported thenable
//!   (`envelope.rs::wrap_script_source`), so the rejection surfaces
//!   as a module-evaluation error instead of being dropped on the
//!   floor (the assignment itself is synchronous; nothing else ever
//!   observes the rejection);
//! * an exported async IIFE that throws → exit 1 (same await path);
//! * a *resolved* exported promise → exit 0, value discarded
//!   (script-mode output stays console-only).
//!
//! These run through the daemon-mode one-shot path (`burn -e CODE`),
//! the same plumbing `burn run file.js` uses.

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_eval(code: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .arg("-e")
        .arg(code)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

#[test]
fn rejected_exported_promise_exits_nonzero_with_message() {
    let out = run_eval("module.exports = Promise.reject(new Error('boom-rejected'))");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "rejected exported promise must exit 1; stderr: {stderr}"
    );
    assert!(
        stderr.contains("boom-rejected"),
        "stderr must carry the rejection message; got: {stderr}"
    );
    assert!(
        stderr.contains("at "),
        "stderr must carry a stack trace; got: {stderr}"
    );
}

#[test]
fn exported_async_throw_exits_nonzero_with_message() {
    let out = run_eval("module.exports = (async () => { throw new Error('boom-async'); })()");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "exported async throw must exit 1; stderr: {stderr}"
    );
    assert!(
        stderr.contains("boom-async"),
        "stderr must carry the thrown message; got: {stderr}"
    );
}

#[test]
fn top_level_sync_throw_exits_nonzero_with_message() {
    let out = run_eval("throw new Error('boom-sync')");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "top-level throw must exit 1; stderr: {stderr}"
    );
    assert!(
        stderr.contains("boom-sync"),
        "stderr must carry the thrown message; got: {stderr}"
    );
}

#[test]
fn resolved_exported_promise_still_exits_zero() {
    let out = run_eval("module.exports = Promise.resolve(42); console.log('done-ok')");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "resolved exported promise must exit 0; stderr: {stderr}"
    );
    assert!(
        stdout.contains("done-ok"),
        "console output must still flow; got: {stdout}"
    );
}

#[test]
fn run_file_with_rejected_exported_promise_exits_nonzero() {
    // Same contract through `burn run FILE` (file path, not -e).
    let dir = std::env::temp_dir().join(format!("burn_exitcode_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let file = dir.join("rejector.js");
    std::fs::write(
        &file,
        "module.exports = Promise.reject(new Error('boom-file'));\n",
    )
    .expect("write script");
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .arg("run")
        .arg(&file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "burn run with rejected export must exit 1; stderr: {stderr}"
    );
    assert!(
        stderr.contains("boom-file"),
        "stderr must carry the rejection message; got: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
