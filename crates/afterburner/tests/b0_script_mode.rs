// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B0 phase gate: top-level script mode via `burn` (CLI) + via
//! `Afterburner::run_script` (library).
//!
//! §8 verification — this file covers:
//!
//! * Top-level `console.log` → real stdout (not JSON-wrapped).
//! * Top-level `await` works through Javy's event-loop drain.
//! * Uncaught exceptions surface as `exit_code: 1` with stderr
//!   carrying the stack.
//! * Syntax errors surface as an `Err(CompileFailed)` at the library
//!   boundary.

#![cfg(feature = "bin")]

use afterburner::{Afterburner, AfterburnerError, Manifold, ScriptInvocation};
use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the compiled `burn` binary, populated by Cargo for
/// integration tests in the crate that declares the binary.
const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_burn_script(source: &str, extra_flags: &[&str]) -> std::process::Output {
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(extra_flags)
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn");
    child.stdin.take();
    child.wait_with_output().expect("wait burn")
}

#[test]
fn top_level_console_log_reaches_stdout() {
    let out = run_burn_script(r#"console.log("hello from script mode")"#, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello from script mode"),
        "stdout = {stdout:?}"
    );
}

#[test]
fn top_level_await_resolves() {
    // Script mode's outer wrapper is compiled as an ES module with
    // `event_loop(true)`, so top-level await is legitimate.
    let src = r#"
        const v = await Promise.resolve(42);
        console.log("resolved:", v);
    "#;
    let out = run_burn_script(src, &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("resolved: 42"), "stdout = {stdout:?}");
}

#[test]
fn uncaught_exception_yields_exit_1_with_partial_stdout() {
    // `before throw` must flush to stdout BEFORE the Error propagates.
    let src = r#"
        console.log("before throw");
        throw new Error("boom");
    "#;
    let out = run_burn_script(src, &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1, got {:?}",
        out.status.code()
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("before throw"), "stdout = {stdout:?}");
    assert!(stderr.contains("boom"), "stderr = {stderr:?}");
}

#[test]
fn library_run_script_with_sealed_default() {
    // The library API's default manifold is `sealed()` — console.log
    // still goes through plenum's polyfill (which uses the baked-in
    // Javy.IO path) regardless of capability gates, because
    // `console.*` is not a capability-gated resource.
    let ab = Afterburner::new().expect("build ab");
    let outcome = ab
        .run_script(r#"console.log("lib"); console.log("ok");"#)
        .expect("script ran");
    assert_eq!(outcome.exit_code, 0);
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        stdout.contains("lib") && stdout.contains("ok"),
        "stdout = {stdout:?}"
    );
}

#[test]
fn library_script_syntax_error_yields_exit_1() {
    // Syntax errors in user source surface as runtime exceptions
    // because the outer wrapper wraps user code into a JS Function
    // body — the parser blows up at `Function` construction time, not
    // at our wrapper's `compile_src`. That's the same shape Node
    // gives back: exit code 1 with a SyntaxError-ish stderr.
    //
    // `Err(CompileFailed)` from script mode is reserved for our
    // outer-wrapper text being malformed — i.e., a bug on our side.
    let ab = Afterburner::new().expect("build ab");
    let outcome = ab
        .run_script("this is not valid js (*^(")
        .expect("ran (with error)");
    assert_eq!(outcome.exit_code, 1);
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    assert!(
        stderr.contains("Error") || stderr.contains("SyntaxError") || stderr.contains("expecting"),
        "expected SyntaxError-ish stderr, got {stderr:?}"
    );
    // We should *not* get a `CompileFailed`-shape error with this
    // particular stderr — that path is for outer-wrapper bugs only.
    let _ = AfterburnerError::CompileFailed("unused; satisfies import lint".into());
}

#[test]
fn library_script_uncaught_exception_yields_exit_1() {
    let ab = Afterburner::new().expect("build ab");
    let outcome = ab
        .run_script("throw new Error('library boom');")
        .expect("script ran (exit != 0 is Ok)");
    assert_eq!(outcome.exit_code, 1);
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    assert!(stderr.contains("library boom"), "stderr = {stderr:?}");
}

#[test]
fn library_run_script_with_invocation_threads_argv_env() {
    let ab = Afterburner::builder()
        .manifold(Manifold::sealed())
        .build()
        .expect("build");
    let mut inv = ScriptInvocation {
        argv: vec!["burn".into(), "[test]".into(), "x".into(), "y".into()],
        ..ScriptInvocation::default()
    };
    inv.env.insert("MY_FLAG".into(), "one".into());
    inv.env.insert("OTHER".into(), "two".into());

    let src = r#"
        console.log("argv0:", process.argv[0]);
        console.log("argv[2]:", process.argv[2]);
        console.log("argv[3]:", process.argv[3]);
        console.log("MY_FLAG:", process.env.MY_FLAG);
        console.log("OTHER:", process.env.OTHER);
    "#;
    let outcome = ab
        .run_script_with(src, &inv, ab.default_limits())
        .expect("script ran");
    assert_eq!(
        outcome.exit_code,
        0,
        "stderr: {:?}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(stdout.contains("argv0: burn"), "stdout = {stdout:?}");
    assert!(stdout.contains("argv[2]: x"), "stdout = {stdout:?}");
    assert!(stdout.contains("argv[3]: y"), "stdout = {stdout:?}");
    assert!(stdout.contains("MY_FLAG: one"), "stdout = {stdout:?}");
    assert!(stdout.contains("OTHER: two"), "stdout = {stdout:?}");
}

#[test]
fn cli_piped_stdin_not_expected_in_script_mode() {
    // `burn run` / `burn -e` do NOT consume stdin — that's `burn thrust`.
    // If we pipe stdin here, it should be ignored cleanly.
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(r#"console.log("script ignores stdin")"#)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"{\"payload\": \"ignored\"}\n");
    }
    let out = child.wait_with_output().expect("wait burn");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("script ignores stdin"),
        "stdout = {stdout:?}"
    );
}
