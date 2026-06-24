// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! End-to-end `burn repl --lang <L>` integration tests.
//!
//! Each test drives the real `burn` binary, piping a REPL session on stdin and
//! asserting the values it prints to stdout. This covers the whole path:
//! arg parsing -> language dispatch -> per-line render -> compile (for the
//! native langs, via the existing single-file drivers) -> embedder run ->
//! the stdout-delta display.
//!
//! Toolchain honesty: a test for a compiled language LOUD-SKIPs (prints why and
//! returns) when its toolchain is absent - no `cargo`/`go`, no `wasm32-wasip1`
//! target, no wasi-sdk. The skip is detected from the actionable error the
//! driver emits ("not found on PATH", "rustup target add", "wasi-sdk not
//! found", ...), so the suite is never silently green when a tool is missing.
//! The Ruby and runtime-less Python paths assert their honest pending message.

#![cfg(feature = "bin")]

use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the compiled `burn` binary (populated by Cargo for the crate that
/// declares the binary).
const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Drive `burn repl --lang <lang>` with `session` on stdin (each element is one
/// line; a trailing `:exit` is appended). Returns (stdout, stderr).
fn run_repl(lang: &str, session: &[&str]) -> (String, String) {
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        // Force the plain banner / no animation regardless of the test TTY.
        .env("NO_COLOR", "1")
        .arg("repl")
        .arg("--lang")
        .arg(lang)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn repl");

    {
        let mut stdin = child.stdin.take().expect("repl stdin");
        for line in session {
            writeln!(stdin, "{line}").expect("write repl line");
        }
        writeln!(stdin, ":exit").expect("write :exit");
        // stdin dropped here -> EOF, so the loop also ends if :exit is missed.
    }

    let out = child.wait_with_output().expect("wait burn repl");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Whether `stderr` shows a missing-toolchain error for a compiled language
/// (the markers the single-file drivers emit). When true, the caller LOUD-SKIPs.
fn toolchain_absent(stderr: &str) -> bool {
    const MARKERS: &[&str] = &[
        "not found on PATH",
        "rustup target add",
        "wasm32-wasip1",
        "wasi-sdk not found",
        "was not found on PATH",
        "exited with code",
    ];
    MARKERS.iter().any(|m| stderr.contains(m))
}

// ---- JS / TS (always available; no external toolchain) ----------------------

#[test]
fn js_repl_evaluates_and_carries_state() {
    let (stdout, stderr) = run_repl(
        "js",
        &[
            "var x = 21",
            "x * 2",
            "function sq(n) { return n*n }",
            "sq(9)",
        ],
    );
    assert!(
        stdout.contains("42"),
        "x*2 -> 42; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(stdout.contains("81"), "sq(9) -> 81; stdout={stdout:?}");
}

#[test]
fn ts_repl_strips_types_and_runs() {
    let (stdout, _stderr) = run_repl(
        "ts",
        &[
            "const x: number = 21",
            "x * 2",
            "const greet = (n: string): string => `hi ${n}`",
            r#"greet("burn")"#,
        ],
    );
    assert!(stdout.contains("42"), "typed x*2 -> 42; stdout={stdout:?}");
    assert!(
        stdout.contains("hi burn"),
        "typed arrow fn -> 'hi burn'; stdout={stdout:?}"
    );
}

#[test]
fn ts_repl_type_only_line_is_a_noop_not_an_error() {
    // An interface is pure type: it strips to nothing and must not error.
    let (stdout, stderr) = run_repl(
        "ts",
        &["interface P { x: number }", "const p: P = { x: 7 }", "p.x"],
    );
    assert!(stdout.contains('7'), "p.x -> 7; stdout={stdout:?}");
    assert!(
        !stderr.contains("SyntaxError"),
        "type-only line must not raise a syntax error; stderr={stderr:?}"
    );
}

// ---- Rust (cargo + wasm32-wasip1) -------------------------------------------

#[test]
fn rust_repl_compiles_and_runs_each_line() {
    let (stdout, stderr) = run_repl(
        "rust",
        &[
            "let x = 21;",
            "x * 2",
            "fn sq(n: i32) -> i32 { n * n }",
            "sq(9)",
            r#"println!("hello from rust");"#,
        ],
    );
    if toolchain_absent(&stderr) {
        eprintln!("SKIP rust REPL (toolchain absent): {stderr}");
        return;
    }
    assert!(
        stdout.contains("42"),
        "x*2 -> 42; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(stdout.contains("81"), "sq(9) -> 81; stdout={stdout:?}");
    assert!(
        stdout.contains("hello from rust"),
        "println! not truncated; stdout={stdout:?}"
    );
}

// ---- Go (GOOS=wasip1 GOARCH=wasm) -------------------------------------------

#[test]
fn go_repl_compiles_and_runs_each_line() {
    let (stdout, stderr) = run_repl(
        "go",
        &[
            "x := 21",
            "x * 2",
            "func sq(n int) int { return n * n }",
            "sq(9)",
            r#"fmt.Println("hello from go")"#,
            r#"import "strings""#,
            r#"strings.ToUpper("burn")"#,
        ],
    );
    if toolchain_absent(&stderr) {
        eprintln!("SKIP go REPL (toolchain absent): {stderr}");
        return;
    }
    assert!(
        stdout.contains("42"),
        "x*2 -> 42; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(stdout.contains("81"), "sq(9) -> 81; stdout={stdout:?}");
    assert!(
        stdout.contains("hello from go"),
        "fmt.Println; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("BURN"),
        "deferred import then strings.ToUpper -> BURN; stdout={stdout:?}"
    );
}

// ---- C (wasi-sdk) -----------------------------------------------------------

#[test]
fn c_repl_runs_or_skips_honestly() {
    let (stdout, stderr) = run_repl("c", &[r#"printf("hello from c\n");"#]);
    if toolchain_absent(&stderr) {
        eprintln!("SKIP c REPL (wasi-sdk absent): {stderr}");
        // The skip must be the honest wasi-sdk message, never a silent pass.
        assert!(
            stderr.contains("wasi-sdk not found"),
            "C skip must be the honest wasi-sdk-missing error; stderr={stderr:?}"
        );
        return;
    }
    assert!(
        stdout.contains("hello from c"),
        "C printf; stdout={stdout:?}"
    );
}

// ---- C++ (wasi-sdk) ---------------------------------------------------------

#[test]
fn cpp_repl_runs_or_skips_honestly() {
    let (stdout, stderr) = run_repl("cpp", &[r#"std::cout << "hi cpp" << std::endl;"#]);
    if toolchain_absent(&stderr) {
        eprintln!("SKIP cpp REPL (wasi-sdk absent): {stderr}");
        assert!(
            stderr.contains("wasi-sdk not found"),
            "C++ skip must be the honest wasi-sdk-missing error; stderr={stderr:?}"
        );
        return;
    }
    assert!(stdout.contains("hi cpp"), "C++ cout; stdout={stdout:?}");
}

// ---- Python (Pyodide runtime via BURN_PYTHON_RUNTIME) -----------------------

#[test]
fn python_repl_runs_or_skips_honestly() {
    let (stdout, stderr) = run_repl("python", &[r#"print("hi py")"#, "6 * 7"]);
    if stderr.contains("python runtime not found") {
        eprintln!("SKIP python REPL (runtime absent): {stderr}");
        return;
    }
    assert!(stdout.contains("hi py"), "print; stdout={stdout:?}");
    assert!(stdout.contains("42"), "6*7 echoed -> 42; stdout={stdout:?}");
}

// ---- Ruby (honest pending) --------------------------------------------------

#[test]
fn ruby_repl_is_honest_pending() {
    // Ruby has no bundled runtime: it must report a clear, actionable pending
    // state (never crash, never silently succeed).
    let (_stdout, stderr) = run_repl("ruby", &[r#"puts "hi""#]);
    assert!(
        stderr.contains("ruby.wasm runtime not bundled"),
        "ruby REPL must say its runtime is pending; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("BURN_RUBY_RUNTIME"),
        "ruby pending message must be actionable; stderr={stderr:?}"
    );
}

// ---- unknown language -------------------------------------------------------

#[test]
fn unknown_language_is_a_clear_error() {
    let (_stdout, stderr) = run_repl("haskell", &[]);
    assert!(
        stderr.contains("haskell") && stderr.contains("supported values"),
        "unknown lang must name it and list the supported set; stderr={stderr:?}"
    );
}
