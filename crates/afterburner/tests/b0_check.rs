// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn check` surface — verifies syntax errors in user source are
//! caught at `register`/compile time, while runtime-only errors
//! (ReferenceError, TypeError) are NOT reported. Matches
//! `node --check foo.js` semantics.

#![cfg(feature = "bin")]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Monotonic counter for unique filenames — tests run in parallel
/// threads within the same process, so a process-id-only suffix races
/// between them.
static CTR: AtomicU64 = AtomicU64::new(0);

fn check_file(source: &str) -> std::process::Output {
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("burn-b0-check-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join(format!("probe-{n}.js"));
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(source.as_bytes()).expect("write");
    drop(f);
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("check")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("burn")
}

#[test]
fn check_passes_on_valid_js() {
    let out = check_file(r#"const x = 1; const y = x + 1;"#);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "check should be quiet-on-success");
}

#[test]
fn check_passes_on_module_exports_udf() {
    let out = check_file("module.exports = (d) => d.n + 1;");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_fails_on_raw_syntax_error() {
    let out = check_file("this is not js (*^(");
    assert!(
        !out.status.success(),
        "expected non-zero exit for syntax error"
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn check_fails_on_unclosed_brace() {
    let out = check_file("const x = { a: 1");
    assert!(!out.status.success());
}

#[test]
fn check_passes_on_runtime_only_error() {
    // `foo.bar()` is syntactically valid — ReferenceError only fires
    // at runtime when `foo` is looked up. `burn check` should not
    // flag this, matching `node --check`.
    let out = check_file("foo.bar();");
    assert!(
        out.status.success(),
        "check should ignore runtime errors; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_passes_on_async_top_level_statements() {
    // Script-mode-ish top-level code (without `await`) must pass. The
    // UDF envelope's wrapper accepts arbitrary top-level statements
    // as the body of a Function constructor.
    let out = check_file("console.log('hi'); const n = Math.random();");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
