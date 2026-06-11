// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! End-to-end coverage for the package-dev loop: `burn init` → `burn test`,
//! and REPL session-state persistence.

#![cfg(feature = "bin")]

use std::io::Write;
use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

#[test]
fn burn_test_runs_a_scaffolded_package() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join("widget");

    let init = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args([
            "init",
            pkg.to_str().unwrap(),
            "--name",
            "widget",
            "--namespace",
            "acme",
        ])
        .output()
        .expect("spawn burn init");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(pkg.join("tests/widget.test.js").exists());

    let test = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args(["test", pkg.to_str().unwrap()])
        .output()
        .expect("spawn burn test");
    let stdout = String::from_utf8_lossy(&test.stdout);
    assert!(
        test.status.success(),
        "burn test failed:\n{stdout}{}",
        String::from_utf8_lossy(&test.stderr)
    );
    assert!(
        stdout.contains("passed"),
        "expected a pass summary:\n{stdout}"
    );
}

#[test]
fn repl_persists_session_state_across_lines() {
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn repl");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"var a = 3;\na + 4\n:exit\n")
        .unwrap();
    let out = child.wait_with_output().expect("wait burn repl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `a` defined on line 1 is still in scope on line 2 → 3 + 4 = 7.
    assert!(
        stdout.contains('7'),
        "REPL did not persist state:\n{stdout}"
    );
}
