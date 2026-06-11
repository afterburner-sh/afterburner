// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! buffer.isUtf8 / isAscii (Node 19.4+), fs.promises.constants
//! (Node 18.4+), node:test mock surface (MockFunctionContext +
//! MockTracker + snapshot, Node 19.1 / 22.3+).

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed. stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

#[test]
fn buffer_is_utf8_accepts_valid_utf8() {
    let out = run_inline(
        r#"
        const { isUtf8 } = require('buffer');
        const ok = isUtf8(Buffer.from('héllo 🌍', 'utf8'));
        const ascii = isUtf8(Buffer.from('plain', 'utf8'));
        if (ok === true && ascii === true) console.log('UTF8-OK');
        else console.log('FAIL', ok, ascii);
        "#,
    );
    assert_marker(&out, "UTF8-OK");
}

#[test]
fn buffer_is_utf8_rejects_invalid_continuation() {
    let out = run_inline(
        r#"
        const { isUtf8 } = require('buffer');
        const bad = Buffer.from([0xc3, 0x28]);  // overlong / bad continuation
        const lone = Buffer.from([0x80]);  // lone continuation byte
        if (isUtf8(bad) === false && isUtf8(lone) === false) console.log('UTF8-REJECT-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "UTF8-REJECT-OK");
}

#[test]
fn buffer_is_ascii_distinguishes_high_byte() {
    let out = run_inline(
        r#"
        const { isAscii } = require('buffer');
        const a = isAscii(Buffer.from('plain', 'utf8'));
        const b = isAscii(Buffer.from([0x80]));
        if (a === true && b === false) console.log('ASCII-OK');
        else console.log('FAIL', a, b);
        "#,
    );
    assert_marker(&out, "ASCII-OK");
}

#[test]
fn buffer_is_utf8_throws_on_garbage_input() {
    let out = run_inline(
        r#"
        const { isUtf8 } = require('buffer');
        try { isUtf8(null); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_INVALID_ARG_TYPE') console.log('ARG-TYPE-OK'); else console.log('FAIL wrong-code', e.code); }
        "#,
    );
    assert_marker(&out, "ARG-TYPE-OK");
}

#[test]
fn fs_promises_constants_alias_present() {
    let out = run_inline(
        r#"
        const fs = require('fs');
        const c = fs.promises.constants;
        if (c && c === fs.constants) console.log('FSP-CONST-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "FSP-CONST-OK");
}

#[test]
fn node_test_mock_function_records_calls() {
    let out = run_inline(
        r#"
        const { mock } = require('node:test');
        const f = mock.fn((a, b) => a + b);
        f(1, 2);
        f(3, 4);
        if (f.mock instanceof Object && f.mock.calls.length === 2 &&
            f.mock.callCount() === 2 &&
            f.mock.calls[0].arguments[0] === 1)
            console.log('MOCK-CALLS-OK');
        else console.log('FAIL', f.mock && f.mock.calls && f.mock.calls.length);
        "#,
    );
    assert_marker(&out, "MOCK-CALLS-OK");
}

#[test]
fn node_test_mock_function_reset_clears_calls() {
    let out = run_inline(
        r#"
        const { mock } = require('node:test');
        const f = mock.fn();
        f(); f();
        f.mock.resetCalls();
        if (f.mock.callCount() === 0) console.log('MOCK-RESET-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "MOCK-RESET-OK");
}

#[test]
fn node_test_exposes_mock_classes_and_snapshot() {
    let out = run_inline(
        r#"
        const t = require('node:test');
        if (typeof t.MockFunctionContext === 'function' &&
            typeof t.MockTracker === 'function' &&
            typeof t.snapshot === 'object' &&
            typeof t.snapshot.setResolveSnapshotPath === 'function')
            console.log('MOCK-CLASSES-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "MOCK-CLASSES-OK");
}
