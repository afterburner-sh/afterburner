// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `util.getSystemErrorName` / `getSystemErrorMessage` /
//! `getSystemErrorMap` (Node 17+/22.4+), `util.getCallSites`
//! (Node 22.9+), and `util.diff` (Node 24+).

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
fn util_get_system_error_name_for_enoent() {
    let out = run_inline(
        r#"
        const util = require('util');
        if (util.getSystemErrorName(-2) === 'ENOENT' &&
            util.getSystemErrorName(-13) === 'EACCES' &&
            util.getSystemErrorName(99999) === 'UNKNOWN')
            console.log('SEN-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SEN-OK");
}

#[test]
fn util_get_system_error_message_returns_text() {
    let out = run_inline(
        r#"
        const util = require('util');
        const m = util.getSystemErrorMessage(-2);
        if (m === 'No such file or directory') console.log('SEM-OK');
        else console.log('FAIL', m);
        "#,
    );
    assert_marker(&out, "SEM-OK");
}

#[test]
fn util_get_system_error_map_returns_map() {
    let out = run_inline(
        r#"
        const util = require('util');
        const m = util.getSystemErrorMap();
        if (m instanceof Map && m.has(-2) && m.get(-2)[0] === 'ENOENT')
            console.log('SEMAP-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SEMAP-OK");
}

#[test]
fn util_get_call_sites_returns_frame_array() {
    let out = run_inline(
        r#"
        const util = require('util');
        function inner() { return util.getCallSites(); }
        const sites = inner();
        if (Array.isArray(sites) && sites.length > 0 &&
            typeof sites[0].lineNumber === 'number')
            console.log('CALLSITES-OK');
        else console.log('FAIL', JSON.stringify(sites));
        "#,
    );
    assert_marker(&out, "CALLSITES-OK");
}

#[test]
fn util_diff_emits_edit_script() {
    let out = run_inline(
        r#"
        const util = require('util');
        const d = util.diff('a\nb\nc', 'a\nB\nc');
        // Should have at least one removal and one addition.
        const removed = d.some(e => e.type === -1);
        const added   = d.some(e => e.type === 1);
        const equal   = d.some(e => e.type === 0);
        if (removed && added && equal) console.log('DIFF-OK');
        else console.log('FAIL', JSON.stringify(d));
        "#,
    );
    assert_marker(&out, "DIFF-OK");
}

#[test]
fn util_diff_empty_when_identical() {
    let out = run_inline(
        r#"
        const util = require('util');
        const d = util.diff('a\nb', 'a\nb');
        // All entries should be type=0 (equal).
        if (d.every(e => e.type === 0)) console.log('DIFF-EQ-OK');
        else console.log('FAIL', JSON.stringify(d));
        "#,
    );
    assert_marker(&out, "DIFF-EQ-OK");
}
