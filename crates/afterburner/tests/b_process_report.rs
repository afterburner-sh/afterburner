// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `process.report` (Node 11+ diagnostic-report API). We don't
//! generate real heap dumps; the surface exists so probe-shaped
//! libraries (clinic.js, debug-side wrappers) don't crash on init.

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
fn process_report_exposes_node_signal_default() {
    let out = run_inline(
        r#"
        if (typeof process.report === 'object' && process.report.signal === 'SIGUSR2')
            console.log('REPORT-SIG-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "REPORT-SIG-OK");
}

#[test]
fn process_report_get_report_returns_canonical_keys() {
    let out = run_inline(
        r#"
        const r = process.report.getReport();
        const want = ['header','javascriptStack','nativeStack','sharedObjects','libuv','workers','environmentVariables'];
        const got = Object.keys(r);
        if (want.every(k => got.includes(k))) console.log('REPORT-KEYS-OK');
        else console.log('FAIL', JSON.stringify(got));
        "#,
    );
    assert_marker(&out, "REPORT-KEYS-OK");
}

#[test]
fn process_report_write_report_returns_a_string() {
    let out = run_inline(
        r#"
        const f = process.report.writeReport();
        if (typeof f === 'string') console.log('REPORT-WRITE-OK');
        else console.log('FAIL', typeof f);
        "#,
    );
    assert_marker(&out, "REPORT-WRITE-OK");
}

#[test]
fn process_report_flags_default_to_false() {
    let out = run_inline(
        r#"
        const r = process.report;
        if (r.reportOnFatalError === false && r.reportOnSignal === false &&
            r.reportOnUncaughtException === false && r.compact === false)
            console.log('REPORT-FLAGS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "REPORT-FLAGS-OK");
}
