// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `vm.measureMemory` (Node 13.9+) and
//! `worker_threads.isMarkedAsUntransferable` (Node 21+).

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
fn vm_measure_memory_resolves_summary_shape() {
    let out = run_inline(
        r#"
        const vm = require('vm');
        vm.measureMemory().then(r => {
            const t = r && r.total;
            if (t && typeof t.jsMemoryEstimate === 'number' &&
                Array.isArray(t.jsMemoryRange) && t.jsMemoryRange.length === 2)
                console.log('MEM-SUMMARY-OK');
            else console.log('FAIL', JSON.stringify(r));
        });
        "#,
    );
    assert_marker(&out, "MEM-SUMMARY-OK");
}

#[test]
fn vm_measure_memory_detailed_includes_current_and_other() {
    let out = run_inline(
        r#"
        const vm = require('vm');
        vm.measureMemory({ mode: 'detailed' }).then(r => {
            if (r && r.current && Array.isArray(r.other)) console.log('MEM-DETAIL-OK');
            else console.log('FAIL', JSON.stringify(r));
        });
        "#,
    );
    assert_marker(&out, "MEM-DETAIL-OK");
}

#[test]
fn worker_threads_mark_and_check_untransferable() {
    let out = run_inline(
        r#"
        const wt = require('worker_threads');
        const buf = new ArrayBuffer(8);
        const before = wt.isMarkedAsUntransferable(buf);
        wt.markAsUntransferable(buf);
        const after = wt.isMarkedAsUntransferable(buf);
        if (before === false && after === true) console.log('UNTRANS-OK');
        else console.log('FAIL', before, after);
        "#,
    );
    assert_marker(&out, "UNTRANS-OK");
}

#[test]
fn worker_threads_is_marked_untransferable_on_unmarked_returns_false() {
    let out = run_inline(
        r#"
        const wt = require('worker_threads');
        if (wt.isMarkedAsUntransferable({}) === false &&
            wt.isMarkedAsUntransferable(new ArrayBuffer(4)) === false)
            console.log('UNMARKED-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "UNMARKED-OK");
}
