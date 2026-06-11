// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `performance.mark` / `measure` / `getEntries*` / `clearMarks` /
//! `clearMeasures` / `timeOrigin` — User Timing Level 3 globals.

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
fn performance_time_origin_is_a_number() {
    let out = run_inline(
        r#"
        if (typeof performance.timeOrigin === 'number' && performance.timeOrigin > 0)
            console.log('TIME-ORIGIN-OK');
        else console.log('FAIL', typeof performance.timeOrigin, performance.timeOrigin);
        "#,
    );
    assert_marker(&out, "TIME-ORIGIN-OK");
}

#[test]
fn performance_mark_and_measure_round_trip() {
    let out = run_inline(
        r#"
        performance.mark('start');
        performance.mark('end');
        const m = performance.measure('span', 'start', 'end');
        if (m.entryType === 'measure' && m.name === 'span' && typeof m.duration === 'number')
            console.log('MM-OK');
        else console.log('FAIL', JSON.stringify(m));
        "#,
    );
    assert_marker(&out, "MM-OK");
}

#[test]
fn performance_get_entries_filters_by_type_and_name() {
    let out = run_inline(
        r#"
        performance.clearMarks();
        performance.clearMeasures();
        performance.mark('m1');
        performance.mark('m2');
        performance.measure('span', 'm1', 'm2');
        const all = performance.getEntries();
        const marks = performance.getEntriesByType('mark');
        const namedMark = performance.getEntriesByName('m1', 'mark');
        if (all.length >= 3 && marks.length === 2 && namedMark.length === 1
            && namedMark[0].name === 'm1') {
            console.log('GE-OK');
        } else {
            console.log('FAIL', all.length, marks.length, namedMark.length);
        }
        "#,
    );
    assert_marker(&out, "GE-OK");
}

#[test]
fn performance_clear_marks_drops_only_marks() {
    let out = run_inline(
        r#"
        performance.clearMarks();
        performance.clearMeasures();
        performance.mark('m');
        performance.measure('measure-1', 'm');
        const beforeMarks = performance.getEntriesByType('mark').length;
        const beforeMeas = performance.getEntriesByType('measure').length;
        performance.clearMarks();
        const afterMarks = performance.getEntriesByType('mark').length;
        const afterMeas = performance.getEntriesByType('measure').length;
        if (beforeMarks >= 1 && beforeMeas >= 1 && afterMarks === 0 && afterMeas === beforeMeas)
            console.log('CLEAR-OK');
        else console.log('FAIL', beforeMarks, beforeMeas, afterMarks, afterMeas);
        "#,
    );
    assert_marker(&out, "CLEAR-OK");
}
