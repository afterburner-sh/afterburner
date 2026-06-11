// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `AbortSignal.any(signals)` — Node 20+ aggregator that returns a
//! signal aborting on the first of the inputs to abort.

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
fn abort_signal_any_aborts_when_first_input_aborts() {
    let out = run_inline(
        r#"
        const a = new AbortController();
        const b = new AbortController();
        const any = AbortSignal.any([a.signal, b.signal]);
        if (any.aborted) { console.log('FAIL pre'); process.exit(1); }
        b.abort(new Error('from-b'));
        setTimeout(() => {
            if (any.aborted && any.reason && any.reason.message === 'from-b') {
                console.log('ANY-OK');
            } else {
                console.log('FAIL', any.aborted, any.reason && any.reason.message);
            }
            process.exit(0);
        }, 50);
        "#,
    );
    assert_marker(&out, "ANY-OK");
}

#[test]
fn abort_signal_any_pre_aborted_input_returns_pre_aborted() {
    let out = run_inline(
        r#"
        const aborted = AbortSignal.abort(new Error('already'));
        const fresh = new AbortController().signal;
        const any = AbortSignal.any([fresh, aborted]);
        if (any.aborted && any.reason && any.reason.message === 'already') console.log('PRE-OK');
        else console.log('FAIL', any.aborted, any.reason && any.reason.message);
        "#,
    );
    assert_marker(&out, "PRE-OK");
}

#[test]
fn abort_signal_any_empty_array_yields_non_aborted() {
    let out = run_inline(
        r#"
        const any = AbortSignal.any([]);
        if (!any.aborted) console.log('EMPTY-OK');
        else console.log('FAIL pre-aborted');
        "#,
    );
    assert_marker(&out, "EMPTY-OK");
}

#[test]
fn abort_signal_any_first_abort_wins() {
    let out = run_inline(
        r#"
        const a = new AbortController();
        const b = new AbortController();
        const any = AbortSignal.any([a.signal, b.signal]);
        a.abort(new Error('a-first'));
        b.abort(new Error('b-second'));
        setTimeout(() => {
            if (any.reason && any.reason.message === 'a-first') console.log('FIRST-OK');
            else console.log('FAIL', any.reason && any.reason.message);
            process.exit(0);
        }, 50);
        "#,
    );
    assert_marker(&out, "FIRST-OK");
}
