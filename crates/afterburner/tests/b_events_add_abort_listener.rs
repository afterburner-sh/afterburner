// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `events.addAbortListener(signal, listener)` (Node 20+).

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
fn add_abort_listener_fires_on_abort() {
    let out = run_inline(
        r#"
        const { addAbortListener } = require('events');
        const ctrl = new AbortController();
        addAbortListener(ctrl.signal, () => console.log('FIRED'));
        ctrl.abort();
        "#,
    );
    assert_marker(&out, "FIRED");
}

#[test]
fn add_abort_listener_already_aborted_fires_async() {
    let out = run_inline(
        r#"
        const { addAbortListener } = require('events');
        const ctrl = new AbortController();
        ctrl.abort();
        let fired = false;
        addAbortListener(ctrl.signal, () => { fired = true; });
        setTimeout(() => console.log(fired ? 'PRE-FIRED' : 'FAIL'), 10);
        "#,
    );
    assert_marker(&out, "PRE-FIRED");
}

#[test]
fn add_abort_listener_returns_disposable() {
    let out = run_inline(
        r#"
        const { addAbortListener } = require('events');
        const ctrl = new AbortController();
        const d = addAbortListener(ctrl.signal, () => {});
        const sym = Symbol.dispose || Symbol.for('Symbol.dispose');
        if (typeof d[sym] === 'function') console.log('DISPOSABLE-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "DISPOSABLE-OK");
}

#[test]
fn add_abort_listener_rejects_invalid_args() {
    let out = run_inline(
        r#"
        const { addAbortListener } = require('events');
        try { addAbortListener(null, () => {}); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_INVALID_ARG_TYPE') console.log('REJECT-OK'); else console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "REJECT-OK");
}
