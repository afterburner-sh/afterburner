// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Web globals real apps probe at module init: `self`, top-level
//! `addEventListener`/`removeEventListener`/`dispatchEvent`,
//! `ProgressEvent`, `CloseEvent`, `ErrorEvent`. Failure on any of
//! these crashes whatwg-url, web-streams-polyfill, undici at load.

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
fn self_references_global_this() {
    let out = run_inline(
        r#"
        if (typeof self !== 'undefined' && self === globalThis) console.log('SELF-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "SELF-OK");
}

#[test]
fn top_level_add_event_listener_dispatches_to_handlers() {
    let out = run_inline(
        r#"
        let fired = false;
        let detail = null;
        addEventListener('beat', (e) => {
            fired = true;
            detail = e.detail;
        });
        dispatchEvent(new CustomEvent('beat', { detail: { tick: 1 } }));
        if (fired && detail && detail.tick === 1) console.log('AEL-OK');
        else console.log('FAIL', fired, JSON.stringify(detail));
        "#,
    );
    assert_marker(&out, "AEL-OK");
}

#[test]
fn remove_event_listener_drops_handler() {
    let out = run_inline(
        r#"
        let count = 0;
        const handler = () => count++;
        addEventListener('hb', handler);
        dispatchEvent(new Event('hb'));
        removeEventListener('hb', handler);
        dispatchEvent(new Event('hb'));
        if (count === 1) console.log('REMOVE-OK');
        else console.log('FAIL', count);
        "#,
    );
    assert_marker(&out, "REMOVE-OK");
}

#[test]
fn progress_event_carries_loaded_total_length_computable() {
    let out = run_inline(
        r#"
        const e = new ProgressEvent('progress', {
            lengthComputable: true,
            loaded: 50,
            total: 100,
        });
        if (e.type === 'progress' && e.loaded === 50 && e.total === 100 &&
            e.lengthComputable === true && e instanceof Event) {
            console.log('PROGRESS-OK');
        } else {
            console.log('FAIL', e.loaded, e.total, e.lengthComputable);
        }
        "#,
    );
    assert_marker(&out, "PROGRESS-OK");
}

#[test]
fn close_event_has_code_reason_was_clean() {
    let out = run_inline(
        r#"
        const e = new CloseEvent('close', { code: 1000, reason: 'bye', wasClean: true });
        if (e.type === 'close' && e.code === 1000 && e.reason === 'bye' &&
            e.wasClean === true && e instanceof Event) {
            console.log('CLOSE-EVT-OK');
        } else {
            console.log('FAIL');
        }
        "#,
    );
    assert_marker(&out, "CLOSE-EVT-OK");
}

#[test]
fn error_event_has_message_and_error_fields() {
    let out = run_inline(
        r#"
        const inner = new Error('oops');
        const e = new ErrorEvent('error', {
            message: 'oops',
            filename: 'a.js',
            lineno: 12,
            colno: 5,
            error: inner,
        });
        if (e.type === 'error' && e.message === 'oops' && e.filename === 'a.js' &&
            e.lineno === 12 && e.colno === 5 && e.error === inner) {
            console.log('ERROR-EVT-OK');
        } else {
            console.log('FAIL');
        }
        "#,
    );
    assert_marker(&out, "ERROR-EVT-OK");
}
