// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `process.stdout` / `stderr` / `stdin` shape - fd numbers, TTY
//! flags, color helpers, EventEmitter-shaped methods. Many real Node
//! libraries (chalk, ora, log streams, pipe-aware tools) probe these
//! at module init.

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
fn process_stdio_fds_are_canonical_zero_one_two() {
    let out = run_inline(
        r#"
        if (process.stdin.fd === 0 && process.stdout.fd === 1 && process.stderr.fd === 2)
            console.log('FD-OK');
        else console.log('FAIL', process.stdin.fd, process.stdout.fd, process.stderr.fd);
        "#,
    );
    assert_marker(&out, "FD-OK");
}

#[test]
fn process_stdout_is_tty_is_false_under_pipe() {
    let out = run_inline(
        r#"
        if (process.stdout.isTTY === false && process.stderr.isTTY === false)
            console.log('TTY-OK');
        else console.log('FAIL', process.stdout.isTTY, process.stderr.isTTY);
        "#,
    );
    assert_marker(&out, "TTY-OK");
}

#[test]
fn process_stdout_columns_and_rows_are_finite() {
    let out = run_inline(
        r#"
        if (typeof process.stdout.columns === 'number' && process.stdout.columns > 0
            && typeof process.stdout.rows === 'number' && process.stdout.rows > 0)
            console.log('SIZE-OK');
        else console.log('FAIL', process.stdout.columns, process.stdout.rows);
        "#,
    );
    assert_marker(&out, "SIZE-OK");
}

#[test]
fn process_stdout_color_helpers_are_callable() {
    let out = run_inline(
        r#"
        if (typeof process.stdout.getColorDepth === 'function' &&
            typeof process.stdout.hasColors === 'function' &&
            process.stdout.getColorDepth() >= 1 &&
            process.stdout.hasColors() === false) console.log('COLOR-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "COLOR-OK");
}

#[test]
fn process_stdio_event_emitter_shape() {
    let out = run_inline(
        r#"
        const all = ['on', 'once', 'removeListener', 'off'];
        for (const m of all) {
            if (typeof process.stdout[m] !== 'function') { console.log('FAIL stdout.', m); process.exit(1); }
            if (typeof process.stderr[m] !== 'function') { console.log('FAIL stderr.', m); process.exit(1); }
            if (typeof process.stdin[m] !== 'function') { console.log('FAIL stdin.', m); process.exit(1); }
        }
        console.log('EE-OK');
        "#,
    );
    assert_marker(&out, "EE-OK");
}

#[test]
fn process_stdout_write_invokes_callback_after_microtask() {
    let out = run_inline(
        r#"
        let called = false;
        process.stdout.write('STDOUT-CB-OK\n', () => { called = true; });
        Promise.resolve().then(() => {
            if (called) console.log('CB-OK');
            else console.log('FAIL');
            process.exit(0);
        });
        "#,
    );
    assert_marker(&out, "CB-OK");
}
