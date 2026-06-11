// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Async-style `child_process` wrappers: `spawn` / `exec` /
//! `execFile` / `fork`. The host backend is synchronous; the
//! wrappers run inline and dispatch the canonical `spawn` /
//! `exit` / `close` / `data` events on a microtask.

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
fn spawn_emits_data_then_close_with_zero_status() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        let collected = '';
        let closeCode = null;
        const child = cp.spawn('echo', ['SPAWN-MARK']);
        child.stdout.on('data', c => { collected += c.toString(); });
        child.on('close', code => {
            closeCode = code;
            if (collected.indexOf('SPAWN-MARK') >= 0 && closeCode === 0) {
                console.log('SPAWN-OK');
            } else {
                console.log('FAIL', closeCode, JSON.stringify(collected));
            }
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 3000);
        "#,
    );
    assert_marker(&out, "SPAWN-OK");
}

#[test]
fn spawn_exposes_pid_and_spawnargs() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        const child = cp.spawn('true', ['x', 'y']);
        if (child.spawnfile === 'true' && Array.isArray(child.spawnargs) &&
            child.spawnargs[0] === 'true' && typeof child.pid === 'number') {
            console.log('META-OK');
        } else {
            console.log('FAIL', child.spawnfile, JSON.stringify(child.spawnargs));
        }
        child.on('close', () => process.exit(0));
        setTimeout(() => process.exit(1), 3000);
        "#,
    );
    assert_marker(&out, "META-OK");
}

#[test]
fn exec_callback_fires_with_stdout() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        cp.exec('echo HELLO-EXEC', (err, stdout, stderr) => {
            if (!err && stdout.indexOf('HELLO-EXEC') >= 0) console.log('EXEC-OK');
            else console.log('FAIL', err && err.message, JSON.stringify(stdout));
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 3000);
        "#,
    );
    assert_marker(&out, "EXEC-OK");
}

#[test]
fn exec_callback_receives_error_on_non_zero_exit() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        cp.exec('false', (err, stdout, stderr) => {
            if (err) console.log('EXEC-ERR-OK');
            else console.log('FAIL no-err');
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 3000);
        "#,
    );
    assert_marker(&out, "EXEC-ERR-OK");
}

#[test]
fn exec_file_callback_with_buffer_encoding() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        cp.execFile('echo', ['BUF-OUT'], { encoding: 'buffer' }, (err, stdout) => {
            if (Buffer.isBuffer(stdout) && stdout.toString('utf8').indexOf('BUF-OUT') >= 0) {
                console.log('EXECFILE-BUF-OK');
            } else {
                console.log('FAIL', typeof stdout);
            }
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 3000);
        "#,
    );
    assert_marker(&out, "EXECFILE-BUF-OK");
}

#[test]
fn child_process_class_is_constructable() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        const proto = cp.ChildProcess.prototype;
        if (typeof cp.ChildProcess === 'function' && proto && typeof proto.on === 'function')
            console.log('CP-CLASS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CP-CLASS-OK");
}

#[test]
fn spawn_stdout_set_encoding_emits_strings() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        const child = cp.spawn('echo', ['ENC-TEST']);
        child.stdout.setEncoding('utf8');
        let saw = null;
        child.stdout.on('data', c => { saw = c; });
        child.on('close', () => {
            if (typeof saw === 'string' && saw.indexOf('ENC-TEST') >= 0) console.log('ENC-OK');
            else console.log('FAIL', typeof saw, saw);
            process.exit(0);
        });
        setTimeout(() => process.exit(1), 3000);
        "#,
    );
    assert_marker(&out, "ENC-OK");
}
