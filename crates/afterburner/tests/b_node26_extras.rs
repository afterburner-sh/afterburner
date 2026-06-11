// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Stub-closure audit — fills the last reachable Node-26-era gaps:
//!
//! * `Promise.try` (Stage 3 / Node 22+)
//! * `net.Socket.setEncoding` / `tls.TLSSocket.setEncoding`

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", source])
        .output()
        .expect("spawn burn")
}

fn assert_ok(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains(marker),
        "missing `{marker}`\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

#[test]
#[serial]
fn promise_try_wraps_sync_return() {
    let src = r#"
        Promise.try(() => 42).then(v => {
            if (v !== 42) { console.error('v=', v); process.exit(2); }
            console.log('PROMISE_TRY_SYNC_OK');
            process.exit(0);
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_ok(&run_inline(src), "PROMISE_TRY_SYNC_OK");
}

#[test]
#[serial]
fn promise_try_wraps_sync_throw() {
    let src = r#"
        Promise.try(() => { throw new Error('boom'); }).catch(e => {
            if (!e || e.message !== 'boom') { console.error('e=', e); process.exit(2); }
            console.log('PROMISE_TRY_THROW_OK');
            process.exit(0);
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_ok(&run_inline(src), "PROMISE_TRY_THROW_OK");
}

#[test]
#[serial]
fn promise_try_passes_extra_args() {
    let src = r#"
        Promise.try((a, b) => a + b, 2, 3).then(v => {
            if (v !== 5) { console.error('v=', v); process.exit(2); }
            console.log('PROMISE_TRY_ARGS_OK');
            process.exit(0);
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_ok(&run_inline(src), "PROMISE_TRY_ARGS_OK");
}

#[test]
#[serial]
fn net_socket_setEncoding_smoke() {
    // We can't easily do a full net round-trip in a one-shot script,
    // but we can confirm the API is callable and stores the encoding.
    let src = r#"
        const net = require('net');
        const s = new net.Socket();
        s.setEncoding('utf8');
        if (s._encoding !== 'utf8') { console.error('enc=', s._encoding); process.exit(2); }
        s.setEncoding(null);
        if (s._encoding !== null) { console.error('reset failed:', s._encoding); process.exit(3); }
        let threw = false;
        try { s.setEncoding('not-a-real-encoding'); } catch (_) { threw = true; }
        if (!threw) { console.error('bad encoding accepted'); process.exit(4); }
        console.log('NET_SETENC_OK');
    "#;
    assert_ok(&run_inline(src), "NET_SETENC_OK");
}

#[test]
#[serial]
fn tls_socket_setEncoding_smoke() {
    let src = r#"
        const tls = require('tls');
        const s = new tls.TLSSocket();
        s.setEncoding('utf8');
        if (s._encoding !== 'utf8') { console.error('enc=', s._encoding); process.exit(2); }
        s.setEncoding(null);
        if (s._encoding !== null) { console.error('reset failed:', s._encoding); process.exit(3); }
        console.log('TLS_SETENC_OK');
    "#;
    assert_ok(&run_inline(src), "TLS_SETENC_OK");
}
