// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `dns.resolveAny` / `resolveCaa` (DNS extras) and
//! `child_process.execFileSync` (Node 0.11.12+).

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
fn dns_resolve_caa_returns_empty_array() {
    let out = run_inline(
        r#"
        const dns = require('dns');
        dns.resolveCaa('example.com', (err, list) => {
            if (!err && Array.isArray(list) && list.length === 0)
                console.log('CAA-OK');
            else console.log('FAIL', err && err.message, list);
        });
        "#,
    );
    assert_marker(&out, "CAA-OK");
}

#[test]
fn dns_resolve_any_returns_combined_records() {
    let out = run_inline(
        r#"
        const dns = require('dns');
        dns.resolveAny('localhost', (err, list) => {
            // We don't insist on a specific number - just that the
            // dispatcher returned without crashing and gave us an array.
            if (Array.isArray(list)) console.log('ANY-OK');
            else console.log('FAIL', err && err.message);
        });
        "#,
    );
    assert_marker(&out, "ANY-OK");
}

#[test]
fn dns_resolve_srv_naptr_ptr_default_empty() {
    let out = run_inline(
        r#"
        const dns = require('dns');
        let pending = 2, ok = true;
        dns.resolveSrv('example.com', (err, list) => {
            if (err || !Array.isArray(list) || list.length !== 0) ok = false;
            if (--pending === 0) console.log(ok ? 'SRV-NAPTR-OK' : 'FAIL');
        });
        dns.resolveNaptr('example.com', (err, list) => {
            if (err || !Array.isArray(list) || list.length !== 0) ok = false;
            if (--pending === 0) console.log(ok ? 'SRV-NAPTR-OK' : 'FAIL');
        });
        "#,
    );
    assert_marker(&out, "SRV-NAPTR-OK");
}

#[test]
fn child_process_exec_file_sync_runs_command() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        const buf = cp.execFileSync('echo', ['hello-burn']);
        if (Buffer.isBuffer(buf) && buf.toString('utf8').trim() === 'hello-burn')
            console.log('EFS-BUF-OK');
        else console.log('FAIL', typeof buf, buf && buf.toString());
        "#,
    );
    assert_marker(&out, "EFS-BUF-OK");
}

#[test]
fn child_process_exec_file_sync_returns_string_with_encoding() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        const s = cp.execFileSync('echo', ['hi'], { encoding: 'utf8' });
        if (typeof s === 'string' && s.trim() === 'hi') console.log('EFS-STR-OK');
        else console.log('FAIL', typeof s, JSON.stringify(s));
        "#,
    );
    assert_marker(&out, "EFS-STR-OK");
}

#[test]
fn child_process_exec_file_sync_throws_on_non_zero_exit() {
    let out = run_inline(
        r#"
        const cp = require('child_process');
        try {
            cp.execFileSync('false', []);
            console.log('FAIL no-throw');
        } catch (e) {
            if (e.status !== 0) console.log('EFS-FAIL-OK');
            else console.log('FAIL', e.status);
        }
        "#,
    );
    assert_marker(&out, "EFS-FAIL-OK");
}
