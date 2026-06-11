// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `tls.checkServerIdentity(hostname, cert)` - verifies a peer cert
//! matches the requested hostname. Returns `undefined` on match, an
//! `Error` with `code: ERR_TLS_CERT_ALTNAME_INVALID` on mismatch.

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
fn check_server_identity_exact_match_returns_undefined() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        const cert = { subjectaltname: 'DNS:example.com' };
        if (tls.checkServerIdentity('example.com', cert) === undefined) console.log('EXACT-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "EXACT-OK");
}

#[test]
fn check_server_identity_wildcard_match() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        const cert = { subjectaltname: 'DNS:*.example.com' };
        if (tls.checkServerIdentity('foo.example.com', cert) === undefined) console.log('WILD-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "WILD-OK");
}

#[test]
fn check_server_identity_mismatch_returns_error_with_code() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        const cert = { subjectaltname: 'DNS:example.com' };
        const r = tls.checkServerIdentity('evil.com', cert);
        if (r instanceof Error && r.code === 'ERR_TLS_CERT_ALTNAME_INVALID') console.log('MISMATCH-OK');
        else console.log('FAIL', r);
        "#,
    );
    assert_marker(&out, "MISMATCH-OK");
}

#[test]
fn check_server_identity_falls_back_to_subject_cn() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        const cert = { subject: { CN: 'fallback.com' } };
        if (tls.checkServerIdentity('fallback.com', cert) === undefined) console.log('CN-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CN-OK");
}

#[test]
fn check_server_identity_no_cert_returns_error() {
    let out = run_inline(
        r#"
        const tls = require('tls');
        const r = tls.checkServerIdentity('example.com', null);
        if (r instanceof Error) console.log('NULL-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "NULL-OK");
}
