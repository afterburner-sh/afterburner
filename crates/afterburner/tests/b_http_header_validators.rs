// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `http.validateHeaderName` / `validateHeaderValue` (Node 14.3+),
//! `http.setMaxIdleHTTPParsers` (Node 18.8+), and `http.WebSocket`
//! alias (Node 22+).

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
fn validate_header_name_accepts_canonical_token() {
    let out = run_inline(
        r#"
        const http = require('http');
        try {
            http.validateHeaderName('Content-Type');
            http.validateHeaderName('X-Custom-Header_42');
            console.log('VHN-OK');
        } catch (e) { console.log('FAIL', e.message); }
        "#,
    );
    assert_marker(&out, "VHN-OK");
}

#[test]
fn validate_header_name_rejects_invalid_chars() {
    let out = run_inline(
        r#"
        const http = require('http');
        try { http.validateHeaderName('bad header'); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_INVALID_HTTP_TOKEN') console.log('VHN-REJ-OK'); else console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "VHN-REJ-OK");
}

#[test]
fn validate_header_name_rejects_empty() {
    let out = run_inline(
        r#"
        const http = require('http');
        try { http.validateHeaderName(''); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_INVALID_HTTP_TOKEN') console.log('VHN-EMPTY-OK'); else console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "VHN-EMPTY-OK");
}

#[test]
fn validate_header_value_rejects_crlf() {
    let out = run_inline(
        r#"
        const http = require('http');
        try { http.validateHeaderValue('X-Hdr', 'foo\r\nbar'); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_INVALID_CHAR') console.log('VHV-CR-OK'); else console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "VHV-CR-OK");
}

#[test]
fn validate_header_value_rejects_undefined() {
    let out = run_inline(
        r#"
        const http = require('http');
        try { http.validateHeaderValue('X-Hdr', undefined); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_HTTP_INVALID_HEADER_VALUE') console.log('VHV-UNDEF-OK'); else console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "VHV-UNDEF-OK");
}

#[test]
fn validate_header_value_accepts_normal_value() {
    let out = run_inline(
        r#"
        const http = require('http');
        try {
            http.validateHeaderValue('X-Hdr', 'hello-world');
            http.validateHeaderValue('X-Hdr', 42);
            console.log('VHV-OK');
        } catch (e) { console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "VHV-OK");
}

#[test]
fn set_max_idle_http_parsers_accepts_positive_integer() {
    let out = run_inline(
        r#"
        const http = require('http');
        http.setMaxIdleHTTPParsers(500);
        console.log('SMIHP-OK');
        "#,
    );
    assert_marker(&out, "SMIHP-OK");
}

#[test]
fn set_max_idle_http_parsers_rejects_zero() {
    let out = run_inline(
        r#"
        const http = require('http');
        try { http.setMaxIdleHTTPParsers(0); console.log('FAIL no-throw'); }
        catch (e) { if (e.code === 'ERR_OUT_OF_RANGE') console.log('SMIHP-REJ-OK'); else console.log('FAIL', e.code); }
        "#,
    );
    assert_marker(&out, "SMIHP-REJ-OK");
}

#[test]
fn http_websocket_alias_matches_global() {
    let out = run_inline(
        r#"
        const http = require('http');
        if (http.WebSocket === globalThis.WebSocket) console.log('HTTP-WS-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "HTTP-WS-OK");
}
