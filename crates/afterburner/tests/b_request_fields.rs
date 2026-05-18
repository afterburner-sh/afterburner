// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `Request` constructor fields: redirect / cache / credentials /
//! mode / referrer / referrerPolicy / integrity / keepalive +
//! Request(req) clone shape.

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
fn request_default_fields_match_spec() {
    let out = run_inline(
        r#"
        const r = new Request('http://x.com');
        if (r.redirect === 'follow' && r.cache === 'default' && r.credentials === 'same-origin'
            && r.mode === 'cors' && r.method === 'GET' && r.keepalive === false)
            console.log('DEF-OK');
        else console.log('FAIL', JSON.stringify({
            redirect: r.redirect, cache: r.cache, creds: r.credentials, mode: r.mode,
            method: r.method, keepalive: r.keepalive,
        }));
        "#,
    );
    assert_marker(&out, "DEF-OK");
}

#[test]
fn request_init_overrides_defaults() {
    let out = run_inline(
        r#"
        const r = new Request('http://x.com', {
            method: 'POST',
            redirect: 'manual',
            credentials: 'include',
            mode: 'no-cors',
            cache: 'reload',
            integrity: 'sha256-x',
            keepalive: true,
        });
        if (r.method === 'POST' && r.redirect === 'manual' && r.credentials === 'include' &&
            r.mode === 'no-cors' && r.cache === 'reload' && r.integrity === 'sha256-x' &&
            r.keepalive === true) console.log('OVR-OK');
        else console.log('FAIL', JSON.stringify(r));
        "#,
    );
    assert_marker(&out, "OVR-OK");
}

#[test]
fn request_clone_via_constructor() {
    let out = run_inline(
        r#"
        const orig = new Request('http://x.com', { redirect: 'error', credentials: 'omit' });
        const cloned = new Request(orig);
        if (cloned.url === orig.url && cloned.redirect === 'error' && cloned.credentials === 'omit')
            console.log('CLONE-CTOR-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CLONE-CTOR-OK");
}

#[test]
fn request_clone_method_returns_separate_instance() {
    let out = run_inline(
        r#"
        const r = new Request('http://x.com', { redirect: 'manual' });
        const r2 = r.clone();
        if (r !== r2 && r2.redirect === 'manual' && r2.url === r.url) console.log('CLONE-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CLONE-OK");
}

#[test]
fn request_init_overlay_on_request_input_works() {
    let out = run_inline(
        r#"
        const orig = new Request('http://x.com', { redirect: 'manual' });
        const overlay = new Request(orig, { redirect: 'follow', method: 'POST' });
        if (overlay.url === 'http://x.com' && overlay.redirect === 'follow' && overlay.method === 'POST')
            console.log('OVERLAY-OK');
        else console.log('FAIL', overlay.redirect, overlay.method);
        "#,
    );
    assert_marker(&out, "OVERLAY-OK");
}
