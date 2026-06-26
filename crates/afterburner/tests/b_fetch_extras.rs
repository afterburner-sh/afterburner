// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Fetch surface fills: `Headers.prototype.getSetCookie` (Node 19+),
//! `Response.json` / `error` / `redirect` (Node 18.0+).

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
fn headers_get_set_cookie_splits_into_array() {
    let out = run_inline(
        r#"
        const h = new Headers();
        h.append('Set-Cookie', 'a=1; Path=/');
        h.append('Set-Cookie', 'b=2; Secure');
        const arr = h.getSetCookie();
        if (arr.length === 2 && arr[0] === 'a=1; Path=/' && arr[1] === 'b=2; Secure')
            console.log('SETCOOKIE-OK');
        else console.log('FAIL', JSON.stringify(arr));
        "#,
    );
    assert_marker(&out, "SETCOOKIE-OK");
}

#[test]
fn headers_get_set_cookie_preserves_internal_commas_in_expires() {
    let out = run_inline(
        r#"
        const h = new Headers();
        h.append('Set-Cookie', 'sid=abc; Expires=Wed, 09 Jun 2021 10:18:14 GMT');
        h.append('Set-Cookie', 'theme=dark');
        const arr = h.getSetCookie();
        if (arr.length === 2 && arr[0].indexOf('Expires=Wed') >= 0 && arr[1] === 'theme=dark')
            console.log('EXPIRES-OK');
        else console.log('FAIL', JSON.stringify(arr));
        "#,
    );
    assert_marker(&out, "EXPIRES-OK");
}

#[test]
fn headers_keys_values_iterate_match_entries() {
    let out = run_inline(
        r#"
        const h = new Headers({ 'X-A': '1', 'X-B': '2' });
        const keys = []; const it = h.keys();
        let r = it.next();
        while (!r.done) { keys.push(r.value); r = it.next(); }
        if (keys.includes('x-a') && keys.includes('x-b')) console.log('ITER-OK');
        else console.log('FAIL', JSON.stringify(keys));
        "#,
    );
    assert_marker(&out, "ITER-OK");
}

#[test]
fn response_json_static_emits_content_type() {
    let out = run_inline(
        r#"
        async function main() {
            const r = Response.json({ a: 1 }, { status: 201 });
            if (r.status !== 201) { console.log('FAIL status'); return; }
            if (r.headers.get('content-type') !== 'application/json') {
                console.log('FAIL ct', r.headers.get('content-type')); return;
            }
            const obj = await r.json();
            if (obj.a === 1) console.log('JSON-STATIC-OK');
            else console.log('FAIL body');
        }
        main();
        "#,
    );
    assert_marker(&out, "JSON-STATIC-OK");
}

#[test]
fn response_redirect_validates_status_range() {
    let out = run_inline(
        r#"
        const ok = Response.redirect('https://x.com', 308);
        if (ok.status !== 308 || ok.headers.get('location') !== 'https://x.com') {
            console.log('FAIL valid', ok.status, ok.headers.get('location'));
            process.exit(1);
        }
        try {
            Response.redirect('https://x.com', 200);
            console.log('FAIL no-throw');
            process.exit(1);
        } catch (_) { console.log('REDIRECT-OK'); }
        "#,
    );
    assert_marker(&out, "REDIRECT-OK");
}

#[test]
fn response_error_synthesises_zero_status() {
    let out = run_inline(
        r#"
        const r = Response.error();
        if (r.status === 0 && r.type === 'error') console.log('ERR-OK');
        else console.log('FAIL', r.status, r.type);
        "#,
    );
    assert_marker(&out, "ERR-OK");
}
