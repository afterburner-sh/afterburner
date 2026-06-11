// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Async outbound HTTP — `__host_http_request_async` end-to-end.
//!
//! The wasm side dispatches the request through Tokio (no
//! wasm-thread blocking), and the response comes back through the
//! shard event loop as a `daemon-event` of kind `http-response`,
//! which resolves the matching `globalThis.__ab_http_pending`
//! Promise. This is what makes `await fetch(url)` and the
//! `req.on('response', …)` callback contract work without the
//! wasm thread serialising the round-trip.
//!
//! These tests pin the contract that real Node-shape libraries
//! (npm's `make-fetch-happen` / `minipass-fetch`, undici,
//! node-fetch, pacote) need to actually progress: the JS-side
//! `await fetch(url)` returns a Promise that *only* resolves when
//! real async work completes, and the daemon stays alive until the
//! response has been delivered.

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
fn fetch_resolves_promise_after_script_body_returns() {
    // The canonical "real async" check — the script body returns
    // immediately; the fetch Promise's resolution has to come from
    // the daemon dispatching a host-side response event. If the
    // daemon exits the moment the user fn returns (the pre-async
    // bug), the inner `console.log('OK', …)` never fires.
    let out = run_inline(
        r#"
        async function main() {
            const res = await fetch('http://example.com/');
            console.log('OK status', res.status);
        }
        main().catch(e => { console.log('FAIL:', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "OK status 200");
}

#[test]
fn http_request_event_response_callback_fires() {
    // Same posture but via the canonical `req.on('response', cb)`
    // event. minipass-fetch / pacote register on this event after
    // the synchronous `request()` call returns; the daemon must
    // hold the loop open until the host signals completion.
    let out = run_inline(
        r#"
        const http = require('http');
        const req = http.request('http://example.com/', { method: 'GET' });
        req.on('response', res => {
            console.log('RESP', res.statusCode);
        });
        req.on('error', e => { console.log('ERR', e.message); process.exit(1); });
        req.end();
        "#,
    );
    assert_marker(&out, "RESP 200");
}

#[test]
fn http_request_callback_form_fires() {
    // `http.request(url, cb)` / `http.get(url, cb)` — the cb-style
    // entry point. Cb fires with a synthetic IncomingMessage; we
    // assert the response object exposes the readable-stream
    // surface so downstream stream consumers (Minipass, native fs
    // pipe, etc.) keep working.
    let out = run_inline(
        r#"
        const http = require('http');
        http.get('http://example.com/', res => {
            if (typeof res.on !== 'function') {
                console.log('NO-EE'); process.exit(1);
            }
            if (typeof res.pipe !== 'function') {
                console.log('NO-PIPE'); process.exit(1);
            }
            let bytes = 0;
            res.on('data', chunk => { bytes += (chunk && chunk.length) ? chunk.length : 0; });
            res.on('end', () => console.log('DONE bytes >0:', bytes > 0));
        }).on('error', e => { console.log('ERR', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "DONE bytes >0: true");
}

#[test]
fn parallel_fetches_complete_concurrently() {
    // Three concurrent fetches should take roughly the time of one
    // round-trip — proof the host side dispatches each on its own
    // Tokio task instead of serialising them on the wasm thread.
    // The JS side self-times the parallel-fetch window (excluding
    // burn cold-start) and prints the elapsed millis. Measuring
    // outside burn would conflate cold-start time with dispatch
    // time and flake under cross-binary CPU pressure.
    let out = run_inline(
        r#"
        async function main() {
            const urls = ['http://example.com/', 'http://example.org/', 'http://example.net/'];
            const t0 = Date.now();
            const r = await Promise.all(urls.map(u => fetch(u).then(x => x.status)));
            const elapsed = Date.now() - t0;
            console.log('STATUSES', r.join(','));
            console.log('FETCH_MS', elapsed);
        }
        main().catch(e => { console.log('FAIL:', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "STATUSES 200,200,200");
    // Under serial dispatch (3 round-trips × ~300ms each) the total
    // would push past 1s. Parallel dispatch is bounded by the slowest
    // single fetch (~300-500ms on a healthy network). 4s is a generous
    // ceiling that still catches a structural regression to serial
    // dispatch (which would be 3-15s depending on network latency).
    let stdout = String::from_utf8_lossy(&out.stdout);
    let fetch_ms: u64 = stdout
        .lines()
        .find_map(|l| l.strip_prefix("FETCH_MS "))
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("FETCH_MS missing from stdout:\n{stdout}"));
    assert!(
        fetch_ms < 4000,
        "parallel fetches took too long; possible regression to serial dispatch ({fetch_ms}ms)"
    );
}

#[test]
fn fetch_response_text_returns_full_body() {
    // The Response.text() Promise has to settle with the full body
    // — early bug rounds had it resolve with the bogus
    // `__HOST_ERR__:` string when the body was empty, or with an
    // empty Buffer because the host's UTF-8 lossy decode dropped
    // the bytes. Pin the contract.
    let out = run_inline(
        r#"
        async function main() {
            const res = await fetch('http://example.com/');
            const t = await res.text();
            if (typeof t !== 'string') {
                console.log('NOT-STRING'); process.exit(1);
            }
            // example.com is consistently ~1KB of HTML.
            console.log('TEXT-LEN', t.length > 100 ? 'big' : ('small=' + t.length));
        }
        main().catch(e => { console.log('FAIL:', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "TEXT-LEN big");
}

#[test]
fn https_fetch_resolves_through_async_path() {
    // TLS path uses the same `__host_http_request_async` indirection
    // but the host's reqwest backend handles the rustls handshake.
    // Ensures the cert chain isn't a pre-flight failure.
    let out = run_inline(
        r#"
        async function main() {
            const res = await fetch('https://example.com/');
            console.log('TLS-OK', res.status);
        }
        main().catch(e => { console.log('FAIL:', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "TLS-OK 200");
}
