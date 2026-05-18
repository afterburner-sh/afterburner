// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `http2.connect` → `session.request` → stream events. Wired
//! against the same async outbound HTTP path fetch / http.request
//! use, so the same `:method` / `:path` / `:scheme` / `:authority`
//! pseudo-header shape works without negotiating real h2 ALPN at
//! the JS layer.

#![cfg(feature = "bin")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;

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

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Tiny single-connection HTTP/1.1 echo server — we accept one
/// request, send a 200 with a body that includes the
/// `:path` value the burn-side h2 polyfill translated.
fn run_echo_server(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind echo");
    let (mut s, _) = listener.accept().expect("accept");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let body = format!("hello-from-test path={path}");
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {len}\r\n\
         X-Test: round-trip\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len()
    );
    let _ = s.write_all(resp.as_bytes());
    let _ = s.shutdown(std::net::Shutdown::Both);
}

#[test]
fn http2_connect_session_emits_connect_event() {
    let out = run_inline(
        r#"
        const http2 = require('http2');
        const s = http2.connect('https://x.invalid');
        s.on('connect', () => { console.log('CONNECT-OK'); s.destroy(); process.exit(0); });
        setTimeout(() => process.exit(1), 1000);
        "#,
    );
    assert_marker(&out, "CONNECT-OK");
}

#[test]
fn http2_session_request_round_trips_against_local_server() {
    let port = pick_port();
    let server = thread::Builder::new()
        .name("h2-echo".into())
        .spawn(move || run_echo_server(port))
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(50));

    let script = format!(
        r#"
        const http2 = require('http2');
        const s = http2.connect('http://127.0.0.1:{port}');
        s.on('connect', () => {{
            const req = s.request({{
                ':method': 'GET',
                ':path': '/world',
                ':scheme': 'http',
            }});
            let body = '';
            let h = null;
            req.on('response', headers => {{ h = headers; }});
            req.on('data', c => {{ body += c.toString('utf8'); }});
            req.on('end', () => {{
                if (h && h[':status'] === 200 && body.indexOf('path=/world') >= 0)
                    console.log('H2-OK');
                else console.log('FAIL', h && h[':status'], body);
                s.destroy();
                process.exit(0);
            }});
            req.on('error', e => {{ console.log('ERR', e.message); process.exit(1); }});
            req.end();
        }});
        s.on('error', e => {{ console.log('SERR', e.message); process.exit(1); }});
        setTimeout(() => {{ console.log('TIMEOUT'); process.exit(1); }}, 5000);
        "#
    );
    let out = run_inline(&script);
    let _ = server.join();
    assert_marker(&out, "H2-OK");
}

#[test]
fn http2_session_ping_invokes_callback() {
    let out = run_inline(
        r#"
        const http2 = require('http2');
        const s = http2.connect('https://x.invalid');
        s.on('connect', () => {
            s.ping((err, duration, payload) => {
                if (!err && typeof duration === 'number' && payload) console.log('PING-OK');
                else console.log('FAIL');
                s.destroy();
                process.exit(0);
            });
        });
        setTimeout(() => process.exit(1), 1000);
        "#,
    );
    assert_marker(&out, "PING-OK");
}

#[test]
fn http2_constants_match_canonical_names() {
    let out = run_inline(
        r#"
        const http2 = require('http2');
        const c = http2.constants;
        if (c.HTTP2_HEADER_METHOD === ':method' && c.HTTP2_HEADER_PATH === ':path' &&
            c.HTTP2_HEADER_STATUS === ':status' && c.NGHTTP2_NO_ERROR === 0)
            console.log('CONST-OK');
        else console.log('FAIL');
        "#,
    );
    assert_marker(&out, "CONST-OK");
}

#[test]
fn http2_get_default_settings_returns_node_defaults() {
    let out = run_inline(
        r#"
        const http2 = require('http2');
        const s = http2.getDefaultSettings();
        if (s.headerTableSize === 4096 && s.initialWindowSize === 65535 &&
            s.maxFrameSize === 16384) console.log('DEF-OK');
        else console.log('FAIL', s);
        "#,
    );
    assert_marker(&out, "DEF-OK");
}

#[test]
fn http2_create_secure_server_returns_listenable_server() {
    // `http2.createSecureServer` delegates to createServer (TLS
    // termination happens daemon-side via ALPN). The returned Server
    // exposes `.listen` / `.close` / `.on('request', …)` like the
    // cleartext http2 server. Pin the working surface — earlier
    // rounds threw `ERR_HTTP2_NOT_IMPLEMENTED`; that's no longer the
    // case once `createSecureServer` was wired through.
    let out = run_inline(
        r#"
        const http2 = require('http2');
        const srv = http2.createSecureServer();
        if (
            srv &&
            typeof srv.listen === 'function' &&
            typeof srv.close === 'function' &&
            typeof srv.on === 'function'
        ) console.log('SERVER-OK');
        else console.log('FAIL shape');
        "#,
    );
    assert_marker(&out, "SERVER-OK");
}
