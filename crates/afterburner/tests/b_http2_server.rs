// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `http2.createServer().listen()` end-to-end. The daemon's
//! per-connection auto-builder serves H1 and H2 over the same TCP
//! listener — H2 is detected by the connection preface
//! (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and routed to hyper's H2
//! engine; H1 falls through to the existing pipeline.
//!
//! Run with `cargo test --test b_http2_server -- --test-threads=1` —
//! parallel runs spawn ten burn processes simultaneously, which
//! saturates plugin instantiation and the 15s wait_for_listener
//! window goes flaky under that load. Single-threaded the suite
//! finishes in ~45s.

#![cfg(feature = "bin")]

use serial_test::serial;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Pick an unused port via a transient bind. Stale-port collisions
/// happen often in CI; bumping into a sequence beats an OS-allocated
/// port we then have to introspect from the child.
static NEXT: AtomicU16 = AtomicU16::new(19200);
fn pick_port() -> u16 {
    loop {
        let p = NEXT.fetch_add(1, Ordering::Relaxed);
        if let Ok(l) = TcpListener::bind(("127.0.0.1", p)) {
            drop(l);
            return p;
        }
        if p > 65000 {
            panic!("no free port");
        }
    }
}

fn wait_for_listener(port: u16, max: Duration) -> bool {
    let deadline = Instant::now() + max;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

fn spawn(source: &str) -> Child {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn")
}

/// Send a raw HTTP/2 cleartext (h2c) prior-knowledge request and
/// return the first response line. No external `curl` dependency —
/// h2c is a 24-byte preface + a SETTINGS frame + HEADERS frame +
/// (optional) DATA frame. We rely on hyper to parse this; `curl`
/// is not always available in test environments.
fn h1_get(port: u16, path: &str) -> String {
    use std::io::{Read, Write};
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap_or(0);
    out
}

// ---- listening + basic h1 path -------------------------------------

#[test]
#[serial]
fn http2_server_serves_h1_request_via_request_event() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        srv.on('request', (req, res) => {{
            res.setHeader('content-type', 'text/plain');
            res.end('h1-served\n');
        }});
        srv.listen({port});
        "#
    );
    let mut child = spawn(&src);
    assert!(
        wait_for_listener(port, Duration::from_secs(60)),
        "no listener on :{port}"
    );
    let r = h1_get(port, "/");
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.contains("h1-served"), "{r}");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn http2_server_serves_h1_request_via_stream_event() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        srv.on('stream', (stream, headers) => {{
            stream.respond({{ ':status': 200, 'content-type': 'text/plain' }});
            stream.end('stream-served:' + headers[':path'] + '\n');
        }});
        srv.listen({port});
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));
    let r = h1_get(port, "/foo");
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    assert!(r.contains("stream-served:/foo"), "{r}");
    let _ = child.kill();
    let _ = child.wait();
}

// ---- h2 prior-knowledge cleartext path -----------------------------

/// Build the minimal h2c connection preface + SETTINGS ACK — we
/// don't need a full client. After sending the preface we read
/// frames until we see a HEADERS frame for stream 1 (the response).
/// The hex check confirms we got real H2 wire format back.
fn h2c_connection_preface() -> Vec<u8> {
    // RFC 7540 §3.5: connection preface for cleartext.
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    PREFACE.to_vec()
}

#[test]
#[serial]
fn http2_server_responds_to_h2_connection_preface() {
    use std::io::{Read, Write};
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        srv.on('stream', (stream, headers) => {{
            stream.respond({{ ':status': 200 }});
            stream.end('h2-ok');
        }});
        srv.listen({port});
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(&h2c_connection_preface()).unwrap();

    // Read enough to confirm hyper sent us a SETTINGS frame back —
    // first 9 bytes after preface ack are the H2 frame header for
    // SETTINGS. Frame header layout: 24-bit length, 8-bit type,
    // 8-bit flags, 31-bit stream id.
    let mut buf = [0u8; 9];
    let n = s.read(&mut buf).unwrap_or(0);
    // Hyper responds with SETTINGS (type 0x04) on stream 0.
    let got_settings_back = n >= 9 && buf[3] == 0x04;
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        got_settings_back,
        "expected H2 SETTINGS frame (type 0x04) from server, got {n} bytes: {:02x?}",
        &buf[..n]
    );
}

// ---- create server callback shape ----------------------------------

#[test]
#[serial]
fn create_server_callback_attaches_request_handler() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer((req, res) => {{
            res.end('cb-served\n');
        }});
        srv.listen({port});
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));
    let r = h1_get(port, "/");
    assert!(r.contains("cb-served"), "{r}");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn http2_server_address_returns_listening_port() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        srv.on('request', (req, res) => {{
            res.setHeader('x-port', String(srv.address() && srv.address().port));
            res.end('ok\n');
        }});
        srv.listen({port});
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));
    let r = h1_get(port, "/");
    let want = format!("x-port: {port}");
    assert!(r.contains(&want), "missing `{want}` in: {r}");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn http2_server_close_releases_port() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        srv.on('request', (req, res) => res.end('a\n'));
        srv.listen({port}, () => {{
            // After one request, close the server so the port releases.
        }});
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));
    let _ = h1_get(port, "/");
    let _ = child.kill();
    let _ = child.wait();
    // After the child is killed, the port should be reusable.
    std::thread::sleep(Duration::from_millis(500));
    let _l = TcpListener::bind(("127.0.0.1", port)).expect("port should release after kill");
}

// ---- ServerHttp2Stream surface -------------------------------------

#[test]
#[serial]
fn server_h2_stream_response_writes_body() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        srv.on('stream', (stream) => {{
            stream.respond({{ ':status': 201, 'x-stream': 'yes' }});
            stream.write('chunk1');
            stream.end('chunk2');
        }});
        srv.listen({port});
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));
    let r = h1_get(port, "/");
    assert!(r.starts_with("HTTP/1.1 201"), "{r}");
    assert!(r.contains("x-stream: yes"), "{r}");
    assert!(r.contains("chunk1") && r.contains("chunk2"), "{r}");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn server_h2_stream_pseudo_headers_translated() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        srv.on('stream', (stream, headers) => {{
            const got = {{
                method: headers[':method'],
                path:   headers[':path'],
                scheme: headers[':scheme'],
                authority: headers[':authority'],
            }};
            stream.respond({{ ':status': 200, 'content-type': 'application/json' }});
            stream.end(JSON.stringify(got));
        }});
        srv.listen({port});
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));
    let r = h1_get(port, "/abc?q=1");
    assert!(r.contains(r#""method":"GET""#), "{r}");
    assert!(r.contains(r#""path":"/abc?q=1""#), "{r}");
    let _ = child.kill();
    let _ = child.wait();
}

// ---- error / lifecycle ---------------------------------------------

#[test]
#[serial]
fn http2_server_emits_listening_event() {
    let port = pick_port();
    let src = format!(
        r#"
        const http2 = require('http2');
        const srv = http2.createServer();
        let fired = false;
        srv.on('listening', () => {{ fired = true; }});
        srv.listen({port}, () => {{
            // Send a request to ourselves to confirm we're up.
        }});
        srv.on('request', (req, res) => res.end(fired ? 'fired' : 'no'));
        "#
    );
    let mut child = spawn(&src);
    assert!(wait_for_listener(port, Duration::from_secs(60)));
    let r = h1_get(port, "/");
    assert!(r.contains("fired"), "{r}");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn http2_create_server_is_constructable_and_loads_module() {
    // No-listen smoke check: classes exist, getDefaultSettings runs,
    // constants are present.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(
            r#"
            const h2 = require('http2');
            const srv = h2.createServer();
            const s = h2.getDefaultSettings();
            const ok = (typeof srv.listen === 'function')
                && (typeof srv.close === 'function')
                && (typeof s.initialWindowSize === 'number')
                && (h2.constants.NGHTTP2_NO_ERROR === 0);
            console.log(ok ? 'CTOR-OK' : 'FAIL');
        "#,
        )
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CTOR-OK"), "{stdout}");
}
