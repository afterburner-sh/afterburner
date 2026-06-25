// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `EventSource` (Server-Sent Events client).
//!
//! Polyfill is built on `fetch` - buffered, no streaming. Works for
//! finite SSE responses where the server emits N events then closes.
//! Tests run an in-process SSE server (TcpListener thread) that
//! sends a known event sequence and closes; burn connects, parses,
//! fires `message` / `open` / custom events.

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

/// Run an SSE server that emits `body` once then closes the
/// connection (one accept, one response).
fn run_sse_once(port: u16, body: String) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind sse");
    listener.set_nonblocking(false).ok();
    let (mut s, _) = listener.accept().expect("accept");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    // Read the request preamble so the kernel doesn't RST.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n\
         Content-Length: {len}\r\n\r\n{body}",
        len = body.len(),
        body = body
    );
    let _ = s.write_all(resp.as_bytes());
    let _ = s.shutdown(std::net::Shutdown::Both);
}

#[test]
fn event_source_class_is_constructable_with_constants() {
    let out = run_inline(
        r#"
        if (typeof EventSource !== 'function') { console.log('FAIL no-ctor'); process.exit(1); }
        if (EventSource.CONNECTING !== 0 || EventSource.OPEN !== 1 || EventSource.CLOSED !== 2) {
            console.log('FAIL bad-consts'); process.exit(1);
        }
        var es = new EventSource('http://127.0.0.1:1/');
        if (typeof es.close !== 'function') { console.log('FAIL no-close'); process.exit(1); }
        if (typeof es.addEventListener !== 'function') { console.log('FAIL no-listener'); process.exit(1); }
        es.close();
        if (es.readyState !== EventSource.CLOSED) {
            console.log('FAIL bad-state', es.readyState); process.exit(1);
        }
        console.log('SHAPE-OK');
        "#,
    );
    assert_marker(&out, "SHAPE-OK");
}

#[test]
fn event_source_message_event_fires_on_data_line() {
    let port = pick_port();
    let body = "data: hello\n\ndata: world\n\n".to_string();
    let server = thread::Builder::new()
        .name("sse-once".into())
        .spawn(move || run_sse_once(port, body))
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(50));

    let script = format!(
        r#"
        var seen = [];
        var es = new EventSource('http://127.0.0.1:{port}/sse');
        es.onmessage = (e) => {{
            seen.push(e.data);
            if (seen.length === 2) {{
                if (seen[0] === 'hello' && seen[1] === 'world') console.log('MSG-OK');
                else console.log('FAIL', JSON.stringify(seen));
                es.close();
                process.exit(0);
            }}
        }};
        es.onerror = () => {{ /* ignore reconnect attempts */ }};
        setTimeout(() => {{ console.log('TIMEOUT seen=' + JSON.stringify(seen)); process.exit(1); }}, 5000);
        "#
    );
    let out = run_inline(&script);
    let _ = server.join();
    assert_marker(&out, "MSG-OK");
}

#[test]
fn event_source_named_event_fires_via_add_event_listener() {
    let port = pick_port();
    let body = "event: ping\ndata: 1\n\nevent: ping\ndata: 2\n\n".to_string();
    let server = thread::Builder::new()
        .name("sse-named".into())
        .spawn(move || run_sse_once(port, body))
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(50));

    let script = format!(
        r#"
        var seen = [];
        var es = new EventSource('http://127.0.0.1:{port}/sse');
        es.addEventListener('ping', (e) => {{
            seen.push(e.data);
            if (seen.length === 2) {{
                if (seen[0] === '1' && seen[1] === '2') console.log('NAMED-OK');
                else console.log('FAIL', seen.join(','));
                es.close();
                process.exit(0);
            }}
        }});
        es.onerror = () => {{}};
        setTimeout(() => {{ console.log('TIMEOUT'); process.exit(1); }}, 5000);
        "#
    );
    let out = run_inline(&script);
    let _ = server.join();
    assert_marker(&out, "NAMED-OK");
}

#[test]
fn event_source_multiline_data_field_concatenates() {
    let port = pick_port();
    let body = "data: line1\ndata: line2\ndata: line3\n\n".to_string();
    let server = thread::Builder::new()
        .name("sse-multi".into())
        .spawn(move || run_sse_once(port, body))
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(50));

    let script = format!(
        r#"
        var es = new EventSource('http://127.0.0.1:{port}/sse');
        es.onmessage = (e) => {{
            if (e.data === 'line1\nline2\nline3') console.log('MULTI-OK');
            else console.log('FAIL', JSON.stringify(e.data));
            es.close();
            process.exit(0);
        }};
        es.onerror = () => {{}};
        setTimeout(() => {{ console.log('TIMEOUT'); process.exit(1); }}, 5000);
        "#
    );
    let out = run_inline(&script);
    let _ = server.join();
    assert_marker(&out, "MULTI-OK");
}

#[test]
fn event_source_id_field_updates_last_event_id() {
    let port = pick_port();
    let body = "id: 42\nevent: tick\ndata: ok\n\n".to_string();
    let server = thread::Builder::new()
        .name("sse-id".into())
        .spawn(move || run_sse_once(port, body))
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(50));

    let script = format!(
        r#"
        var es = new EventSource('http://127.0.0.1:{port}/sse');
        es.addEventListener('tick', (e) => {{
            if (e.lastEventId === '42') console.log('ID-OK');
            else console.log('FAIL', e.lastEventId);
            es.close();
            process.exit(0);
        }});
        es.onerror = () => {{}};
        setTimeout(() => {{ console.log('TIMEOUT'); process.exit(1); }}, 5000);
        "#
    );
    let out = run_inline(&script);
    let _ = server.join();
    assert_marker(&out, "ID-OK");
}
