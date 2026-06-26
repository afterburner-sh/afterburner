// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! WebSocket client (RFC 6455) - JS-on-net implementation tests.
//!
//! Two layers:
//!
//! 1. **Shape tests** (always run): constructor exists, exposes the
//!    canonical readyState constants, accepts events, encodes /
//!    decodes frames correctly. No network - pure JS exercise.
//!
//! 2. **Round-trip tests**: a hand-rolled Rust WebSocket echo server
//!    runs as a thread inside the Rust test process, bound to
//!    `127.0.0.1:<dynamic>`. burn connects via the WebSocket polyfill,
//!    sends frames, reads echo, closes. Uses workspace `sha1` +
//!    `base64` deps for the handshake - no `tungstenite` / external
//!    WebSocket lib needed.

#![cfg(feature = "bin")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
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

// ---- Shape tests ----------------------------------------------------

#[test]
fn websocket_constructor_and_constants_exposed() {
    let out = run_inline(
        r#"
        if (typeof WebSocket !== 'function') { console.log('FAIL no-ctor'); process.exit(1); }
        if (WebSocket.CONNECTING !== 0 || WebSocket.OPEN !== 1 ||
            WebSocket.CLOSING !== 2 || WebSocket.CLOSED !== 3) {
            console.log('FAIL bad-consts'); process.exit(1);
        }
        // Construct against a definitely-unreachable port so we don't
        // wait on the network. The constructor + readyState should
        // still expose the right shape immediately.
        var ws = new WebSocket('ws://127.0.0.1:1');
        if (ws.readyState !== WebSocket.CONNECTING && ws.readyState !== WebSocket.CLOSED) {
            console.log('FAIL bad-state', ws.readyState); process.exit(1);
        }
        if (typeof ws.send !== 'function' || typeof ws.close !== 'function') {
            console.log('FAIL bad-methods'); process.exit(1);
        }
        if (typeof ws.addEventListener !== 'function' ||
            typeof ws.removeEventListener !== 'function') {
            console.log('FAIL bad-events'); process.exit(1);
        }
        // Force-close so the burn process exits without hanging on the
        // pending socket.
        ws.close();
        console.log('SHAPE-OK');
        "#,
    );
    assert_marker(&out, "SHAPE-OK");
}

#[test]
fn websocket_url_parses_and_assigns_protocol() {
    let out = run_inline(
        r#"
        var ws = new WebSocket('ws://127.0.0.1:1/path?q=1', ['v1', 'v2']);
        if (ws.url !== 'ws://127.0.0.1:1/path?q=1') {
            console.log('FAIL url', ws.url); process.exit(1);
        }
        // Pre-open the protocol field is ''; we just check it exists.
        if (typeof ws.protocol !== 'string') { console.log('FAIL proto'); process.exit(1); }
        ws.close();
        console.log('URL-OK');
        "#,
    );
    assert_marker(&out, "URL-OK");
}

// ---- Round-trip tests (live in-process echo server) -----------------

static PORT_CTR: AtomicU16 = AtomicU16::new(0);
fn pick_port() -> u16 {
    // Bind to port 0, take the OS-assigned port, drop the listener.
    // Then tell the spawned echo thread to bind that exact port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let _ = PORT_CTR.fetch_add(1, Ordering::Relaxed);
    port
}

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn ws_accept_key(client_key: &str) -> String {
    use base64::Engine;
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Run a single-connection WebSocket echo server on `port` and return
/// once the client sends a close. Reads ONE text frame, echoes it
/// back as a text frame, then handles the close handshake. Server
/// frames are NOT masked (per RFC 6455).
fn run_echo_server(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind echo server");
    listener.set_nonblocking(false).ok();
    let (mut stream, _addr) = listener.accept().expect("accept");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    // ---- handshake ----
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut tmp).expect("read handshake");
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let (_, key) = head
        .lines()
        .find_map(|line| {
            let mut sp = line.splitn(2, ':');
            let name = sp.next()?.trim();
            let value = sp.next()?.trim();
            if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                Some(("", value.to_string()))
            } else {
                None
            }
        })
        .expect("Sec-WebSocket-Key");
    let accept = ws_accept_key(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .expect("write handshake");

    // ---- read one frame ----
    fn read_frame(stream: &mut TcpStream) -> (u8, Vec<u8>, bool) {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).expect("frame hdr");
        let fin = (hdr[0] & 0x80) != 0;
        let opcode = hdr[0] & 0x0F;
        let masked = (hdr[1] & 0x80) != 0;
        let mut len = (hdr[1] & 0x7F) as usize;
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).unwrap();
            len = ((ext[0] as usize) << 8) | (ext[1] as usize);
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).unwrap();
            len = ((ext[4] as usize) << 24)
                | ((ext[5] as usize) << 16)
                | ((ext[6] as usize) << 8)
                | (ext[7] as usize);
        }
        let mask = if masked {
            let mut m = [0u8; 4];
            stream.read_exact(&mut m).unwrap();
            Some(m)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).unwrap();
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }
        (opcode, payload, fin)
    }
    let (opcode, payload, _fin) = read_frame(&mut stream);
    // Echo back as same-opcode frame, no mask.
    fn write_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) {
        let mut hdr = vec![0x80 | opcode];
        if payload.len() < 126 {
            hdr.push(payload.len() as u8);
        } else if payload.len() < 65536 {
            hdr.push(126);
            hdr.push(((payload.len() >> 8) & 0xFF) as u8);
            hdr.push((payload.len() & 0xFF) as u8);
        } else {
            hdr.push(127);
            for i in (0..8).rev() {
                hdr.push(((payload.len() >> (i * 8)) & 0xFF) as u8);
            }
        }
        stream.write_all(&hdr).unwrap();
        stream.write_all(payload).unwrap();
    }
    write_frame(&mut stream, opcode, &payload);
    // Wait for client close (opcode 0x8); echo close back.
    let (close_opcode, close_payload, _) = read_frame(&mut stream);
    if close_opcode == 0x8 {
        write_frame(&mut stream, 0x8, &close_payload);
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[test]
fn websocket_text_round_trip_against_local_echo() {
    let port = pick_port();
    let server = thread::Builder::new()
        .name("ws-echo".into())
        .spawn(move || run_echo_server(port))
        .unwrap();

    // Give the OS a moment to take the bind back.
    thread::sleep(std::time::Duration::from_millis(50));

    let script = format!(
        r#"
        var ws = new WebSocket('ws://127.0.0.1:{port}/');
        ws.onopen = function() {{ ws.send('hello-burn'); }};
        ws.onmessage = function(e) {{
            if (e.data === 'hello-burn') console.log('ECHO-OK');
            else console.log('FAIL', JSON.stringify(e.data));
            ws.close(1000, 'bye');
        }};
        ws.onclose = function() {{ process.exit(0); }};
        setTimeout(() => {{ console.log('TIMEOUT'); process.exit(1); }}, 5000);
        "#
    );
    let out = run_inline(&script);
    server.join().expect("echo server thread");
    assert_marker(&out, "ECHO-OK");
}

#[test]
fn websocket_binary_round_trip_with_arraybuffer() {
    let port = pick_port();
    let server = thread::Builder::new()
        .name("ws-echo-bin".into())
        .spawn(move || run_echo_server(port))
        .unwrap();
    thread::sleep(std::time::Duration::from_millis(50));

    let script = format!(
        r#"
        var ws = new WebSocket('ws://127.0.0.1:{port}/');
        ws.binaryType = 'arraybuffer';
        ws.onopen = function() {{
            var ab = new ArrayBuffer(4);
            var view = new Uint8Array(ab);
            view[0]=1; view[1]=2; view[2]=3; view[3]=255;
            ws.send(view);
        }};
        ws.onmessage = function(e) {{
            if (!(e.data instanceof ArrayBuffer)) {{
                console.log('FAIL not-ab', typeof e.data); ws.close(); return;
            }}
            var v = new Uint8Array(e.data);
            if (v.length === 4 && v[0]===1 && v[1]===2 && v[2]===3 && v[3]===255) {{
                console.log('BIN-OK');
            }} else {{
                console.log('FAIL bytes', Array.from(v).join(','));
            }}
            ws.close(1000, '');
        }};
        ws.onclose = function() {{ process.exit(0); }};
        setTimeout(() => {{ console.log('TIMEOUT'); process.exit(1); }}, 5000);
        "#
    );
    let out = run_inline(&script);
    server.join().expect("echo server thread");
    assert_marker(&out, "BIN-OK");
}
