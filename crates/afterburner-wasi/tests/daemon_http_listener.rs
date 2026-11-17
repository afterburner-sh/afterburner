// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! B2.4 - real HTTP listener end-to-end. Spawns a `DaemonHttp`
//! with a live nuclei runtime, a WasmCombustor, and a dispatcher
//! thread; makes a real HTTP request against `127.0.0.1:PORT` and
//! checks the response came through the full pipeline:
//!
//! ```text
//! raw TCP → HTTP handler → DaemonEvent channel →
//! dispatcher thread → DaemonRuntime::dispatch_event →
//! plugin daemon_event mode → user JS handler → res.end(body) →
//! __host_http_reply → DaemonHttp::deliver_reply →
//! kovan bounded channel → HTTP handler → TCP response
//! ```

#![cfg(feature = "daemon")]

use afterburner_core::Manifold;
use afterburner_wasi::{DaemonHttp, WasmCombustor, WasmConfig};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Pick a port in the ephemeral range that's unlikely to collide with
/// whatever's running on the host. Prefers ports > 49152 (IANA
/// ephemeral range). Uses the test process id to vary across test
/// invocations and a per-test counter to avoid parallel-test
/// collisions within one binary.
fn pick_port() -> u16 {
    use std::sync::atomic::AtomicU16;
    static CTR: AtomicU16 = AtomicU16::new(0);
    let offset = CTR.fetch_add(1, Ordering::Relaxed);
    let pid_tail = (std::process::id() & 0xFF) as u16;
    49500 + ((pid_tail * 7 + offset * 17) % 5000)
}

/// Block until `127.0.0.1:port` accepts a TCP connection or the
/// deadline elapses. The bind + serve runs on the nuclei runtime
/// asynchronously - we need to wait for the listener to actually be
/// up before firing a request at it.
fn wait_for_listener(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Send a raw HTTP/1.1 request and return the full response bytes.
fn http_raw(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.write_all(request.as_bytes()).expect("write");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read");
    resp
}

#[test]
fn hello_from_burn_serves_http() {
    // This is the headline example in IMPL_PLAN_BURN_RUNTIME.md §1,
    // minus the CLI wrapper (B2.5). Exercises every hop of the
    // daemon pipeline against a real socket.
    let rt = nuclei::Runtime::new().expect("build nuclei runtime");
    let daemon_http = DaemonHttp::with_runtime(rt.handle(), 64);

    let port = pick_port();
    let source = format!(
        r#"
        const http = require('node:http');
        http.createServer(function(_req, res) {{
            res.end('hello from burn\n');
        }}).listen({port});
        console.log('listening on http://localhost:' + {port});
        "#
    );

    let c = WasmCombustor::new(WasmConfig::default()).expect("combustor");
    let mut daemon = c
        .spawn_daemon_with(&source, Manifold::open(), Arc::clone(&daemon_http))
        .expect("spawn daemon");
    assert!(
        daemon.has_listeners(),
        "createServer().listen() should register"
    );

    // Dispatcher thread: drains events the HTTP handler pushes and
    // feeds them to the long-lived Store. A shutdown flag lets us
    // stop cleanly at the end of the test without leaking threads.
    let done = Arc::new(AtomicBool::new(false));
    let dispatcher_daemon_http = Arc::clone(&daemon_http);
    let dispatcher_done = Arc::clone(&done);
    let dispatcher = std::thread::spawn(move || -> Result<(), String> {
        while !dispatcher_done.load(Ordering::Relaxed) {
            match dispatcher_daemon_http.try_recv_event() {
                Some(event) => {
                    let envelope = serde_json::json!({
                        "kind": "http-request",
                        "server_id": event.server_id,
                        "req_id": event.req_id,
                        "req": {
                            "method": event.method,
                            "url": event.url,
                            "headers": event.headers.iter().cloned().collect::<std::collections::BTreeMap<_,_>>(),
                            "body": String::from_utf8_lossy(&event.body).into_owned(),
                        }
                    });
                    daemon
                        .dispatch_event(envelope)
                        .map_err(|e| format!("dispatch: {e}"))?;
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        Ok(())
    });

    // Wait for the HTTP listener to bind. The spawn happens inside
    // daemon-init's `__host_http_listen` call, but the actual bind
    // completes asynchronously on the nuclei runtime.
    assert!(
        wait_for_listener(port, Duration::from_secs(3)),
        "HTTP listener never came up on :{port}"
    );

    // Fire the request.
    let resp = http_raw(
        port,
        &format!("GET /hello HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    );
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200 OK, got:\n{resp}"
    );
    assert!(
        resp.contains("hello from burn"),
        "missing body in response:\n{resp}"
    );

    // Teardown.
    done.store(true, Ordering::Relaxed);
    dispatcher.join().ok();
    rt.shutdown_timeout(Duration::from_secs(2));
}

#[test]
fn headers_and_status_roundtrip() {
    let rt = nuclei::Runtime::new().expect("nuclei");
    let daemon_http = DaemonHttp::with_runtime(rt.handle(), 64);
    let port = pick_port();
    let source = format!(
        r#"
        const http = require('http');
        http.createServer(function(req, res) {{
            res.writeHead(418, {{
                'content-type': 'text/plain; charset=utf-8',
                'x-burn-echo': req.method + ' ' + req.url
            }});
            res.end('teapot\n');
        }}).listen({port});
        "#
    );
    let c = WasmCombustor::new(WasmConfig::default()).unwrap();
    let mut daemon = c
        .spawn_daemon_with(&source, Manifold::open(), Arc::clone(&daemon_http))
        .unwrap();
    let done = Arc::new(AtomicBool::new(false));

    let dispatcher = {
        let dh = Arc::clone(&daemon_http);
        let d = Arc::clone(&done);
        std::thread::spawn(move || {
            while !d.load(Ordering::Relaxed) {
                if let Some(event) = dh.try_recv_event() {
                    let envelope = serde_json::json!({
                        "kind": "http-request",
                        "server_id": event.server_id,
                        "req_id": event.req_id,
                        "req": {
                            "method": event.method,
                            "url": event.url,
                            "headers": {},
                            "body": "",
                        }
                    });
                    let _ = daemon.dispatch_event(envelope);
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        })
    };

    assert!(wait_for_listener(port, Duration::from_secs(3)));
    let resp = http_raw(
        port,
        &format!("GET /brew HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    );
    assert!(resp.starts_with("HTTP/1.1 418"), "got:\n{resp}");
    assert!(resp.contains("x-burn-echo: GET /brew"), "got:\n{resp}");
    assert!(resp.contains("teapot"), "got:\n{resp}");

    done.store(true, Ordering::Relaxed);
    dispatcher.join().ok();
    rt.shutdown_timeout(Duration::from_secs(2));
}

#[test]
fn sealed_manifold_denies_listen() {
    // The `listen` axis gates the daemon bind exactly like `net` gates
    // outbound: a sealed manifold's `.listen(port)` must be refused
    // BEFORE any socket bind, surfacing the permission-denied detail
    // on the server's 'error' event.
    let rt = nuclei::Runtime::new().expect("nuclei");
    let daemon_http = DaemonHttp::with_runtime(rt.handle(), 64);
    let port = pick_port();
    let source = format!(
        r#"
        const http = require('http');
        const server = http.createServer(function(_req, res) {{ res.end('nope'); }});
        server.on('error', function(e) {{
            console.log('LISTEN_ERR code=' + e.code + ' msg=' + e.message);
        }});
        server.listen({port});
        "#
    );
    let c = WasmCombustor::new(WasmConfig::default()).expect("combustor");
    let daemon = c
        .spawn_daemon_with(&source, Manifold::sealed(), Arc::clone(&daemon_http))
        .expect("spawn daemon");
    assert!(
        !daemon.has_listeners(),
        "sealed manifold must not register a listener"
    );
    assert!(
        !wait_for_listener(port, Duration::from_millis(300)),
        "sealed manifold must not bind :{port}"
    );
    let stdout = String::from_utf8_lossy(&daemon.drain_stdout()).into_owned();
    assert!(
        stdout.contains("LISTEN_ERR code=EACCES"),
        "expected an EACCES listen error, stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("permission denied"),
        "expected the permission-denied detail, stdout:\n{stdout}"
    );
    rt.shutdown_timeout(Duration::from_secs(2));
}

#[test]
fn listen_granted_port_binds_and_other_port_is_denied() {
    // A `Ports([p])` grant lets the daemon bind exactly p - and
    // nothing else (checked here via a second server on p2).
    use afterburner_core::ListenAccess;
    let rt = nuclei::Runtime::new().expect("nuclei");
    let daemon_http = DaemonHttp::with_runtime(rt.handle(), 64);
    let port = pick_port();
    let denied_port = pick_port();
    let mut manifold = Manifold::sealed();
    manifold.listen = ListenAccess::Ports(vec![port]);
    let source = format!(
        r#"
        const http = require('http');
        http.createServer(function(_req, res) {{
            res.end('granted\n');
        }}).listen({port});
        const second = http.createServer(function(_req, res) {{ res.end('x'); }});
        second.on('error', function(e) {{
            console.log('SECOND_ERR code=' + e.code);
        }});
        second.listen({denied_port});
        "#
    );
    let c = WasmCombustor::new(WasmConfig::default()).expect("combustor");
    let mut daemon = c
        .spawn_daemon_with(&source, manifold, Arc::clone(&daemon_http))
        .expect("spawn daemon");
    assert!(daemon.has_listeners(), "granted port must register");

    let done = Arc::new(AtomicBool::new(false));
    let dispatcher = {
        let dh = Arc::clone(&daemon_http);
        let d = Arc::clone(&done);
        std::thread::spawn(move || {
            while !d.load(Ordering::Relaxed) {
                if let Some(event) = dh.try_recv_event() {
                    let envelope = serde_json::json!({
                        "kind": "http-request",
                        "server_id": event.server_id,
                        "req_id": event.req_id,
                        "req": {
                            "method": event.method,
                            "url": event.url,
                            "headers": {},
                            "body": "",
                        }
                    });
                    let _ = daemon.dispatch_event(envelope);
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            daemon
        })
    };

    assert!(
        wait_for_listener(port, Duration::from_secs(3)),
        "granted port :{port} must bind"
    );
    assert!(
        !wait_for_listener(denied_port, Duration::from_millis(200)),
        "ungranted port :{denied_port} must not bind"
    );
    let resp = http_raw(
        port,
        &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    );
    assert!(resp.starts_with("HTTP/1.1 200"), "got:\n{resp}");
    assert!(resp.contains("granted"), "got:\n{resp}");

    done.store(true, Ordering::Relaxed);
    let daemon = dispatcher.join().expect("dispatcher join");
    let stdout = String::from_utf8_lossy(&daemon.drain_stdout()).into_owned();
    assert!(
        stdout.contains("SECOND_ERR code=EACCES"),
        "second server should be denied with EACCES, stdout:\n{stdout}"
    );
    rt.shutdown_timeout(Duration::from_secs(2));
}

// ---- response bodies are bytes ----------------------------------------

/// Send raw request bytes and return the response head (lowercased text)
/// and body (exact bytes), split at the first blank line.
fn http_bytes(port: u16, request: &[u8]) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.write_all(request).expect("write");
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).expect("read");
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head ends");
    (
        String::from_utf8_lossy(&resp[..split]).to_ascii_lowercase(),
        resp[split + 4..].to_vec(),
    )
}

fn bare_request(port: u16, method: &str) -> Vec<u8> {
    format!("{method} / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// Serve `handler` (the body of `function (req, res) { ... }`) on a real
/// listener, run `check` against its port, then tear everything down.
fn with_handler(handler: &str, check: impl FnOnce(u16)) {
    let rt = nuclei::Runtime::new().expect("nuclei");
    let daemon_http = DaemonHttp::with_runtime(rt.handle(), 64);
    let port = pick_port();
    let source = format!(
        "const http = require('http');\n\
         http.createServer(function(req, res) {{ {handler} }}).listen({port});"
    );
    let c = WasmCombustor::new(WasmConfig::default()).expect("combustor");
    let mut daemon = c
        .spawn_daemon_with(&source, Manifold::open(), Arc::clone(&daemon_http))
        .expect("spawn daemon");
    let done = Arc::new(AtomicBool::new(false));
    let dispatcher = {
        let dh = Arc::clone(&daemon_http);
        let d = Arc::clone(&done);
        std::thread::spawn(move || {
            while !d.load(Ordering::Relaxed) {
                if let Some(event) = dh.try_recv_event() {
                    let envelope =
                        afterburner_wasi::daemon_envelopes::http_event_to_envelope(&event);
                    let _ = daemon.dispatch_event(envelope);
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        })
    };
    assert!(
        wait_for_listener(port, Duration::from_secs(3)),
        "HTTP listener never came up on :{port}"
    );
    check(port);
    done.store(true, Ordering::Relaxed);
    dispatcher.join().ok();
    rt.shutdown_timeout(Duration::from_secs(2));
}

#[test]
fn response_of_all_256_byte_values_arrives_exact() {
    with_handler(
        "const b = Buffer.alloc(256); for (let i = 0; i < 256; i++) b[i] = i; res.end(b);",
        |port| {
            let (head, body) = http_bytes(port, &bare_request(port, "GET"));
            assert!(head.starts_with("http/1.1 200"), "head:\n{head}");
            assert!(head.contains("content-length: 256\r\n"), "head:\n{head}");
            assert_eq!(body, (0..=255u8).collect::<Vec<u8>>());
        },
    );
}

#[test]
fn response_of_85000_non_ascii_bytes_arrives_exact() {
    with_handler(
        "const p = new Uint8Array([0xc3, 0xa9, 0x80, 0xff, 0x00, 0x7f, 0xe2, 0x82, 0xac]);\
         const n = 85000; const b = new Uint8Array(n);\
         for (let o = 0; o < n; o += p.length) b.set(p.subarray(0, Math.min(p.length, n - o)), o);\
         res.end(b);",
        |port| {
            let pattern = [0xc3, 0xa9, 0x80, 0xff, 0x00, 0x7f, 0xe2, 0x82, 0xac];
            let expect: Vec<u8> = pattern.iter().copied().cycle().take(85_000).collect();
            let (head, body) = http_bytes(port, &bare_request(port, "GET"));
            assert!(head.contains("content-length: 85000\r\n"), "head:\n{head}");
            assert!(
                body == expect,
                "85000-byte body differs ({} bytes)",
                body.len()
            );
        },
    );
}

#[test]
fn mixed_buffer_string_and_uint8array_chunks_arrive_in_order() {
    with_handler(
        "res.write(Buffer.from([0xff, 0x00])); res.write('h\\u00e9llo');\
         res.end(new Uint8Array([1, 2, 3]));",
        |port| {
            let (head, body) = http_bytes(port, &bare_request(port, "GET"));
            let mut expect = vec![0xff, 0x00];
            expect.extend_from_slice("h\u{e9}llo".as_bytes());
            expect.extend_from_slice(&[1, 2, 3]);
            let length = format!("content-length: {}\r\n", expect.len());
            assert!(head.contains(&length), "head:\n{head}");
            assert_eq!(body, expect);
        },
    );
}

#[test]
fn string_chunk_arrives_as_its_utf8_bytes() {
    with_handler("res.end('h\\u00e9llo \\u20ac \\ud83d\\ude00');", |port| {
        let text = "h\u{e9}llo \u{20ac} \u{1f600}";
        let (head, body) = http_bytes(port, &bare_request(port, "GET"));
        let length = format!("content-length: {}\r\n", text.len());
        assert!(head.contains(&length), "head:\n{head}");
        assert_eq!(body, text.as_bytes());
    });
}

#[test]
fn string_chunks_honour_their_encoding() {
    with_handler(
        "res.write('ff00', 'hex'); res.write('\\u00e9\\u00ff', 'latin1');\
         res.write('a\\u20ac', 'utf16le'); res.write('/wA=', 'base64'); res.end('A', 'binary');",
        |port| {
            let (_, body) = http_bytes(port, &bare_request(port, "GET"));
            assert_eq!(
                body,
                vec![
                    0xff, 0x00, 0xe9, 0xff, 0x61, 0x00, 0xac, 0x20, 0xff, 0x00, 0x41
                ]
            );
        },
    );
}

#[test]
fn empty_responses_have_a_zero_length_body() {
    with_handler("res.end();", |port| {
        let (head, body) = http_bytes(port, &bare_request(port, "GET"));
        assert!(head.starts_with("http/1.1 200"), "head:\n{head}");
        assert!(head.contains("content-length: 0\r\n"), "head:\n{head}");
        assert!(body.is_empty());
    });
    with_handler("res.write(''); res.end('');", |port| {
        let (head, body) = http_bytes(port, &bare_request(port, "GET"));
        assert!(head.contains("content-length: 0\r\n"), "head:\n{head}");
        assert!(body.is_empty());
    });
}

#[test]
fn head_request_reports_the_byte_length_and_sends_no_body() {
    with_handler("res.end(Buffer.alloc(300, 7));", |port| {
        let (head, body) = http_bytes(port, &bare_request(port, "HEAD"));
        assert!(head.starts_with("http/1.1 200"), "head:\n{head}");
        assert!(head.contains("content-length: 300\r\n"), "head:\n{head}");
        assert!(body.is_empty());
    });
}

#[test]
fn a_chunk_that_is_not_string_or_bytes_throws_and_leaves_the_response_open() {
    with_handler(
        "try { res.end(123); } catch (e) { res.statusCode = 500; res.end(e.code); }",
        |port| {
            let (head, body) = http_bytes(port, &bare_request(port, "GET"));
            assert!(head.starts_with("http/1.1 500"), "head:\n{head}");
            assert_eq!(body, b"ERR_INVALID_ARG_TYPE");
        },
    );
}

#[test]
fn a_reply_with_only_a_string_body_is_still_served() {
    // What a guest built against the older polyfill sends.
    with_handler(
        "const send = globalThis.__host_http_reply;\
         globalThis.__host_http_reply = (id) =>\
           send(id, JSON.stringify({status: 200, headers: {}, body: 'old \\u00e9'}));\
         res.end('ignored');",
        |port| {
            let (_, body) = http_bytes(port, &bare_request(port, "GET"));
            assert_eq!(body, "old \u{e9}".as_bytes());
        },
    );
}

#[test]
fn a_malformed_body_b64_answers_502() {
    with_handler(
        "const send = globalThis.__host_http_reply;\
         globalThis.__host_http_reply = (id) =>\
           send(id, JSON.stringify({status: 200, headers: {}, body_b64: '!!bad!!'}));\
         res.end('x');",
        |port| {
            let (head, body) = http_bytes(port, &bare_request(port, "GET"));
            assert!(head.starts_with("http/1.1 502"), "head:\n{head}");
            assert!(!body.is_empty());
        },
    );
}

#[test]
fn http2_response_of_all_256_byte_values_arrives_exact() {
    // The same handler answers an HTTP/2 prior-knowledge client: the reply is
    // one `ReplyEnvelope` for every protocol.
    with_handler(
        "const b = Buffer.alloc(256); for (let i = 0; i < 256; i++) b[i] = i; res.end(b);",
        |port| {
            let rt = nuclei::Runtime::new().expect("client runtime");
            let (status, length, body) = rt.block_on(async move {
                let tcp = nuclei::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .expect("connect");
                let (mut send, conn) = h2::client::handshake(tcp).await.expect("h2 handshake");
                nuclei::spawn(async move {
                    let _ = conn.await;
                })
                .detach();
                let request = http::Request::builder()
                    .method("GET")
                    .uri(format!("http://127.0.0.1:{port}/"))
                    .body(())
                    .expect("request");
                let (response, _) = send.send_request(request, true).expect("send request");
                let response = response.await.expect("response");
                let status = response.status().as_u16();
                let length = response
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok().map(str::to_owned));
                let mut stream = response.into_body();
                let mut body = Vec::new();
                while let Some(chunk) = stream.data().await {
                    let chunk = chunk.expect("data frame");
                    body.extend_from_slice(&chunk);
                    let _ = stream.flow_control().release_capacity(chunk.len());
                }
                (status, length, body)
            });
            assert_eq!(status, 200);
            assert_eq!(length.as_deref(), Some("256"));
            assert_eq!(body, (0..=255u8).collect::<Vec<u8>>());
            rt.shutdown_timeout(Duration::from_secs(2));
        },
    );
}
