// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B2.4 — real axum listener end-to-end. Spawns a `DaemonHttp`
//! with a live tokio runtime, a WasmCombustor, and a dispatcher
//! thread; makes a real HTTP request against `127.0.0.1:PORT` and
//! checks the response came through the full pipeline:
//!
//! ```text
//! raw TCP → axum handler → DaemonEvent channel →
//! dispatcher thread → DaemonRuntime::dispatch_event →
//! plugin daemon_event mode → user JS handler → res.end(body) →
//! __host_http_reply → DaemonHttp::deliver_reply →
//! kovan bounded channel → axum handler → TCP response
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
/// deadline elapses. Axum's bind + serve runs on the tokio runtime
/// asynchronously — we need to wait for the listener to actually be
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
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let daemon_http = DaemonHttp::with_runtime(rt.handle().clone(), 64);

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

    // Dispatcher thread: drains events the axum handler pushes and
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

    // Wait for the axum listener to bind. The spawn happens inside
    // daemon-init's `__host_http_listen` call, but the actual bind
    // completes asynchronously on the tokio runtime.
    assert!(
        wait_for_listener(port, Duration::from_secs(3)),
        "axum listener never came up on :{port}"
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
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio");
    let daemon_http = DaemonHttp::with_runtime(rt.handle().clone(), 64);
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
