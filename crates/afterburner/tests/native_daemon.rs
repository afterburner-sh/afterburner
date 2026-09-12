// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Non-JS daemon guests (`docs/wasi-daemon-abi.md`): a daemon-shaped
//! Rust / Go / C WASI guest, run through the real `burn run` CLI, serving
//! more than one real HTTP request over a real socket.
//!
//! Each fixture (`tests/fixtures/native_daemon/server.{rs,go,c}`) exports
//! the `afterburner_daemon_*` ABI directly (no framework, no macros - the
//! same four functions a package author would hand-write) and replies to
//! every request with `request #N path=<url>`, so a passing test proves
//! both that the daemon serves more than one request AND that guest state
//! (the counter) survives across calls, exactly as the design doc claims.
//!
//! All three toolchains (`rustc`, `go` >= 1.24, the bundled wasi-sdk) are
//! present and were used for real on the machine these tests were written
//! against - none are `#[ignore]`d.

#![cfg(feature = "bin")]

use serial_test::serial;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

/// Wait up to 60s for something to accept connections on `addr` - the
/// same ceiling `b3_daemon_lifecycle.rs` uses to absorb a cold-CI wasmtime
/// engine startup (debug builds are slow to cold-instantiate).
fn wait_for_listener(addr: SocketAddr) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("native daemon never started listening on {addr}");
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write request");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    resp
}

fn body_of(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("").trim()
}

fn kill(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Write `fixture` (a `native_daemon/server.*` file with `__PORT__`
/// substituted) into a fresh temp dir under the given file name, spawn
/// `burn run` on it, wait for the listener, fire two requests at two
/// different paths, and assert both distinct bodies. Shared by all three
/// language tests below - one assertion path, one implementation.
fn run_and_verify(fixture_source: &str, port: u16, file_name: &str) {
    let source = fixture_source.replace("__PORT__", &port.to_string());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(file_name);
    std::fs::write(&path, source).expect("write fixture");

    let child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .arg("run")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn run");

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    wait_for_listener(addr);

    let resp1 = http_get(addr, "/alpha");
    let resp2 = http_get(addr, "/beta");

    assert!(
        resp1.starts_with("HTTP/1.1 200"),
        "resp1 status line: {resp1:?}"
    );
    assert!(
        resp2.starts_with("HTTP/1.1 200"),
        "resp2 status line: {resp2:?}"
    );
    assert_eq!(
        body_of(&resp1),
        "request #1 path=/alpha",
        "first request's body (full response: {resp1:?})"
    );
    assert_eq!(
        body_of(&resp2),
        "request #2 path=/beta",
        "second request's body - must differ from the first, proving guest \
         state (the request counter) survives across calls (full response: {resp2:?})"
    );

    kill(child);
}

#[test]
#[serial]
fn rust_daemon_serves_multiple_requests() {
    let port = pick_port();
    let fixture = include_str!("fixtures/native_daemon/server.rs");
    run_and_verify(fixture, port, "server.rs");
}

/// Rust is the language the operator is taking into another product, so
/// it gets proven past "two requests": 40 real, sequential HTTP requests
/// against ONE `burn run` process - the same instance the whole way
/// through, per `docs/wasi-daemon-abi.md`. Each request's body must carry
/// the exact expected sequence number, so this fails immediately if state
/// ever resets (a fresh one-shot per request wearing a daemon's clothes)
/// or if the daemon dies partway (fuel not actually replenished per call -
/// `daemon_runtime_native`'s own
/// `fuel_is_replenished_not_accumulated_across_many_dispatches` unit test
/// proves the mechanism directly; this proves it end to end through the
/// real CLI, real sockets, real axum dispatch).
#[test]
#[serial]
fn rust_daemon_survives_many_sequential_requests() {
    const REQUEST_COUNT: u32 = 40;

    let port = pick_port();
    let source =
        include_str!("fixtures/native_daemon/server.rs").replace("__PORT__", &port.to_string());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("server.rs");
    std::fs::write(&path, source).expect("write fixture");

    let child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .arg("run")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn run");

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    wait_for_listener(addr);

    for n in 1..=REQUEST_COUNT {
        let resp = http_get(addr, "/ping");
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "request {n}/{REQUEST_COUNT} status line: {resp:?}"
        );
        let expected = format!("request #{n} path=/ping");
        assert_eq!(
            body_of(&resp),
            expected,
            "request {n}/{REQUEST_COUNT}: the sequence number must match exactly - a \
             mismatch here means either state didn't survive across calls (a fresh \
             instance per request) or the daemon silently died and something else \
             answered; full response: {resp:?}"
        );
    }

    kill(child);
}

#[test]
#[serial]
fn go_daemon_serves_multiple_requests() {
    let port = pick_port();
    let fixture = include_str!("fixtures/native_daemon/server.go");
    run_and_verify(fixture, port, "server.go");
}

#[test]
#[serial]
fn c_daemon_serves_multiple_requests() {
    let port = pick_port();
    let fixture = include_str!("fixtures/native_daemon/server.c");
    run_and_verify(fixture, port, "server.c");
}

/// A partially-shaped native module (some but not all four
/// `afterburner_daemon_*` exports) must fail loudly at `burn run` time
/// naming what's wrong, never silently fall back to a one-shot run that
/// would leave an author wondering why their "server" printed nothing and
/// exited. See docs/wasi-daemon-abi.md's `NativeDaemonShape::Malformed`.
#[test]
#[serial]
fn partial_daemon_abi_is_a_hard_error_not_silent_one_shot() {
    let source = r#"
        #[unsafe(no_mangle)]
        pub extern "C" fn afterburner_alloc(len: i32) -> i32 {
            let mut buf = Vec::<u8>::with_capacity(len.max(0) as usize);
            let ptr = buf.as_mut_ptr();
            std::mem::forget(buf);
            ptr as i32
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn afterburner_daemon_dispatch(_ptr: i32, _len: i32) -> i32 { 0 }

        fn main() {
            println!("should never print: burn must refuse this build");
        }
    "#;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("partial.rs");
    std::fs::write(&path, source).expect("write fixture");

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .arg("run")
        .arg(&path)
        .output()
        .expect("spawn burn run");

    assert!(
        !out.status.success(),
        "a partial daemon ABI must not exit 0"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("should never print"),
        "must not have silently run main() as a one-shot: stdout={stdout:?}"
    );
    assert!(
        stderr.contains("afterburner_daemon_init") || stderr.contains("afterburner_dealloc"),
        "error must name the missing export(s): stderr={stderr:?}"
    );
}
