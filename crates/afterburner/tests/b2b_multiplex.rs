// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B2b phase gate: host-wide multiplex listener pool.
//!
//! Internal refactor — the JS-visible API of `http.createServer()` is
//! unchanged. Tests here cover the new semantics:
//!
//! * EADDRINUSE surfaces synchronously as an 'error' event on the
//!   second `.listen(port)` call on the same port within one process
//!   (matches Node).
//! * Two listeners on *different* ports in one script both work, and
//!   requests route to the right handler by port.
//! * `server.close()` releases the port — a subsequent `.listen(port)`
//!   on the same port succeeds.
//! * `listen` failures emit an async 'error' event rather than
//!   throwing synchronously (matches Node's listen-failure contract).
//! * The pre-B2b ghost-listener bug is gone: a port that fails the
//!   OS bind no longer leaves a phantom `server_id` with no socket.

#![cfg(feature = "bin")]

mod common;

use common::{ChildGuard, pick_port, wait_for_listener};
use serial_test::serial;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Multiplex tests probe ports that may not actually be bound (the
/// EADDRINUSE / phantom-listener paths), so the helper returns an
/// Option instead of panicking on connect failure. Distinct from
/// `common::http_get` which panics on connect — this is the variant
/// specific to "did the listener register?" probes.
fn http_get(port: u16) -> Option<String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut out = String::new();
    stream.read_to_string(&mut out).ok()?;
    Some(out)
}

fn spawn_script(src: &str) -> Child {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn")
}

// ---- EADDRINUSE on collision --------------------------------------------

#[test]
#[serial]
fn second_listen_on_same_port_emits_error() {
    let port = pick_port();
    let src = format!(
        r#"
        const http = require('http');
        const results = [];
        const a = http.createServer((_req, res) => {{ res.end('a'); }});
        a.on('listening', () => results.push('a-listening'));
        a.on('error', (e) => results.push('a-err=' + e.code));
        a.listen({port});

        const b = http.createServer((_req, res) => {{ res.end('b'); }});
        b.on('listening', () => results.push('b-listening'));
        b.on('error', (e) => {{
            results.push('b-err=' + e.code);
            // Give the first listener a moment to finish listening,
            // then exit. Otherwise the daemon stays alive forever.
            setTimeout(() => {{
                console.log(JSON.stringify(results));
                process.exit(0);
            }}, 100);
        }});
        b.listen({port});
        "#
    );
    let child = spawn_script(&src);
    let out = child.wait_with_output().expect("wait burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("a-listening"),
        "first server should have listened: {stdout}"
    );
    assert!(
        stdout.contains("b-err=EADDRINUSE"),
        "second server should emit EADDRINUSE error event: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- two listeners, different ports -------------------------------------

#[test]
#[serial]
fn two_listeners_on_different_ports_route_independently() {
    let port_a = pick_port();
    let port_b = pick_port();
    let src = format!(
        r#"
        const http = require('http');
        http.createServer((_req, res) => {{ res.end('A:{port_a}'); }}).listen({port_a});
        http.createServer((_req, res) => {{ res.end('B:{port_b}'); }}).listen({port_b});
        "#
    );
    let _child = ChildGuard::new(spawn_script(&src));
    assert!(
        wait_for_listener(port_a, Duration::from_secs(60)),
        "listener A should come up on {port_a}"
    );
    assert!(
        wait_for_listener(port_b, Duration::from_secs(60)),
        "listener B should come up on {port_b}"
    );

    let resp_a = http_get(port_a).expect("GET A");
    let resp_b = http_get(port_b).expect("GET B");
    assert!(
        resp_a.contains(&format!("A:{port_a}")),
        "A response wrong: {resp_a}"
    );
    assert!(
        resp_b.contains(&format!("B:{port_b}")),
        "B response wrong: {resp_b}"
    );
}

// ---- close releases the port --------------------------------------------

#[test]
#[serial]
fn close_then_relisten_on_same_port_succeeds() {
    let port = pick_port();
    let src = format!(
        r#"
        const http = require('http');
        const results = [];

        const first = http.createServer((_req, res) => {{ res.end('first'); }});
        first.on('listening', () => {{
            results.push('first-listening');
            first.close(() => {{
                results.push('first-closed');
                // Give close enough time to complete the port release
                // (abort is async inside tokio). 250ms is generous but
                // bounded — a regressed close-leak still fails the
                // test at the second listen's EADDRINUSE.
                setTimeout(() => {{
                    const second = http.createServer((_req, res) => {{ res.end('second'); }});
                    second.on('listening', () => {{
                        results.push('second-listening');
                        second.close(() => {{
                            console.log(JSON.stringify(results));
                            process.exit(0);
                        }});
                    }});
                    second.on('error', (e) => {{
                        results.push('second-err=' + e.code);
                        console.log(JSON.stringify(results));
                        process.exit(1);
                    }});
                    second.listen({port});
                }}, 250);
            }});
        }});
        first.listen({port});
        "#
    );
    let out = spawn_script(&src).wait_with_output().expect("wait burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "close/relisten failed, exit={}: stdout={stdout}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("first-listening"),
        "first never listened: {stdout}"
    );
    assert!(
        stdout.contains("first-closed"),
        "first never closed: {stdout}"
    );
    assert!(
        stdout.contains("second-listening"),
        "second should have listened after first closed: {stdout}"
    );
    assert!(
        !stdout.contains("second-err"),
        "second should NOT error after first closed: {stdout}"
    );
}

// ---- listen failure emits error async, doesn't throw --------------------

#[test]
#[serial]
fn listen_failure_emits_error_event_not_throw() {
    // Stand up a listener, then have the script try to bind the same
    // port. The second bind must NOT throw (or the whole script would
    // die before `error` could fire); it must emit 'error' async so
    // a handler attached after .listen() still catches it.
    let port = pick_port();
    let src = format!(
        r#"
        const http = require('http');
        const a = http.createServer((_req, res) => {{ res.end('a'); }});
        a.listen({port});

        let gotError = false;
        let gotThrow = false;
        const b = http.createServer((_req, res) => {{ res.end('b'); }});
        try {{
            b.listen({port});
        }} catch (e) {{
            gotThrow = true;
        }}
        b.on('error', (e) => {{
            gotError = true;
            setTimeout(() => {{
                console.log('threw=' + gotThrow + ' error=' + gotError + ' code=' + e.code);
                process.exit(0);
            }}, 50);
        }});
        "#
    );
    let out = spawn_script(&src).wait_with_output().expect("wait burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("threw=false"),
        "listen() should not throw synchronously: {stdout}"
    );
    assert!(
        stdout.contains("error=true"),
        "listen() should emit 'error' event: {stdout}"
    );
    assert!(
        stdout.contains("code=EADDRINUSE"),
        "error event should carry EADDRINUSE: {stdout}"
    );
}

// ---- ghost-listener regression ------------------------------------------
//
// Pre-B2b bug: a `.listen(port)` where the port was already owned by
// another process would silently register a phantom server_id with no
// real socket. The user's `listening` callback would fire but curl
// would get connection-refused. B2b synchronously binds before
// allocating the server_id so the failure surfaces as an 'error'
// event instead.

#[test]
#[serial]
fn external_port_owner_surfaces_eaddrinuse() {
    let port = pick_port();
    // Bind the port from the host side so the burn script's
    // .listen() hits an OS-level EADDRINUSE, not a within-process
    // collision.
    let blocker = std::net::TcpListener::bind(("127.0.0.1", port)).expect("blocker bind");

    let src = format!(
        r#"
        const http = require('http');
        let listenedFalsely = false;
        let errored = false;
        const s = http.createServer((_req, res) => {{ res.end('hi'); }});
        s.on('listening', () => {{ listenedFalsely = true; }});
        s.on('error', (e) => {{
            errored = true;
            setTimeout(() => {{
                console.log('listened=' + listenedFalsely + ' error=' + errored + ' code=' + e.code);
                process.exit(0);
            }}, 50);
        }});
        s.listen({port});
        "#
    );
    let out = spawn_script(&src).wait_with_output().expect("wait burn");
    drop(blocker);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("listened=false"),
        "ghost-listening bug: listen callback fired even though port was already owned: {stdout}"
    );
    assert!(
        stdout.contains("error=true"),
        "error event should fire when external process owns the port: {stdout}"
    );
    assert!(
        stdout.contains("code=EADDRINUSE"),
        "expected EADDRINUSE, got: {stdout}"
    );
}
