// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! B7 security guardrails for `net` (raw TCP).
//!
//! Each test pins a specific defense in `daemon_net::net_outbound_allowed`
//! or the library/daemon partition. If any go red, the threat model has
//! regressed:
//!
//! * **`NetAccess::None`** - `--sandbox` without `--allow-net` must
//!   reject `net.connect` with `EACCES`.
//! * **Allow-list narrowing** - `--allow-net 127.0.0.1` lets that host
//!   through but blocks unlisted hosts. The bind-then-drop helper gives
//!   us a guaranteed-free port without needing a real server.
//! * **`OutboundHttp` blocks raw TCP** - covered by a unit test in
//!   `daemon_net.rs`; we don't re-verify here because the CLI cannot
//!   construct an HTTP-only manifold (only `OutboundFull`).
//! * **Library mode rejects `net.createServer().listen()`** - the
//!   library API never installs `DaemonNet`, so inbound listening must
//!   surface `ENO_DAEMON`. (Outbound `net.connect` is covered too - it
//!   reaches the no-daemon stub and gets `ENO_DAEMON`.)

use afterburner::Afterburner;
use serial_test::serial;
use std::net::TcpListener;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Bind+drop a listener to find a guaranteed-free port. Race-prone in
/// theory, fine for single-shot tests in practice.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

// ---------------------------------------------------------------------
// (1) NetAccess::None blocks net.connect
// ---------------------------------------------------------------------

#[test]
#[serial]
fn sandbox_without_allow_net_blocks_connect() {
    let port = free_port();
    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('error', (e) => {{
                if (e.code === 'EACCES') {{
                    console.log('SEALED_OK');
                    process.exit(0);
                }}
                console.error('wrong code:', e.code, e.message);
                process.exit(2);
            }});
            sock.on('connect', () => {{
                console.error('LEAK: connected despite NetAccess::None');
                process.exit(1);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["--sandbox", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("SEALED_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------
// (2) Allow-list narrowing - listed host permitted, unlisted blocked
// ---------------------------------------------------------------------

#[test]
#[serial]
fn allow_list_blocks_unlisted_host() {
    let port = free_port();
    // Allow only 127.0.0.2 (a loopback alias that's never the target).
    // The script targets 127.0.0.1 - must be denied with EACCES.
    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('error', (e) => {{
                if (e.code === 'EACCES') {{
                    console.log('FILTER_OK');
                    process.exit(0);
                }}
                console.error('wrong code:', e.code, e.message);
                process.exit(2);
            }});
            sock.on('connect', () => {{
                console.error('LEAK: unlisted host connected');
                process.exit(1);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["--sandbox", "--allow-net", "127.0.0.2", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("FILTER_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn allow_list_permits_listed_host() {
    // Bind a quick echo on 127.0.0.1 so the listed-host case actually
    // gets a real connect, not just past the manifold check.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let _t = std::thread::spawn(move || {
        // Accept once; immediately close - we only need the connect to
        // succeed against the listening socket.
        if let Ok((_s, _)) = listener.accept() {}
    });

    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('connect', () => {{
                console.log('ALLOWED_OK');
                sock.destroy();
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('unexpected:', e.code, e.message);
                process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["--sandbox", "--allow-net", "127.0.0.1", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("ALLOWED_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------
// (3) Library mode never installs DaemonNet - listen + connect deny
// ---------------------------------------------------------------------

/// `Afterburner::run_script` is the library entry point. It does not
/// install `DaemonNet`, so every `__host_net_*` import returns
/// `E_NO_DAEMON` and the polyfill surfaces `ENO_DAEMON`. The point of
/// the test is to lock that contract - library callers don't acquire
/// inbound or outbound TCP just because the polyfill is present.
#[test]
fn library_mode_rejects_net_listen() {
    let ab = Afterburner::new().expect("build");
    let out = ab
        .run_script(
            r#"
            const net = require('net');
            const server = net.createServer();
            server.on('error', (e) => {
                console.log('LISTEN_DENIED code=' + e.code);
            });
            server.listen(0, '127.0.0.1');
        "#,
        )
        .expect("run_script");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("LISTEN_DENIED"),
        "expected library-mode listen rejection; stdout = {stdout}"
    );
    assert!(
        stdout.contains("ENO_DAEMON") || stdout.contains("EACCES"),
        "expected ENO_DAEMON or EACCES code; stdout = {stdout}"
    );
}

#[test]
fn library_mode_rejects_net_connect() {
    let ab = Afterburner::new().expect("build");
    let port = free_port();
    let src = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('error', (e) => {{
                console.log('CONNECT_DENIED code=' + e.code);
            }});
        "#
    );
    let out = ab.run_script(&src).expect("run_script");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("CONNECT_DENIED"),
        "expected library-mode connect rejection; stdout = {stdout}"
    );
    assert!(
        stdout.contains("ENO_DAEMON") || stdout.contains("EACCES"),
        "expected ENO_DAEMON or EACCES code; stdout = {stdout}"
    );
}
