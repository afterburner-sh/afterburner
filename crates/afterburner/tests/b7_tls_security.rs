// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! B7 security guardrails for `tls`.
//!
//! Pinned defenses:
//!
//! * **`NetAccess::None`** — `--sandbox` without `--allow-net` blocks
//!   `tls.connect` with `EACCES`.
//! * **Allow-list narrowing** — `--allow-net 127.0.0.2` permits that
//!   host but blocks `127.0.0.1`.
//! * **`OutboundHttp` blocks raw TLS** — covered by a unit test in
//!   `daemon_tls.rs`; the CLI cannot construct an HTTP-only manifold.
//! * **Library mode rejects `tls.createServer().listen()` and
//!   `tls.connect`** — `Afterburner::run_script` never installs
//!   `DaemonTls`, so both paths surface `ENO_DAEMON`.
//! * **`rejectUnauthorized=true` rejects self-signed by default** —
//!   covered in `b7_tls::handshake_failure_self_signed_with_strict_verification`;
//!   not duplicated here.

use afterburner::Afterburner;
use serial_test::serial;
use std::net::TcpListener;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

#[test]
#[serial]
fn sandbox_without_allow_net_blocks_tls_connect() {
    let port = free_port();
    let parent = format!(
        r#"
            const tls = require('tls');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                rejectUnauthorized: false,
            }});
            sock.on('error', (e) => {{
                if (e.code === 'EACCES') {{
                    console.log('SEALED_OK');
                    process.exit(0);
                }}
                console.error('wrong code:', e.code, e.message);
                process.exit(2);
            }});
            sock.on('secureConnect', () => {{
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

#[test]
#[serial]
fn allow_list_blocks_unlisted_host_for_tls() {
    let port = free_port();
    let parent = format!(
        r#"
            const tls = require('tls');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                rejectUnauthorized: false,
            }});
            sock.on('error', (e) => {{
                if (e.code === 'EACCES') {{
                    console.log('FILTER_OK');
                    process.exit(0);
                }}
                console.error('wrong code:', e.code, e.message);
                process.exit(2);
            }});
            sock.on('secureConnect', () => {{
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
fn library_mode_rejects_tls_listen() {
    let ab = Afterburner::new().expect("build");
    let out = ab
        .run_script(
            r#"
            const tls = require('tls');
            const fakePem = '-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n';
            // The cert/key strings are bogus, but library mode should
            // refuse before validating them — the check happens in the
            // host stub, not in the rustls parser.
            try {
                const server = tls.createServer({ cert: fakePem, key: fakePem });
                server.on('error', (e) => {
                    console.log('LISTEN_DENIED code=' + e.code);
                });
                server.listen(0, '127.0.0.1');
            } catch (e) {
                console.log('LISTEN_DENIED code=THREW msg=' + e.message);
            }
        "#,
        )
        .expect("run_script");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LISTEN_DENIED"), "stdout = {stdout}");
    assert!(
        stdout.contains("ENO_DAEMON") || stdout.contains("EACCES") || stdout.contains("THREW"),
        "stdout = {stdout}"
    );
}

#[test]
fn library_mode_rejects_tls_connect() {
    let ab = Afterburner::new().expect("build");
    let port = free_port();
    let src = format!(
        r#"
            const tls = require('tls');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                rejectUnauthorized: false,
            }});
            sock.on('error', (e) => {{
                console.log('CONNECT_DENIED code=' + e.code);
            }});
        "#
    );
    let out = ab.run_script(&src).expect("run_script");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CONNECT_DENIED"), "stdout = {stdout}");
    assert!(
        stdout.contains("ENO_DAEMON") || stdout.contains("EACCES"),
        "stdout = {stdout}"
    );
}
