// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B7 — `dgram` (UDP) socket integration tests.
//!
//! Drives the host coordinator end-to-end through the burn CLI:
//! burn binds + sends, the test thread does the inverse from outside.
//! Coordination uses a shared event-log file (UDP is fire-and-forget,
//! so cross-process pipe buffering is not an option).
//!
//! Coverage:
//!  * `bind_and_address_round_trip` — bind to ephemeral port, address()
//!    returns matching {address, port}.
//!  * `send_to_external_listener` — burn's send arrives at a rust-side
//!    `std::net::UdpSocket` receiver.
//!  * `receive_from_external_sender` — rust-side sends a packet, burn
//!    observes it via 'message' event with rinfo populated.
//!  * `bind_with_explicit_address` — bind('127.0.0.1', 0) works.
//!  * `close_releases_socket` — close() lets the daemon exit when
//!    nothing else holds a ref.

#![cfg(feature = "bin")]

use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn scratch(label: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_dgram_{label}_{pid}_{n}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn spawn_burn_silent(cwd: &PathBuf, src: &str) -> std::process::Child {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(cwd)
        .args(["-A", "-e", src])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn burn")
}

#[test]
fn bind_and_address_round_trip() {
    let dir = scratch("bind_addr");
    let log = dir.join("events.log");
    let src = format!(
        r#"
            const dgram = require('dgram');
            const fs = require('fs');
            const sock = dgram.createSocket('udp4');
            sock.on('listening', () => {{
                const addr = sock.address();
                fs.writeFileSync({log}, JSON.stringify(addr));
                sock.close();
            }});
            sock.bind(0, '127.0.0.1');
        "#,
        log = serde_json::to_string(log.to_str().unwrap()).unwrap()
    );
    let mut child = spawn_burn_silent(&dir, &src);
    // Poll for the log file rather than sleep a fixed budget — under
    // cross-binary CPU pressure burn cold-start can stretch past any
    // hard-coded duration.
    let mut contents = String::new();
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(s) = fs::read_to_string(&log)
            && !s.is_empty()
        {
            contents = s;
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(!contents.is_empty(), "log file never produced");
    let addr: serde_json::Value = serde_json::from_str(&contents).expect("addr JSON");
    assert_eq!(addr["address"], "127.0.0.1");
    assert!(addr["port"].as_u64().unwrap() > 0, "port: {}", addr["port"]);
    assert_eq!(addr["family"], "IPv4");
}

#[test]
fn send_to_external_listener() {
    // External rust UDP listener; burn binds + sends a packet to it.
    let listener = UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    // 60s recv timeout — cold GH 4-vCPU cold-spawn of burn + plugin
    // + dgram bind + send can take 30-45s.
    listener
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok();
    let listener_port = listener.local_addr().unwrap().port();

    let dir = scratch("send_ext");
    let log = dir.join("done.log");
    let src = format!(
        r#"
            const dgram = require('dgram');
            const fs = require('fs');
            const sock = dgram.createSocket('udp4');
            sock.on('listening', () => {{
                sock.send('hello-from-burn', {port}, '127.0.0.1', (err) => {{
                    fs.writeFileSync({log}, err ? ('ERR:' + err.message) : 'OK');
                    sock.close();
                }});
            }});
            sock.bind(0, '127.0.0.1');
        "#,
        port = listener_port,
        log = serde_json::to_string(log.to_str().unwrap()).unwrap()
    );
    let mut child = spawn_burn_silent(&dir, &src);

    let mut buf = [0u8; 1024];
    let result = listener.recv_from(&mut buf);
    // Give burn time for the send callback to fire + write the log
    // file before we kill the process. The packet has been received
    // already; this just lets the JS-side microtask drain.
    let mut log_contents = String::new();
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(s) = fs::read_to_string(&log)
            && !s.is_empty()
        {
            log_contents = s;
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    let (n, _from): (usize, SocketAddr) = result.expect("recv from burn");
    assert_eq!(&buf[..n], b"hello-from-burn", "burn payload mismatch");
    assert!(
        log_contents.contains("OK"),
        "burn send callback: {log_contents:?}"
    );
}

#[test]
fn receive_from_external_sender() {
    // burn binds; rust sends; burn observes via 'message' event.
    let dir = scratch("recv_ext");
    let log = dir.join("rcv.log");
    let port_log = dir.join("port.log");
    let src = format!(
        r#"
            const dgram = require('dgram');
            const fs = require('fs');
            const sock = dgram.createSocket('udp4');
            sock.on('listening', () => {{
                const a = sock.address();
                fs.writeFileSync({pl}, String(a.port));
            }});
            sock.on('message', (msg, rinfo) => {{
                fs.writeFileSync({log},
                    'GOT=' + msg.toString('utf8') +
                    '|FROM=' + rinfo.address + ':' + rinfo.port +
                    '|FAM=' + rinfo.family +
                    '|SIZE=' + rinfo.size);
                sock.close();
            }});
            sock.bind(0, '127.0.0.1');
        "#,
        pl = serde_json::to_string(port_log.to_str().unwrap()).unwrap(),
        log = serde_json::to_string(log.to_str().unwrap()).unwrap()
    );
    let mut child = spawn_burn_silent(&dir, &src);

    // Wait for burn to bind + write the port file.
    let port = {
        let mut got = None;
        // 120 × 500ms = 60s ceiling; cold GH 4-vCPU cold-spawn of
        // burn + plugin + dgram bind can take 30-45s.
        for _ in 0..120 {
            std::thread::sleep(Duration::from_millis(500));
            if let Ok(s) = fs::read_to_string(&port_log)
                && let Ok(p) = s.trim().parse::<u16>()
            {
                got = Some(p);
                break;
            }
        }
        got.expect("burn published bound port within 60s")
    };

    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    sender
        .send_to(b"ping-from-rust", ("127.0.0.1", port))
        .expect("rust send_to");

    // Wait for burn to write the receive log + close.
    let mut last = String::new();
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(500));
        if let Ok(s) = fs::read_to_string(&log)
            && s.contains("GOT=")
        {
            last = s;
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(last.contains("GOT=ping-from-rust"), "log: {last:?}");
    assert!(last.contains("FROM=127.0.0.1:"), "log: {last:?}");
    assert!(last.contains("FAM=IPv4"), "log: {last:?}");
    assert!(last.contains("SIZE=14"), "log: {last:?}");
}

#[test]
fn close_lets_daemon_exit() {
    // Bind + immediately close. With no other refs, the daemon should
    // exit on its own. We assert via a short timeout: if burn is still
    // running after a few seconds, close didn't release the ref.
    let dir = scratch("close_exit");
    let src = r#"
        const dgram = require('dgram');
        const sock = dgram.createSocket('udp4');
        sock.on('listening', () => sock.close());
        sock.bind(0, '127.0.0.1');
    "#;
    let mut child = spawn_burn_silent(&dir, src);
    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("burn didn't exit after socket.close()");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
