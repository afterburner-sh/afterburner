// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! B7 - `net` raw TCP integration.
//!
//! Each test spins up a fixture TCP server in a background thread,
//! then runs `burn` with an inline parent script that connects via
//! `net.connect`, exchanges bytes, and asserts the result. Validates
//! the full IPC path: __host_net_connect → tokio TcpStream::connect →
//! Connect event → daemon_event dispatcher → socket._dispatchConnect
//! → user 'connect' callback; same in reverse for the data direction.

use serial_test::serial;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Boot a single-shot TCP echo server on `127.0.0.1:0`. Returns the
/// bound port plus a JoinHandle that exits when the spawned thread
/// completes.
fn spawn_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let port = listener.local_addr().expect("local_addr").port();
    let handle = thread::spawn(move || {
        // Accept everything that comes; echo bytes back until peer
        // closes. Multi-connection.
        for incoming in listener.incoming() {
            let Ok(mut s) = incoming else { return };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    (port, handle)
}

/// Boot a server that reads exactly N bytes then closes. For the
/// half-close test.
fn spawn_drain_then_close(expected_bytes: usize) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind drain");
    let port = listener.local_addr().expect("local_addr").port();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let handle = thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        let mut got = Vec::with_capacity(expected_bytes);
        let mut buf = [0u8; 4096];
        while got.len() < expected_bytes {
            let n = s.read(&mut buf).expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let _ = s.shutdown(Shutdown::Both);
        tx.send(got).ok();
        // Block forever - the test side decides when to drop the
        // listener via the JoinHandle.
        rx.recv().ok();
        Vec::new()
    });
    let port_copy = port;
    let _ = port_copy;
    (port, handle)
}

#[test]
#[serial]
fn round_trip_echo() {
    let (port, _server) = spawn_echo_server();
    let parent = format!(
        r#"
            const net = require('net');
            const {{ Buffer }} = require('buffer');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            const got = [];
            sock.on('connect', () => {{
                sock.write(Buffer.from('hello-burn'));
            }});
            sock.on('data', (chunk) => {{
                got.push(chunk);
                const total = Buffer.concat(got).toString('utf8');
                if (total === 'hello-burn') {{
                    console.log('ROUND_TRIP_OK');
                    sock.end();
                }}
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('client error:', e && e.message || e);
                process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("ROUND_TRIP_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn connect_to_closed_port_emits_error() {
    // Bind+drop a listener to find a guaranteed-free port. (In practice
    // some other process could grab the port between drop and connect,
    // but the race is rare and the test is single-shot.)
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);

    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            let sawError = false;
            sock.on('error', (e) => {{
                sawError = true;
                if (e.code === 'ECONNREFUSED') {{
                    console.log('REFUSED_OK');
                }} else {{
                    console.log('OTHER_ERR=' + e.code);
                }}
            }});
            sock.on('close', () => {{
                process.exit(sawError ? 0 : 1);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("REFUSED_OK") || stdout.contains("OTHER_ERR=ECONNREFUSED"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn end_half_closes_writes_through() {
    let (port, _drainer) = spawn_drain_then_close(11);
    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('connect', () => {{
                sock.write('hello-world');
                sock.end();
            }});
            sock.on('end', () => {{
                console.log('END_OK');
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('client error:', e && e.message || e);
                process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("END_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn destroy_kills_connection() {
    let (port, _server) = spawn_echo_server();
    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('connect', () => {{
                sock.destroy();
            }});
            sock.on('close', () => {{
                console.log('CLOSED_OK destroyed=' + sock.destroyed);
                process.exit(0);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("CLOSED_OK destroyed=true"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn set_no_delay_and_keep_alive_no_throw() {
    // Both calls go through the host coordinator → socket2 →
    // setsockopt path now (previously they were best-effort no-ops).
    // The test passes if (a) no 'error' event fires, (b) the
    // connection still works for reading + writing afterwards.
    let (port, _server) = spawn_echo_server();
    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            let errored = false;
            sock.on('error', (e) => {{
                errored = true;
                console.error('unexpected error:', e.code, e.message);
            }});
            sock.on('connect', () => {{
                sock.setNoDelay(true);
                sock.setKeepAlive(true, 10000);
                // Round-trip a tiny payload after toggling options to
                // prove the connection is still healthy.
                sock.write('post-opts');
            }});
            sock.on('data', (chunk) => {{
                if (chunk.toString('utf8') === 'post-opts' && !errored) {{
                    console.log('OPTS_OK');
                }} else {{
                    console.error('echo mismatch:', chunk.toString('utf8'));
                    process.exit(2);
                }}
                sock.end();
            }});
            sock.on('close', () => process.exit(errored ? 3 : 0));
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("OPTS_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn set_no_delay_disable_then_re_enable() {
    // Toggle TCP_NODELAY off, then back on, then verify the
    // connection still echoes correctly. Catches any case where the
    // flag flip leaves the stream in a bad state.
    let (port, _server) = spawn_echo_server();
    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('connect', () => {{
                sock.setNoDelay(false);  // explicit disable
                sock.setNoDelay(true);   // re-enable
                sock.write('toggle-test');
            }});
            sock.on('data', (chunk) => {{
                if (chunk.toString('utf8') === 'toggle-test') {{
                    console.log('TOGGLE_OK');
                    sock.end();
                }}
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('error:', e.message); process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout:\n{stdout}");
    assert!(stdout.contains("TOGGLE_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn set_keep_alive_with_short_delay_does_not_disconnect() {
    // SO_KEEPALIVE with a short idle (1s) should configure the
    // option without immediately tearing the connection down. We
    // round-trip a payload after waiting > the idle to prove the
    // socket survives.
    let (port, _server) = spawn_echo_server();
    let parent = format!(
        r#"
            const net = require('net');
            const sock = net.connect({{ port: {port}, host: '127.0.0.1' }});
            sock.on('connect', () => {{
                sock.setKeepAlive(true, 1000);
                // Wait briefly so the option is in effect, then
                // exchange data.
                setTimeout(() => sock.write('post-keepalive'), 1500);
            }});
            sock.on('data', (chunk) => {{
                if (chunk.toString('utf8') === 'post-keepalive') {{
                    console.log('KEEPALIVE_OK');
                    sock.end();
                }}
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('error:', e.message); process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout:\n{stdout}");
    assert!(stdout.contains("KEEPALIVE_OK"), "stdout: {stdout}");
}

#[test]
#[serial]
fn server_accepts_connection_and_echoes() {
    // Server in burn (JS), client in this test thread. Use port 0 so
    // the OS picks a free one; read it back via the 'listening' event.
    let (port_tx, port_rx) = mpsc::channel::<u16>();

    let parent = r#"
        const net = require('net');
        const server = net.createServer((sock) => {
            sock.on('data', (chunk) => sock.write(chunk));
            sock.on('end', () => sock.end());
        });
        server.listen(0, '127.0.0.1', () => {
            const addr = server.address();
            // Print the bound port to stdout so the test harness can
            // pick it up.
            console.log('PORT=' + addr.port);
        });
        // Stay alive - server keeps the daemon up via has_refs.
    "#;

    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn server");

    // Read stdout until we see PORT= line.
    let stdout = child.stdout.take().expect("piped stdout");
    let port_tx_clone = port_tx.clone();
    let reader = thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stdout);
        for line in r.lines() {
            let Ok(line) = line else { return };
            if let Some(rest) = line.strip_prefix("PORT=") {
                let port: u16 = rest.parse().expect("parse port");
                let _ = port_tx_clone.send(port);
                return;
            }
        }
    });
    let port = port_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("burn server announced port");
    drop(reader);

    // Connect from this thread, send bytes, expect echo.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect to burn server");
    conn.write_all(b"abc-from-host").expect("write");
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    let want = b"abc-from-host".len();
    conn.set_read_timeout(Some(Duration::from_secs(5))).ok();
    while got.len() < want {
        let n = conn.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
        if got.len() >= want {
            break;
        }
    }
    let _ = want;
    assert_eq!(&got, b"abc-from-host");
    drop(conn);
    child.kill().ok();
    child.wait().ok();
}

#[test]
#[serial]
fn multiple_concurrent_connections() {
    let (port, _server) = spawn_echo_server();
    let parent = format!(
        r#"
            const net = require('net');
            const target = {{ port: {port}, host: '127.0.0.1' }};
            let done = 0;
            const N = 5;
            for (let i = 0; i < N; i++) {{
                (function(idx) {{
                    const sock = net.connect(target);
                    let received = '';
                    sock.on('connect', () => sock.write('msg-' + idx));
                    sock.on('data', (c) => {{
                        received += c.toString('utf8');
                        if (received === ('msg-' + idx)) {{
                            sock.end();
                        }}
                    }});
                    sock.on('close', () => {{
                        if (++done === N) {{
                            console.log('CONCURRENT_OK');
                            process.exit(0);
                        }}
                    }});
                    sock.on('error', (e) => {{
                        console.error('idx', idx, 'err', e && e.message);
                        process.exit(2);
                    }});
                }})(i);
            }}
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("CONCURRENT_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn ip_helpers() {
    // Pure-JS isIP / isIPv4 / isIPv6 - no host needed. Run in-process
    // via `burn -e`.
    let parent = r#"
        const net = require('net');
        const out = [];
        out.push(net.isIPv4('127.0.0.1'));
        out.push(net.isIPv4('::1'));
        out.push(net.isIPv6('::1'));
        out.push(net.isIPv6('not-an-ip'));
        out.push(net.isIP('1.2.3.4'));
        out.push(net.isIP('::ffff:1.2.3.4'));
        out.push(net.isIP('garbage'));
        console.log('IP=' + JSON.stringify(out));
    "#;
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(
        stdout.contains("IP=[true,false,true,false,4,6,0]"),
        "stdout: {stdout}"
    );
}

/// Spin up a Unix-domain echo server in JS inside burn, then connect
/// from a native Rust thread and round-trip a payload.
///
/// Pattern mirrors `server_accepts_connection_and_echoes` for TCP.
#[test]
#[serial]
#[cfg(unix)]
fn unix_domain_stream_round_trip() {
    use std::os::unix::net::UnixStream;

    // Unique socket path scoped to this test run.
    let path = format!("/tmp/burn-test-unix-{}.sock", std::process::id());
    let path_clone = path.clone();

    let parent = format!(
        r#"
            const net = require('net');
            const server = net.createServer((sock) => {{
                sock.on('data', (chunk) => sock.write(chunk));
                sock.on('end', () => sock.end());
            }});
            server.listen({{ path: '{path}' }}, () => {{
                console.log('UNIX_LISTENING');
            }});
        "#,
        path = path,
    );

    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args(["-A", "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn unix server");

    // Wait for the 'listening' banner.
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel::<()>();
    let _reader = thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stdout);
        for line in r.lines().map_while(Result::ok) {
            if line.contains("UNIX_LISTENING") {
                let _ = tx.send(());
                return;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("burn unix server announced listening");

    // Connect from this thread and exchange bytes.
    let mut conn = UnixStream::connect(&path_clone).expect("connect to burn unix server");
    conn.write_all(b"hello-unix").expect("write");
    conn.flush().ok();
    // Half-close the write side so the server sees EOF and echoes.
    conn.shutdown(Shutdown::Write).ok();

    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    conn.set_read_timeout(Some(Duration::from_secs(10))).ok();
    loop {
        match conn.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    assert_eq!(got, b"hello-unix", "echo mismatch: {:?}", got);

    child.kill().ok();
    child.wait().ok();
    let _ = std::fs::remove_file(&path_clone);
}

/// A JS client inside burn connects to a Unix-domain echo server
/// running in this test thread, sends a payload, and checks the echo.
///
/// Pattern mirrors `round_trip_echo` for TCP.
#[test]
#[serial]
#[cfg(unix)]
fn unix_domain_client_connect() {
    use std::os::unix::net::UnixListener;

    let path = format!("/tmp/burn-test-unix-client-{}.sock", std::process::id());
    let _ = std::fs::remove_file(&path);

    // Native listener.
    let listener = UnixListener::bind(&path).expect("bind unix listener");
    let path_for_server = path.clone();

    let _server = thread::spawn(move || {
        // Accept one connection and echo bytes back (unix_domain_client_connect
        // only sends a single short message then exits).
        if let Some(Ok(mut s)) = listener.incoming().next() {
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        let _ = path_for_server;
    });

    let parent = format!(
        r#"
            const net = require('net');
            const {{ Buffer }} = require('buffer');
            const sock = net.connect({{ path: '{path}' }});
            const got = [];
            sock.on('connect', () => {{
                sock.write(Buffer.from('unix-client-test'));
            }});
            sock.on('data', (chunk) => {{
                got.push(chunk.toString('utf8'));
                const full = got.join('');
                if (full.length >= 'unix-client-test'.length) {{
                    if (full === 'unix-client-test') {{
                        console.log('UNIX_CLIENT_OK');
                    }} else {{
                        console.error('MISMATCH: ' + JSON.stringify(full));
                    }}
                    sock.destroy();
                    process.exit(0);
                }}
            }});
            sock.on('error', (e) => {{
                console.error('error:', e.message);
                process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#,
        path = path,
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn unix client");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("UNIX_CLIENT_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// A JS `dgram` socket binds, and a native UDP client sends it a datagram which
/// the JS echoes back. Exercises inbound `'message'` delivery (the daemon-event
/// translator routing host UDP recv to the dgram handler).
#[test]
#[serial]
fn dgram_inbound_message_round_trip() {
    use std::net::UdpSocket;

    // PID-derived port to avoid collisions across parallel test binaries.
    let port: u16 = 40000 + (std::process::id() % 10000) as u16;

    let parent = format!(
        r#"
            const dgram = require('dgram');
            const sock = dgram.createSocket('udp4');
            sock.on('message', (msg, rinfo) => {{
                sock.send(msg, rinfo.port, rinfo.address);
            }});
            sock.on('listening', () => console.log('DGRAM_LISTENING'));
            sock.on('error', (e) => {{ console.error('error:', e.message); process.exit(2); }});
            sock.bind({port}, '127.0.0.1');
        "#,
        port = port,
    );

    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .args(["-A", "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn dgram server");

    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel::<()>();
    let _reader = thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stdout);
        for line in r.lines().map_while(Result::ok) {
            if line.contains("DGRAM_LISTENING") {
                let _ = tx.send(());
                return;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("burn dgram server announced listening");

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client.set_read_timeout(Some(Duration::from_secs(10))).ok();
    client
        .send_to(b"ping-dgram", ("127.0.0.1", port))
        .expect("send_to");
    let mut buf = [0u8; 64];
    let (n, _from) = client.recv_from(&mut buf).expect("recv_from echo");
    assert_eq!(&buf[..n], b"ping-dgram", "dgram inbound echo mismatch");

    child.kill().ok();
    child.wait().ok();
}
