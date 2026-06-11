// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B3 phase gate: daemon mode lifecycle — `process.exit(n)` returns the
//! right code, `setInterval` keeps the daemon alive, `.unref()` lets it
//! exit.
//!
//! Each test spawns `burn -e <source>` as a subprocess and observes exit
//! codes, stdout, and timing behavior.
//!
//! Tests run sequentially (`serial_test`) because they spawn long-lived
//! subprocesses that contend for CPU under parallel execution — debug
//! builds are slow to cold-instantiate the WASM engine, and a dozen
//! parallel instantiations can oversubscribe CPU enough that the
//! timing assertions below (exit-within-10s etc.) flake.

#![cfg(feature = "bin")]

use serial_test::serial;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

// ---- process.exit propagation -------------------------------------------

#[test]
#[serial]
fn process_exit_zero_from_script() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg("console.log('before'); process.exit(0);")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(
        out.status.success(),
        "expected exit 0, got {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("before"),
        "stdout should contain output before exit"
    );
}

#[test]
#[serial]
fn process_exit_nonzero_from_script() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg("console.log('exiting'); process.exit(42);")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(
        !out.status.success(),
        "expected non-zero exit, got {}",
        out.status
    );
    assert_eq!(
        out.status.code(),
        Some(42),
        "expected exit code 42, got {:?}",
        out.status.code()
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("exiting"),
        "stdout should contain output before exit"
    );
}

#[test]
#[serial]
fn process_exit_without_arg_is_zero() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg("process.exit();")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(
        out.status.success(),
        "exit() with no arg should be 0, got {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- setInterval keeps daemon alive -------------------------------------

#[test]
#[serial]
fn setinterval_keeps_daemon_alive() {
    // Script uses setInterval to log periodically. We wait for a few
    // ticks then kill the process — the key assertion is that it did
    // NOT exit immediately (which it would if setInterval didn't keep
    // the runtime alive).
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            var count = 0;
            setInterval(function() {
                count++;
                console.log('tick ' + count);
                if (count >= 3) process.exit(0);
            }, 50);
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn");

    // Give it up to 30 seconds — debug-build WASM engine startup is
    // slow and multiple parallel subprocess tests contend for CPU.
    let out = wait_with_timeout(&mut child, Duration::from_secs(30));
    let stdout = String::from_utf8_lossy(&out.0);
    assert!(
        stdout.contains("tick 1"),
        "should have fired at least once: stdout={stdout}"
    );
    assert!(
        stdout.contains("tick 3"),
        "should have fired 3 times: stdout={stdout}"
    );
    assert!(
        out.2.success(),
        "should exit 0 via process.exit: status={}",
        out.2
    );
}

// ---- setTimeout with non-zero delay in daemon mode ----------------------

#[test]
#[serial]
fn settimeout_nonzero_delay_fires() {
    let start = Instant::now();
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            setTimeout(function() {
                console.log('fired');
                process.exit(0);
            }, 100);
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let elapsed = start.elapsed();

    assert!(
        out.status.success(),
        "exit: {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("fired"),
        "timer should have fired"
    );
    // It should have waited at least ~100ms (allow some slack for CI).
    assert!(
        elapsed >= Duration::from_millis(50),
        "elapsed {elapsed:?} — timer should have waited"
    );
}

// ---- unref lets daemon exit ---------------------------------------------

#[test]
#[serial]
fn unref_timer_lets_daemon_exit() {
    // A setInterval that is immediately unref'd should NOT keep the
    // daemon alive. The process should exit quickly.
    let start = Instant::now();
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            var h = setInterval(function() {
                console.log('should not fire');
            }, 5000);
            h.unref();
            console.log('done');
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let elapsed = start.elapsed();

    assert!(
        out.status.success(),
        "exit: {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("done"), "stdout: {stdout}");
    assert!(
        !stdout.contains("should not fire"),
        "unref'd timer should not fire"
    );
    // Should exit well before the 5-second interval. The ceiling
    // absorbs debug-build WASM engine startup; on cold GH 4-vCPU
    // runners this dominates real wall time.
    assert!(
        elapsed < Duration::from_secs(90),
        "elapsed {elapsed:?} — should exit quickly"
    );
}

// ---- clearInterval lets daemon exit -------------------------------------

#[test]
#[serial]
fn clearinterval_lets_daemon_exit() {
    let start = Instant::now();
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            var count = 0;
            var h = setInterval(function() {
                count++;
                console.log('tick ' + count);
                if (count >= 2) clearInterval(h);
            }, 50);
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let elapsed = start.elapsed();

    assert!(
        out.status.success(),
        "exit: {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tick 2"), "stdout: {stdout}");
    // Should exit, not hang forever. Ceiling absorbs debug-build
    // WASM engine startup on cold CI runners.
    assert!(
        elapsed < Duration::from_secs(90),
        "elapsed {elapsed:?} — should exit after clearing"
    );
}

// ---- process.exit from within daemon-event (HTTP handler) ---------------

#[test]
#[serial]
fn process_exit_from_http_handler() {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};

    fn pick_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let p = l.local_addr().expect("local_addr").port();
        drop(l);
        p
    }

    let port = pick_port();
    let source = format!(
        r#"
        const http = require("http");
        http.createServer((_req, res) => {{
            res.end("bye");
            process.exit(7);
        }}).listen({port});
        "#
    );
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(&source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn");

    // Wait for listener. 60s ceiling absorbs cold GH 4-vCPU cold-spawn.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Fire a request that triggers process.exit(7).
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        let req = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(req.as_bytes());
        let mut resp = String::new();
        let _ = stream.read_to_string(&mut resp);
    }

    let out = wait_with_timeout(&mut child, Duration::from_secs(90));
    assert_eq!(
        out.2.code(),
        Some(7),
        "HTTP handler's process.exit(7) should propagate, got {:?}",
        out.2.code()
    );
}

// ---- process.exit emits 'exit' event before exiting ---------------------

#[test]
#[serial]
fn process_exit_emits_exit_event() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            process.on('exit', function(code) {
                console.log('exit event code=' + code);
            });
            console.log('before');
            process.exit(0);
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("before"), "stdout: {stdout}");
    assert!(
        stdout.contains("exit event code=0"),
        "exit event should fire: {stdout}"
    );
}

// ---- clearTimeout for one-shot timer ------------------------------------

#[test]
#[serial]
fn cleartimeout_prevents_fire() {
    let start = Instant::now();
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            var h = setTimeout(function() {
                console.log('should not fire');
            }, 5000);
            clearTimeout(h);
            console.log('cleared');
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let elapsed = start.elapsed();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("cleared"), "stdout: {stdout}");
    assert!(
        !stdout.contains("should not fire"),
        "cleared timer should not fire"
    );
    assert!(
        elapsed < Duration::from_secs(90),
        "should exit quickly: {elapsed:?}"
    );
}

// ---- setTimeout(fn, 0) still works as microtask (not host timer) --------

#[test]
#[serial]
fn settimeout_zero_delay_does_not_keep_daemon_alive() {
    // setTimeout(fn, 0) fires via microtask — it should NOT register a
    // host timer or keep the daemon alive. The script should exit cleanly
    // without entering the event loop.
    let start = Instant::now();
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            setTimeout(function() { console.log('zero-delay'); }, 0);
            console.log('sync');
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let elapsed = start.elapsed();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sync"), "stdout: {stdout}");
    assert!(
        stdout.contains("zero-delay"),
        "zero-delay timer should fire as microtask: {stdout}"
    );
    // Should exit fast — no daemon event loop entered. Ceiling
    // absorbs debug-build WASM engine startup on cold CI runners.
    assert!(
        elapsed < Duration::from_secs(90),
        "zero-delay should not keep daemon alive: {elapsed:?}"
    );
}

// ---- ref() re-enables keepalive after unref() ---------------------------

#[test]
#[serial]
fn ref_after_unref_keeps_alive() {
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(
            r#"
            var count = 0;
            var h = setInterval(function() {
                count++;
                console.log('tick ' + count);
                if (count >= 2) process.exit(0);
            }, 50);
            h.unref();
            h.ref();
            "#,
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn");

    let out = wait_with_timeout(&mut child, Duration::from_secs(30));
    let stdout = String::from_utf8_lossy(&out.0);
    assert!(
        stdout.contains("tick 2"),
        "ref() after unref() should keep alive: {stdout}"
    );
    assert!(out.2.success());
}

// ---- helpers ------------------------------------------------------------

/// Wait for a child process with a timeout. Returns (stdout, stderr, status).
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> (Vec<u8>, Vec<u8>, std::process::ExitStatus) {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    use std::io::Read;
                    let _ = out.read_to_end(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_end(&mut stderr);
                }
                return (stdout, stderr, status);
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let status = child.wait().expect("wait after kill");
                    return (Vec::new(), b"timed out".to_vec(), status);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("try_wait: {e}"),
        }
    }
}
