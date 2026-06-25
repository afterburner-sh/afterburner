// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Shared helpers for integration tests that spawn `burn` as a
//! subprocess.
//!
//! Cargo treats subdirectories of `tests/` as plain modules (not
//! separate test binaries), so any sibling `tests/b_*.rs` can pull
//! these helpers in with `mod common;` without producing an extra
//! `common` executable in the cargo test report.
//!
//! Design goal: replace the byte-for-byte duplicate helpers that
//! used to live in b_shard_pool, b2_http_server, b2b_multiplex,
//! b_daemon_init_bytecode, and b_cluster_multiproc with a single
//! source of truth. The wait-for-listener path is also upgraded
//! from blind 15s TCP polling to a stdout-marker + TCP-poll race,
//! which is what fixes the b_shard_pool flakiness on cold CI
//! runners.

#![allow(dead_code)] // each sibling test binary uses a subset

use kovan_channel::flavors::unbounded::{Receiver, Sender, channel};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Pre-bind to ephemeral port 0 to claim a free port from the OS,
/// then drop the listener so the spawned `burn` can re-bind on it.
/// The race window between drop and re-bind is tens of microseconds;
/// in practice tests using this don't collide.
pub fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

/// RAII wrapper for spawned `burn` children. Kills + reaps on Drop -
/// even when the surrounding test panics, the child won't outlive
/// the test process.
pub struct ChildGuard(Option<Child>);

impl ChildGuard {
    pub fn new(c: Child) -> Self {
        Self(Some(c))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl std::ops::Deref for ChildGuard {
    type Target = Child;
    fn deref(&self) -> &Child {
        self.0.as_ref().expect("child taken")
    }
}

impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child taken")
    }
}

/// Watches a child's stdout in a background thread. Each line is
/// scanned for the configured marker substring; the first match
/// flips `marker_seen`. All lines are also pushed through a
/// lock-free channel for post-mortem inspection on test failure.
///
/// The reader thread is detached and exits naturally when the
/// child closes its stdout (process exit / kill). The watcher
/// itself is cheap to drop and never blocks.
pub struct StdoutWatcher {
    pub marker_seen: Arc<AtomicBool>,
    lines_rx: Receiver<String>,
}

impl StdoutWatcher {
    pub fn spawn(stdout: ChildStdout, marker: String) -> Self {
        let marker_seen = Arc::new(AtomicBool::new(false));
        let (tx, rx): (Sender<String>, Receiver<String>) = channel();
        let seen = marker_seen.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(l) = line else {
                    break;
                };
                if l.contains(&marker) {
                    seen.store(true, Ordering::Release);
                }
                tx.send(l);
            }
        });
        Self {
            marker_seen,
            lines_rx: rx,
        }
    }

    /// Drain any lines buffered in the channel without blocking.
    /// Useful for building a diagnostic on timeout.
    pub fn drain_lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(l) = self.lines_rx.try_recv() {
            out.push(l);
        }
        out
    }
}

/// Race a stdout-marker watch against TCP-connect polling, returning
/// Ok(()) as soon as either confirms the daemon is reachable. On
/// timeout the error message embeds the drained stdout (and stderr
/// if provided) so failures are diagnosable instead of opaque.
///
/// The marker is the substring the watcher was constructed with;
/// e.g. tests inject `console.log('LISTENING:<port>')` into the JS
/// `.listen` callback and pass `format!("LISTENING:{port}")` here.
pub fn wait_for_listening(
    watcher: &StdoutWatcher,
    port: u16,
    timeout: Duration,
    stderr: Option<&mut ChildStderr>,
) -> Result<(), String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if watcher.marker_seen.load(Ordering::Acquire) {
            return Ok(());
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let lines = watcher.drain_lines();
    let mut err_buf = String::new();
    if let Some(s) = stderr {
        let _ = s.read_to_string(&mut err_buf);
    }
    Err(format!(
        "daemon never became ready on :{port} within {timeout:?}\n\
         --- buffered stdout ({n} lines) ---\n{stdout}\n\
         --- captured stderr ---\n{stderr}",
        n = lines.len(),
        stdout = lines.join("\n"),
        stderr = err_buf,
    ))
}

/// JS snippet that calls `console.log('LISTENING:<port>')` once. Pass
/// this into a `.listen(port, () => { ... })` callback or to an
/// `on('listening', () => { ... })` event handler so the marker fires
/// the moment the kernel accepts the bind.
///
/// The `LISTENING:<port>` format includes the port so a test waiting
/// on multiple listeners can disambiguate.
pub fn listening_marker_js(port: u16) -> String {
    format!("console.log('LISTENING:{port}');")
}

/// Spawn a fully-configured `burn` Command, attach a stdout marker
/// watcher, and block until either the LISTENING marker appears in
/// stdout or a TCP connect succeeds. On timeout, panics with a
/// diagnostic dump of stdout + stderr. Returns the child guard plus
/// the still-attached watcher so callers can drain post-readiness
/// stdout lines if needed.
///
/// Callers must shape their JS to print `console.log('LISTENING:' +
/// port)` from the `.listen` callback (see `listening_marker_js`).
/// The TCP fallback covers any test whose JS doesn't cooperate.
pub fn spawn_and_wait_listening(
    mut cmd: Command,
    port: u16,
    timeout: Duration,
) -> (ChildGuard, StdoutWatcher) {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn burn");
    let stdout = child.stdout.take().expect("stdout piped");
    let watcher = StdoutWatcher::spawn(stdout, format!("LISTENING:{port}"));
    let mut guard = ChildGuard::new(child);
    if let Err(e) = wait_for_listening(&watcher, port, timeout, guard.stderr.as_mut()) {
        panic!("{e}");
    }
    (guard, watcher)
}

/// Minimal HTTP/1.1 GET against 127.0.0.1:<port>. Returns the full
/// raw response (status line + headers + body). Use `extract_body`
/// to split out the body half.
pub fn http_get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).expect("write");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read");
    resp
}

/// Minimal HTTP/1.1 POST against 127.0.0.1:<port>. Caller picks the
/// content-type so JSON vs text/plain handlers can both be tested.
/// Returns the full raw response.
pub fn http_post(port: u16, path: &str, body: &str, content_type: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes()).expect("write");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read");
    resp
}

/// TCP-only readiness poll - no stdout marker required. Returns true
/// if the kernel accepts a TCP connection on `port` before the
/// deadline. Use this for tests that don't (or can't) inject a
/// LISTENING marker into their JS source; for the marker-driven path
/// see `wait_for_listening` / `spawn_and_wait_listening`.
pub fn wait_for_listener(port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

pub fn extract_body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}
