// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! End-to-end `burn npm install` test — proves that the full
//! npm-style install pipeline (registry fetch, manifest resolve,
//! tarball download, decompress, tar extract, write to
//! `node_modules/`) works. This was the structural bar we'd been
//! climbing for the last several rounds of node-compat work.
//!
//! What had to land for this to succeed (each was a hard
//! prerequisite, debugged in this order):
//!
//! 1. **Async outbound HTTP** (`b_async_outbound_http`) — pacote /
//!    make-fetch-happen / minipass-fetch await on Promises that
//!    only resolve when the host signals network completion. Sync
//!    HTTP wouldn't ever drive the chain forward.
//! 2. **RFC 3986 URL resolution** (`b_zlib_streaming::url_*`) — the
//!    npm registry redirects tarball downloads to a CDN; the
//!    Location-header redirect goes through `new URL(loc, base)`.
//!    Without proper relative resolution every redirect ended with
//!    an empty host and a malformed `https:///path` URL.
//! 3. **zlib streaming classes** (`b_zlib_streaming::gunzip_*`) —
//!    minizlib wraps `Gunzip` with `_processChunk`. Empty-finalize
//!    short-circuit keeps the canonical `Z_FINISH` no-op call from
//!    synchronously throwing.
//! 4. **Buffer.toString('base64') de-quadratisation** — string
//!    concat in QuickJS goes quadratic. 50 KB took 800 ms, 315 KB
//!    hung. Chunk-then-join collapsed it to ~30 ms / 200 ms.
//! 5. **`fs.openSync` / `writeSync` / `closeSync` fd table** — tar's
//!    Unpack writes file contents through the classic fd triple,
//!    not through `createWriteStream`. The JS-side fd table maps a
//!    small integer to `{ path, offset }` and routes writes through
//!    the existing `__host_fs_write_chunk` bridge.
//!
//! These tests deliberately hit the network. They're slow (multi-
//! second) and require external connectivity to `registry.npmjs.org`.
//! The fast-path tests in the other suites cover every individual
//! piece in isolation; this file pins the integration that real
//! users care about.

#![cfg(all(feature = "bin", feature = "ts"))]

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static DIR_CTR: AtomicU32 = AtomicU32::new(0);
fn fresh_project(name: &str) -> PathBuf {
    let n = DIR_CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("burn_npm_{name}_{pid}_{n}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("package.json"),
        b"{\"name\":\"burn-npm-test\",\"version\":\"1.0.0\",\"private\":true}\n",
    )
    .unwrap();
    dir
}

fn run_burn_in(dir: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

#[test]
#[ignore = "hits the live npm registry; run explicitly with --ignored"]
fn npm_install_lodash_writes_node_modules() {
    let dir = fresh_project("lodash");
    let out = run_burn_in(&dir, &["npm", "install", "lodash"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "npm install failed. stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("added") || stdout.contains("added"),
        "expected npm 'added N package' summary; stderr={stderr}"
    );
    let lodash_dir = dir.join("node_modules").join("lodash");
    assert!(
        lodash_dir.is_dir(),
        "node_modules/lodash should exist after install: {lodash_dir:?}"
    );
    let pkg = fs::read_to_string(lodash_dir.join("package.json")).expect("read lodash pkg.json");
    assert!(pkg.contains("\"name\": \"lodash\"") || pkg.contains("\"name\":\"lodash\""));
}

#[test]
#[ignore = "hits the live npm registry; run explicitly with --ignored"]
fn npm_install_lodash_then_require_returns_real_lib() {
    // Install + invoke. The require chain has to walk through the
    // freshly-written `node_modules/lodash` and pick up the
    // installed package — a real end-to-end verification that the
    // install produced usable JS, not just a directory of files.
    let dir = fresh_project("lodash_use");
    let install = run_burn_in(&dir, &["npm", "install", "lodash"]);
    assert!(
        install.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );
    let script = dir.join("use.js");
    fs::write(
        &script,
        b"const _ = require('lodash');\
          const r = _.camelCase('hello world burn');\
          if (r !== 'helloWorldBurn') { console.log('MISMATCH:', r); process.exit(1); }\
          console.log('LODASH-OK');\n",
    )
    .unwrap();
    let out = run_burn_in(&dir, &["-A", script.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("LODASH-OK"),
        "lodash not usable. stdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore = "hits the live npm registry; ~30s wall clock; run explicitly"]
fn npm_install_express_then_serve_works() {
    // Installs express + its 60+ transitive deps then starts a
    // server and curls the root. This is the ultimate proof: a
    // real-world dep tree works under burn from clean install
    // through to running a request.
    let dir = fresh_project("express");
    let install = run_burn_in(&dir, &["npm", "install", "express"]);
    let install_stderr = String::from_utf8_lossy(&install.stderr).into_owned();
    assert!(install.status.success(), "install failed: {install_stderr}");
    let express_dir = dir.join("node_modules").join("express");
    assert!(
        express_dir.is_dir(),
        "node_modules/express should exist: {express_dir:?}"
    );
    let port: u16 = 38765 + (std::process::id() as u16 % 1000);
    let script = dir.join("server.js");
    fs::write(
        &script,
        format!(
            "const express = require('express');\
             const app = express();\
             app.get('/', (req, res) => res.send('hello from burn-installed-express'));\
             const port = {port};\
             app.listen(port, () => console.log('SERVING on', port));\n"
        )
        .as_bytes(),
    )
    .unwrap();
    // Spawn server in background; give it time to start; curl; kill.
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(&dir)
        .args(["-A", script.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn server");
    // Poll for "SERVING" line in the child's stdout. Up to 8s.
    let start = std::time::Instant::now();
    let mut listening = false;
    while start.elapsed() < Duration::from_secs(8) {
        std::thread::sleep(Duration::from_millis(100));
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            listening = true;
            break;
        }
    }
    if !listening {
        let _ = child.kill();
        let _ = child.wait();
        panic!("express server didn't start on port {port}");
    }
    // GET /
    let body = curl_get(&format!("http://127.0.0.1:{port}/"));
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        body.contains("hello from burn-installed-express"),
        "unexpected body: {body}"
    );
}

fn curl_get(url: &str) -> String {
    // Cheap one-shot HTTP client — parse a `http://host:port/path`
    // URL by hand (the only shape our test issues), open a TCP
    // socket, write a `GET / HTTP/1.0` line, read until EOF. Keeps
    // the test self-contained — no extra workspace deps just to
    // make a single GET request to localhost.
    let stripped = url.strip_prefix("http://").expect("http:// scheme");
    let (host_port, path) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]),
        None => (stripped, "/"),
    };
    let (host, port) = match host_port.find(':') {
        Some(i) => (
            host_port[..i].to_string(),
            host_port[i + 1..].parse::<u16>().unwrap_or(80),
        ),
        None => (host_port.to_string(), 80u16),
    };
    let mut sock = std::net::TcpStream::connect((host.as_str(), port)).expect("tcp connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    let mut buf = String::new();
    use std::io::Read;
    let _ = sock.read_to_string(&mut buf);
    buf
}
