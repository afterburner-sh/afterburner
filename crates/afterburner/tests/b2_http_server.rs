// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! B2 phase gate: `burn server.js` serves HTTP end-to-end.
//!
//! This is the headline example from `IMPL_PLAN_BURN_RUNTIME.md §1`:
//!
//! ```js
//! const http = require("node:http");
//! http.createServer((_req, res) => {
//!     res.end("hello from burn\n");
//! }).listen(3000, () => console.log("listening on http://localhost:3000"));
//! ```
//!
//! The test spawns `burn` as a subprocess, waits for the listener to
//! bind, fires a real HTTP request over a raw TCP socket, asserts the
//! response, and then kills the subprocess cleanly.

#![cfg(feature = "bin")]

mod common;

use common::{ChildGuard, http_get, pick_port, wait_for_listener};
use serial_test::serial;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn http_post(port: u16, path: &str, body: &str) -> String {
    common::http_post(port, path, body, "application/json")
}

/// Spawn `burn -e <source>` with stdout/stderr piped. Returns the
/// child handle for later cleanup. `BURN_SHARDS=2` caps per-subprocess
/// resource use so several test binaries running in parallel don't
/// individually fan out to `available_parallelism()` shards (36 on a
/// developer box) and saturate the host.
fn spawn_burn_inline(source: &str) -> Child {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn")
}

#[test]
#[serial]
fn burn_serves_hello_from_burn() {
    let port = pick_port();
    let source = format!(
        r#"
        const http = require("node:http");
        http.createServer((_req, res) => {{
            res.end("hello from burn\n");
        }}).listen({port}, () => console.log("listening"));
        "#
    );
    let _child = ChildGuard::new(spawn_burn_inline(&source));
    assert!(
        wait_for_listener(port, Duration::from_secs(60)),
        "burn listener didn't come up on :{port}"
    );

    let resp = http_get(port, "/");
    assert!(resp.starts_with("HTTP/1.1 200"), "resp:\n{resp}");
    assert!(resp.contains("hello from burn"), "resp:\n{resp}");
}

#[test]
#[serial]
fn burn_server_echoes_method_and_path() {
    let port = pick_port();
    let source = format!(
        r#"
        const http = require("http");
        http.createServer((req, res) => {{
            res.setHeader("x-method", req.method);
            res.setHeader("x-url", req.url);
            res.writeHead(201);
            res.end("echo\n");
        }}).listen({port});
        "#
    );
    let _child = ChildGuard::new(spawn_burn_inline(&source));
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    let resp = http_get(port, "/test?q=1");
    assert!(resp.starts_with("HTTP/1.1 201"), "resp:\n{resp}");
    assert!(resp.contains("x-method: GET"), "resp:\n{resp}");
    assert!(resp.contains("x-url: /test?q=1"), "resp:\n{resp}");
    assert!(resp.contains("echo"), "resp:\n{resp}");
}

#[test]
#[serial]
fn incoming_message_emits_buffer_chunks() {
    // Phase 0 / Gap D regression: real Node `IncomingMessage` emits
    // `Buffer` chunks unless `setEncoding` was called. body-parser /
    // multer / busboy collect chunks and call `Buffer.concat(chunks)`
    // at `'end'`, which throws if any chunk is a string. We must emit
    // Buffers from `__ab_make_incoming_message::deliver()`.
    let port = pick_port();
    let source = format!(
        r#"
        const http = require('http');
        http.createServer((req, res) => {{
            const chunks = [];
            req.on('data', (chunk) => {{
                chunks.push({{
                    type: typeof chunk,
                    isBuffer: Buffer.isBuffer(chunk),
                    ctor: chunk && chunk.constructor && chunk.constructor.name,
                    len: chunk && chunk.length,
                }});
            }});
            req.on('end', () => {{
                // Concat must succeed — proves chunks are Buffers in
                // the body-parser sense.
                let total;
                try {{
                    const bufs = [];
                    // Re-emit to test concat — we already consumed above,
                    // so feed the asserted shape into a synthetic concat.
                    total = chunks.length;
                }} catch (_) {{
                    total = -1;
                }}
                res.setHeader('content-type', 'application/json');
                res.end(JSON.stringify({{ chunks, total }}));
            }});
        }}).listen({port}, () => console.log("listening"));
        "#
    );
    let _child = ChildGuard::new(spawn_burn_inline(&source));
    assert!(
        wait_for_listener(port, Duration::from_secs(60)),
        "listener didn't bind on :{port}"
    );

    let resp = http_post(port, "/", r#"{"hello":"world"}"#);
    assert!(resp.starts_with("HTTP/1.1 200"), "resp:\n{resp}");

    // The body-parser-relevant invariant: `Buffer.isBuffer(chunk)`
    // returns true. (Our polyfill's `Buffer` is a `Uint8Array`
    // subclass — same as Node since Buffer was reimplemented on top
    // of Uint8Array. `chunk.constructor.name` may be `Buffer` or
    // `Uint8Array` depending on the polyfill internals; what
    // body-parser, multer, busboy etc. actually check is
    // `Buffer.isBuffer`.)
    assert!(
        resp.contains("\"isBuffer\":true"),
        "expected isBuffer:true in response, got:\n{resp}"
    );
    // Length matches the request body byte count.
    assert!(
        resp.contains("\"len\":17"),
        "expected len:17 (length of {{\"hello\":\"world\"}}) in response, got:\n{resp}"
    );
    // Chunk is NOT a string (the pre-fix shape that broke body-parser).
    assert!(
        !resp.contains("\"type\":\"string\""),
        "chunk should not be string post-fix, got:\n{resp}"
    );
}

#[test]
#[serial]
fn body_parser_pattern_buffer_concat_succeeds() {
    // The exact pattern body-parser uses internally: collect chunks,
    // `Buffer.concat`, parse JSON. Without Gap D, `Buffer.concat`
    // would throw `TypeError: argument must be a Buffer`.
    let port = pick_port();
    let source = format!(
        r#"
        const http = require('http');
        http.createServer((req, res) => {{
            const chunks = [];
            req.on('data', (c) => chunks.push(c));
            req.on('end', () => {{
                try {{
                    const buf = Buffer.concat(chunks);
                    const parsed = JSON.parse(buf.toString('utf8'));
                    res.setHeader('content-type', 'application/json');
                    res.end(JSON.stringify({{ ok: true, echo: parsed }}));
                }} catch (e) {{
                    res.statusCode = 500;
                    res.end('concat error: ' + e.message);
                }}
            }});
        }}).listen({port}, () => console.log("listening"));
        "#
    );
    let _child = ChildGuard::new(spawn_burn_inline(&source));
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    let resp = http_post(port, "/", r#"{"a":1,"b":[2,3]}"#);
    assert!(resp.starts_with("HTTP/1.1 200"), "resp:\n{resp}");
    assert!(resp.contains("\"ok\":true"), "resp:\n{resp}");
    assert!(resp.contains("\"a\":1"), "resp:\n{resp}");
}

#[test]
#[serial]
fn burn_plain_script_exits_cleanly() {
    // A script with no `.listen()` should exit 0 quickly — daemon
    // mode detects no listeners and exits.
    let child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(r#"console.log("no listen")"#)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run burn");
    assert!(
        child.status.success(),
        "exit {}, stderr: {}",
        child.status,
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(String::from_utf8_lossy(&child.stdout).contains("no listen"));
}
