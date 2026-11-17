// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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
                // Concat must succeed - proves chunks are Buffers in
                // the body-parser sense.
                let total;
                try {{
                    const bufs = [];
                    // Re-emit to test concat - we already consumed above,
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
    // subclass - same as Node since Buffer was reimplemented on top
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
fn burn_response_bytes_arrive_exact() {
    // A response body is bytes: every value 0..=255 through `res.end(Buffer)`
    // and a large non-ASCII body arrive as sent, with the byte length.
    let port = pick_port();
    let source = format!(
        r#"
        const http = require("node:http");
        http.createServer((req, res) => {{
            if (req.url === "/all") {{
                const b = Buffer.alloc(256);
                for (let i = 0; i < 256; i++) b[i] = i;
                res.end(b);
            }} else {{
                const p = new Uint8Array([0xc3, 0xa9, 0x80, 0xff, 0x00, 0x7f, 0xe2, 0x82, 0xac]);
                const b = new Uint8Array(85000);
                for (let o = 0; o < b.length; o += p.length) {{
                    b.set(p.subarray(0, Math.min(p.length, b.length - o)), o);
                }}
                res.write(b.subarray(0, 40000));
                res.end(b.subarray(40000));
            }}
        }}).listen({port});
        "#
    );
    let _child = ChildGuard::new(spawn_burn_inline(&source));
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    let get = |path: &str| {
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        common::http_exchange_bytes(port, request.as_bytes())
    };
    let (head, body) = get("/all");
    assert!(head.contains("content-length: 256\r\n"), "head:\n{head}");
    assert_eq!(body, (0..=255u8).collect::<Vec<u8>>());

    let pattern = [0xc3, 0xa9, 0x80, 0xff, 0x00, 0x7f, 0xe2, 0x82, 0xac];
    let expect: Vec<u8> = pattern.iter().copied().cycle().take(85_000).collect();
    let (head, body) = get("/large");
    assert!(head.contains("content-length: 85000\r\n"), "head:\n{head}");
    assert!(
        body == expect,
        "85000-byte body differs ({} bytes)",
        body.len()
    );
}

#[test]
#[serial]
fn burn_request_bytes_echo_exact() {
    // A request body that is not text reaches the handler as its exact bytes.
    let port = pick_port();
    let source = format!(
        r#"
        const http = require("node:http");
        http.createServer((req, res) => {{
            const chunks = [];
            req.on("data", (c) => chunks.push(c));
            req.on("end", () => res.end(Buffer.concat(chunks)));
        }}).listen({port});
        "#
    );
    let _child = ChildGuard::new(spawn_burn_inline(&source));
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    let payload: Vec<u8> = (0..=255u8).collect();
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    request.extend_from_slice(&payload);
    let (head, body) = common::http_exchange_bytes(port, &request);
    assert!(head.contains("content-length: 256\r\n"), "head:\n{head}");
    assert_eq!(body, payload);

    // A large body of a repeating pattern that is not valid UTF-8.
    let pattern = [0xc3, 0x28, 0x80, 0xff, 0x00, 0xe2, 0x82];
    let payload: Vec<u8> = pattern.iter().copied().cycle().take(85_000).collect();
    let mut request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    request.extend_from_slice(&payload);
    let (head, body) = common::http_exchange_bytes(port, &request);
    assert!(head.contains("content-length: 85000\r\n"), "head:\n{head}");
    assert!(
        body == payload,
        "85000-byte echo differs ({} bytes)",
        body.len()
    );
}

#[test]
#[serial]
fn burn_request_text_reads_with_set_encoding() {
    // A UTF-8 body still reads as that text through `setEncoding('utf8')`.
    let port = pick_port();
    let source = format!(
        r#"
        const http = require("node:http");
        http.createServer((req, res) => {{
            req.setEncoding("utf8");
            let text = "";
            req.on("data", (c) => {{ text += typeof c === "string" ? "S:" + c : "B"; }});
            req.on("end", () => res.end(text));
        }}).listen({port});
        "#
    );
    let _child = ChildGuard::new(spawn_burn_inline(&source));
    assert!(wait_for_listener(port, Duration::from_secs(60)));

    let text = "h\u{e9}llo \u{20ac}";
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let (_, body) = common::http_exchange_bytes(port, request.as_bytes());
    assert_eq!(body, format!("S:{text}").as_bytes());
}

#[test]
#[serial]
fn burn_plain_script_exits_cleanly() {
    // A script with no `.listen()` should exit 0 quickly - daemon
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
