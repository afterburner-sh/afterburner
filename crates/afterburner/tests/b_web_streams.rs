// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! WHATWG Web Streams (`ReadableStream` / `WritableStream` /
//! `TransformStream`) — pinned end-to-end, including pipeTo /
//! pipeThrough / async iteration / `ReadableStream.from` / cancel
//! propagation / TransformStream-backed CompressionStream.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed. stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

#[test]
fn readable_stream_pipe_to_writable_round_trips_chunks() {
    let out = run_inline(
        r#"
        async function main() {
            const collected = [];
            const rs = new ReadableStream({
                start(c) {
                    c.enqueue(new Uint8Array([1, 2, 3]));
                    c.enqueue(new Uint8Array([4, 5]));
                    c.close();
                },
            });
            const ws = new WritableStream({
                write(chunk) {
                    for (let i = 0; i < chunk.length; i++) collected.push(chunk[i]);
                },
            });
            await rs.pipeTo(ws);
            if (collected.join(',') === '1,2,3,4,5') console.log('PIPE-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "PIPE-OK");
}

#[test]
fn transform_stream_doubles_each_chunk() {
    let out = run_inline(
        r#"
        async function main() {
            const rs = new ReadableStream({
                start(c) { c.enqueue(1); c.enqueue(2); c.enqueue(3); c.close(); },
            });
            const ts = new TransformStream({
                transform(chunk, controller) { controller.enqueue(chunk * 10); },
            });
            const collected = [];
            await rs.pipeThrough(ts).pipeTo(new WritableStream({
                write(c) { collected.push(c); },
            }));
            if (collected.join(',') === '10,20,30') console.log('TF-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "TF-OK");
}

#[test]
fn readable_stream_async_iterator_yields_chunks() {
    let out = run_inline(
        r#"
        async function main() {
            const rs = new ReadableStream({
                start(c) { c.enqueue('a'); c.enqueue('b'); c.enqueue('c'); c.close(); },
            });
            const collected = [];
            for await (const chunk of rs) collected.push(chunk);
            if (collected.join(',') === 'a,b,c') console.log('ITER-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "ITER-OK");
}

#[test]
fn readable_stream_from_iterable_static_constructor() {
    let out = run_inline(
        r#"
        async function main() {
            const rs = ReadableStream.from([10, 20, 30]);
            const collected = [];
            const reader = rs.getReader();
            while (true) {
                const r = await reader.read();
                if (r.done) break;
                collected.push(r.value);
            }
            if (collected.join(',') === '10,20,30') console.log('FROM-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "FROM-OK");
}

#[test]
fn readable_stream_locked_after_get_reader() {
    let out = run_inline(
        r#"
        const rs = new ReadableStream({ start(c) { c.close(); } });
        if (rs.locked === false) {
            rs.getReader();
            if (rs.locked === true) console.log('LOCK-OK');
            else console.log('FAIL post-get');
        } else console.log('FAIL pre-get');
        "#,
    );
    assert_marker(&out, "LOCK-OK");
}

#[test]
fn readable_stream_cancel_invokes_source_cancel() {
    let out = run_inline(
        r#"
        async function main() {
            let cancelled = null;
            const rs = new ReadableStream({
                start(c) { c.enqueue(1); },
                cancel(reason) { cancelled = reason; },
            });
            await rs.cancel('user-stop');
            if (cancelled === 'user-stop') console.log('CANCEL-OK');
            else console.log('FAIL', cancelled);
        }
        main();
        "#,
    );
    assert_marker(&out, "CANCEL-OK");
}

#[test]
fn writable_stream_close_drains_then_resolves() {
    let out = run_inline(
        r#"
        async function main() {
            const written = [];
            let closed = false;
            const ws = new WritableStream({
                write(c) { written.push(c); },
                close() { closed = true; },
            });
            const w = ws.getWriter();
            await w.write('a');
            await w.write('b');
            await w.close();
            if (written.join(',') === 'a,b' && closed) console.log('WS-OK');
            else console.log('FAIL', written.join(','), closed);
        }
        main();
        "#,
    );
    assert_marker(&out, "WS-OK");
}

#[test]
fn compression_stream_gzip_round_trips_via_streams() {
    let out = run_inline(
        r#"
        async function main() {
            const src = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
            const rs = new ReadableStream({
                start(c) { c.enqueue(src); c.close(); },
            });
            const compressed = rs.pipeThrough(new CompressionStream('gzip'));
            const restored = compressed.pipeThrough(new DecompressionStream('gzip'));
            const collected = [];
            await restored.pipeTo(new WritableStream({
                write(c) { for (let i = 0; i < c.length; i++) collected.push(c[i]); },
            }));
            if (collected.join(',') === '72,101,108,108,111') console.log('CS-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "CS-OK");
}

#[test]
fn transform_stream_flush_runs_at_end() {
    let out = run_inline(
        r#"
        async function main() {
            const ts = new TransformStream({
                transform(chunk, controller) { controller.enqueue(chunk + 1); },
                flush(controller) { controller.enqueue(99); },
            });
            const rs = new ReadableStream({
                start(c) { c.enqueue(1); c.enqueue(2); c.close(); },
            });
            const collected = [];
            await rs.pipeThrough(ts).pipeTo(new WritableStream({
                write(c) { collected.push(c); },
            }));
            if (collected.join(',') === '2,3,99') console.log('FLUSH-OK');
            else console.log('FAIL', collected.join(','));
        }
        main();
        "#,
    );
    assert_marker(&out, "FLUSH-OK");
}
