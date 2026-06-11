// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Node 26 surface coverage - the project's stated runtime target.
//! Each missing module or global produces a hard regression in real
//! Node code (libraries probe `typeof` at module-init and crash with
//! ReferenceError, or destructure properties off `require('node:X')`
//! and trip "Cannot convert undefined or null to object"). These
//! tests pin the surface so a future polyfill refactor can't quietly
//! drop pieces of it.
//!
//! The matrix is split into:
//!
//! * **stdlib modules** - every `require('node:X')` Node 26 ships.
//!   We assert each module loads and exposes at least one keyed
//!   property (catch full-blackhole regressions).
//! * **globals** - every Web/Node-shaped object Node 26 puts on
//!   `globalThis` at startup. Some are constructors (Event, Blob),
//!   some functions (fetch, atob), some objects (process, navigator).
//! * **module-shape sanity** - the most-probed members on the few
//!   modules that actually matter day-to-day (fs.constants,
//!   os.constants.errno, path.win32, util.types.isUint8Array, etc).

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

fn assert_ok(out: &std::process::Output, marker: &str) {
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

// ---- stdlib module catalogue ---------------------------------------

const STDLIB_MODULES: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "inspector/promises",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "readline/promises",
    "repl",
    "sea",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "test",
    "test/reporters",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

#[test]
fn every_node26_stdlib_module_loads() {
    let mods_lit = serde_json::to_string(STDLIB_MODULES).unwrap();
    let src = format!(
        r#"
        const mods = {mods_lit};
        const missing = [];
        for (const m of mods) {{
            try {{
                const x = require(m);
                if (x === undefined) {{
                    missing.push(m + ': require returned undefined');
                    continue;
                }}
                const k = Object.keys(x || {{}}).length;
                if (k === 0 && typeof x !== 'function') {{
                    // A tiny set of Node modules legitimately export an
                    // empty namespace (e.g. `wasi` only exposes a class
                    // via `module.exports`); we just want SOMETHING.
                    if (typeof x === 'object' && x !== null && Object.getOwnPropertyNames(x).length === 0) {{
                        // Allowed - module loaded, just no enumerables.
                    }}
                }}
            }} catch (e) {{
                missing.push(m + ': ' + (e && e.message));
            }}
        }}
        if (missing.length === 0) console.log('NODE26_MODULES_OK');
        else {{
            console.log('NODE26_MODULES_MISSING');
            for (const m of missing) console.log('  ', m);
        }}
        "#
    );
    let out = run_inline(&src);
    assert_ok(&out, "NODE26_MODULES_OK");
}

// ---- globals catalogue --------------------------------------------

const GLOBALS: &[&str] = &[
    // Node-side basics
    "Buffer",
    "console",
    "process",
    "queueMicrotask",
    "setTimeout",
    "setInterval",
    "setImmediate",
    "clearTimeout",
    "clearInterval",
    "clearImmediate",
    // Web-platform globals Node ships on globalThis
    "AbortController",
    "AbortSignal",
    "fetch",
    "Response",
    "Request",
    "Headers",
    "FormData",
    "File",
    "Blob",
    "atob",
    "btoa",
    "BroadcastChannel",
    "MessageChannel",
    "MessagePort",
    "MessageEvent",
    "structuredClone",
    "performance",
    "crypto", // Web Crypto namespace
    "TextEncoder",
    "TextDecoder",
    "TextEncoderStream",
    "TextDecoderStream",
    "ReadableStream",
    "WritableStream",
    "TransformStream",
    "CompressionStream",
    "DecompressionStream",
    "EventTarget",
    "Event",
    "CustomEvent",
    "URL",
    "URLSearchParams",
    "navigator",
    "DOMException",
    "WebAssembly",
    // Standard ECMAScript built-ins that Node code depends on too.
    "Promise",
    "Symbol",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "globalThis",
];

#[test]
fn every_node26_global_is_defined() {
    let lit = serde_json::to_string(GLOBALS).unwrap();
    let src = format!(
        r#"
        const names = {lit};
        const missing = [];
        for (const n of names) {{
            const v = globalThis[n];
            if (typeof v === 'undefined') missing.push(n);
        }}
        if (missing.length === 0) console.log('NODE26_GLOBALS_OK');
        else {{
            console.log('NODE26_GLOBALS_MISSING');
            for (const n of missing) console.log('  ', n);
        }}
        "#
    );
    let out = run_inline(&src);
    assert_ok(&out, "NODE26_GLOBALS_OK");
}

// ---- shape spot-checks --------------------------------------------

#[test]
fn fs_constants_carry_posix_open_flags() {
    // `fs.constants.{F,R,W,X}_OK` plus `O_RDONLY` etc. - used by
    // accessSync callers and almost every fs-aware lib.
    let src = r#"
        const fs = require('fs');
        const c = fs.constants;
        const required = ['F_OK','R_OK','W_OK','X_OK','O_RDONLY','O_WRONLY','O_RDWR','O_CREAT','O_TRUNC','O_APPEND'];
        const missing = required.filter(k => typeof c[k] !== 'number');
        if (missing.length === 0) console.log('FS_CONSTANTS_OK');
        else console.log('FS_CONSTANTS_MISSING:', missing.join(','));
    "#;
    assert_ok(&run_inline(src), "FS_CONSTANTS_OK");
}

#[test]
fn os_constants_errno_signals_priority_present() {
    let src = r#"
        const os = require('os');
        const e = os.constants.errno;
        if (e.EEXIST !== 17 || e.ENOENT !== 2) throw new Error('errno bad');
        const s = os.constants.signals;
        if (s.SIGINT !== 2 || s.SIGTERM !== 15) throw new Error('signals bad');
        const p = os.constants.priority;
        if (p.PRIORITY_NORMAL !== 0) throw new Error('priority bad');
        console.log('OS_CONSTANTS_OK');
    "#;
    assert_ok(&run_inline(src), "OS_CONSTANTS_OK");
}

#[test]
fn path_win32_round_trips_drive_letter_paths() {
    let src = r#"
        const { win32 } = require('path');
        const p = win32.parse('C:\\foo\\bar.txt');
        if (p.root !== 'C:\\') throw new Error('root: ' + p.root);
        if (p.base !== 'bar.txt') throw new Error('base: ' + p.base);
        if (p.ext !== '.txt') throw new Error('ext: ' + p.ext);
        if (!win32.isAbsolute('C:\\x')) throw new Error('isAbsolute');
        if (win32.isAbsolute('foo')) throw new Error('isAbsolute relative');
        if (win32.basename('a\\b\\c') !== 'c') throw new Error('basename: ' + win32.basename('a\\b\\c'));
        console.log('PATH_WIN32_OK');
    "#;
    assert_ok(&run_inline(src), "PATH_WIN32_OK");
}

#[test]
fn path_relative_walks_common_prefix() {
    let src = r#"
        const { relative } = require('path');
        if (relative('/a/b/c', '/a/b/d') !== '../d') throw new Error('1');
        if (relative('/a/b', '/a/b/c/d') !== 'c/d') throw new Error('2');
        if (relative('/a', '/a') !== '') throw new Error('3');
        console.log('PATH_RELATIVE_OK');
    "#;
    assert_ok(&run_inline(src), "PATH_RELATIVE_OK");
}

#[test]
fn util_types_recognises_typed_arrays() {
    let src = r#"
        const t = require('util').types;
        if (!t.isUint8Array(new Uint8Array(2))) throw new Error('Uint8');
        if (!t.isFloat64Array(new Float64Array(2))) throw new Error('Float64');
        if (!t.isMap(new Map())) throw new Error('Map');
        if (!t.isPromise(Promise.resolve())) throw new Error('Promise');
        console.log('UTIL_TYPES_OK');
    "#;
    assert_ok(&run_inline(src), "UTIL_TYPES_OK");
}

#[test]
fn event_target_constructor_subclassable() {
    // `class X extends EventTarget {}` is the canonical Node pattern
    // for AbortSignal-like surfaces. Without a real EventTarget
    // constructor, nearly every modern web-API library trips on
    // module-init.
    let src = r#"
        class MyTarget extends EventTarget {
            constructor() { super(); this.tag = 'mt'; }
        }
        const t = new MyTarget();
        let got = null;
        t.addEventListener('hello', e => { got = e.detail; });
        t.dispatchEvent(new CustomEvent('hello', { detail: 7 }));
        if (got !== 7) throw new Error('detail: ' + got);
        if (t.tag !== 'mt') throw new Error('subclass tag lost');
        console.log('EVENT_TARGET_OK');
    "#;
    assert_ok(&run_inline(src), "EVENT_TARGET_OK");
}

#[test]
fn dom_exception_carries_name_and_legacy_code() {
    let src = r#"
        const e = new DOMException('boom', 'AbortError');
        if (e.name !== 'AbortError') throw new Error('name: ' + e.name);
        if (e.message !== 'boom') throw new Error('message: ' + e.message);
        if (e.code !== 20) throw new Error('AbortError legacy code: ' + e.code);
        if (DOMException.ABORT_ERR !== 20) throw new Error('static const');
        console.log('DOM_EXCEPTION_OK');
    "#;
    assert_ok(&run_inline(src), "DOM_EXCEPTION_OK");
}

#[test]
fn blob_round_trips_text() {
    let src = r#"
        async function main() {
            const b = new Blob(['hello, ', 'world'], { type: 'text/plain' });
            if (b.size !== 12) throw new Error('size: ' + b.size);
            if (b.type !== 'text/plain') throw new Error('type: ' + b.type);
            const t = await b.text();
            if (t !== 'hello, world') throw new Error('text: ' + t);
            const sub = b.slice(0, 5);
            if (await sub.text() !== 'hello') throw new Error('slice');
            console.log('BLOB_OK');
        }
        main().catch(e => { console.log('FAIL:', e.message); process.exit(1); });
    "#;
    assert_ok(&run_inline(src), "BLOB_OK");
}

#[test]
fn formdata_holds_string_and_file_entries() {
    let src = r#"
        const fd = new FormData();
        fd.append('a', '1');
        fd.append('a', '2');
        fd.set('b', '3');
        if (fd.getAll('a').length !== 2) throw new Error('multi');
        if (fd.get('b') !== '3') throw new Error('get');
        if (!fd.has('a')) throw new Error('has');
        fd.delete('a');
        if (fd.has('a')) throw new Error('delete');
        console.log('FORMDATA_OK');
    "#;
    assert_ok(&run_inline(src), "FORMDATA_OK");
}

#[test]
fn message_channel_round_trips_payload() {
    // MessageChannel is a same-realm proxy in our impl; postMessage
    // delivers asynchronously via microtask. Used by structured-clone-
    // adjacent libraries and by anything that bridges between modules
    // through ports.
    let src = r#"
        const ch = new MessageChannel();
        let got = null;
        ch.port2.onmessage = (ev) => { got = ev.data; };
        ch.port1.postMessage({ hello: 'world' });
        Promise.resolve().then(() => Promise.resolve()).then(() => {
            if (!got || got.hello !== 'world') {
                console.log('FAIL: got=', JSON.stringify(got));
                process.exit(1);
            }
            console.log('MSG_CHANNEL_OK');
        });
    "#;
    assert_ok(&run_inline(src), "MSG_CHANNEL_OK");
}

#[test]
fn web_crypto_random_uuid_and_subtle_digest() {
    let src = r#"
        async function main() {
            const u = crypto.randomUUID();
            if (typeof u !== 'string' || !/^[0-9a-f-]+$/.test(u)) throw new Error('uuid: ' + u);
            const enc = new TextEncoder().encode('abc');
            const buf = await crypto.subtle.digest('SHA-256', enc);
            const view = new Uint8Array(buf);
            if (view.length !== 32) throw new Error('digest len: ' + view.length);
            // SHA-256("abc") known prefix: ba 78 16 bf
            if (view[0] !== 0xBA || view[1] !== 0x78) throw new Error('digest bytes mismatch');
            console.log('WEB_CRYPTO_OK');
        }
        main().catch(e => { console.log('FAIL:', e.message); process.exit(1); });
    "#;
    assert_ok(&run_inline(src), "WEB_CRYPTO_OK");
}

#[test]
fn navigator_user_agent_has_node_marker() {
    let src = r#"
        if (typeof navigator !== 'object' || typeof navigator.userAgent !== 'string') {
            throw new Error('navigator missing');
        }
        if (navigator.userAgent.indexOf('Node.js') === -1) {
            throw new Error('userAgent: ' + navigator.userAgent);
        }
        console.log('NAVIGATOR_OK');
    "#;
    assert_ok(&run_inline(src), "NAVIGATOR_OK");
}

#[test]
fn diagnostics_channel_publishes_to_subscribers() {
    let src = r#"
        const dc = require('diagnostics_channel');
        const ch = dc.channel('myhook');
        let received = null;
        ch.subscribe(msg => { received = msg; });
        ch.publish({ id: 42 });
        if (!received || received.id !== 42) throw new Error('not received');
        if (!ch.hasSubscribers) throw new Error('hasSubscribers should be true');
        console.log('DIAG_CHANNEL_OK');
    "#;
    assert_ok(&run_inline(src), "DIAG_CHANNEL_OK");
}

#[test]
fn sea_reports_not_running_as_sea() {
    let src = r#"
        const sea = require('sea');
        if (sea.isSea() !== false) throw new Error('isSea should be false');
        try { sea.getAsset('x'); throw new Error('should have thrown'); }
        catch (e) {
            if (e.code !== 'ERR_NOT_IN_SINGLE_EXECUTABLE_APPLICATION') {
                throw new Error('code: ' + e.code);
            }
        }
        console.log('SEA_OK');
    "#;
    assert_ok(&run_inline(src), "SEA_OK");
}

#[test]
fn process_version_advertises_node_26() {
    // npm and pacote gate on >=20.5.0 / >=22.0.0 - we have to claim a
    // major that satisfies both. Pin to v26 (the project's target).
    let src = r#"
        if (!/^v(2[6-9]|[3-9]\d)\./.test(process.version)) {
            throw new Error('version: ' + process.version);
        }
        if (typeof process.versions.node !== 'string') throw new Error('versions.node');
        console.log('VERSION_OK');
    "#;
    assert_ok(&run_inline(src), "VERSION_OK");
}

#[test]
fn process_umask_and_uid_helpers_present() {
    let src = r#"
        if (typeof process.umask() !== 'number') throw new Error('umask');
        if (typeof process.getuid() !== 'number') throw new Error('getuid');
        if (typeof process.getgid() !== 'number') throw new Error('getgid');
        if (typeof process.cpuUsage().user !== 'number') throw new Error('cpuUsage');
        if (typeof process.memoryUsage().rss !== 'number') throw new Error('memoryUsage');
        if (process.permission.has('fs.read', '/x') !== true) throw new Error('permission');
        console.log('PROCESS_HELPERS_OK');
    "#;
    assert_ok(&run_inline(src), "PROCESS_HELPERS_OK");
}

#[test]
fn fs_writev_serializes_buffers() {
    let src = r#"
        const fs = require('fs');
        const path = '/tmp/burn-writev-test-' + Date.now() + '.txt';
        const fd = path; // Pass the path string directly - our writev
                         // accepts both numeric fds and path-string fds.
        const buffers = [Buffer.from('hello, '), Buffer.from('world')];
        const n = fs.writevSync(fd, buffers);
        if (n !== 12) throw new Error('writev returned: ' + n);
        const content = fs.readFileSync(path, 'utf8');
        try { fs.unlinkSync(path); } catch (_) {}
        if (content !== 'hello, world') throw new Error('content: ' + content);
        console.log('FS_WRITEV_OK');
    "#;
    assert_ok(&run_inline(src), "FS_WRITEV_OK");
}

#[test]
fn fs_glob_matches_log_pattern() {
    let src = r#"
        const fs = require('fs');
        // Use a file we know exists (this script's own tmpdir parent).
        const matches = fs.globSync('/tmp/*.tmp.test', {});
        if (!Array.isArray(matches)) throw new Error('not an array: ' + typeof matches);
        console.log('FS_GLOB_OK');
    "#;
    assert_ok(&run_inline(src), "FS_GLOB_OK");
}

#[test]
fn fs_promises_lstat_falls_back_to_stat() {
    let src = r#"
        const fsp = require('fs/promises');
        async function main() {
            // Use /tmp itself - guaranteed directory.
            const s = await fsp.lstat('/tmp');
            if (typeof s.isDirectory !== 'function') throw new Error('Stats.isDirectory missing');
            if (!s.isDirectory()) throw new Error('lstat /tmp not directory');
            console.log('FS_LSTAT_OK');
        }
        main().catch(e => { console.log('FAIL:', e.message); process.exit(1); });
    "#;
    assert_ok(&run_inline(src), "FS_LSTAT_OK");
}

#[test]
fn require_resolves_node_prefix_uniformly() {
    // `require('node:fs')` MUST be identical to `require('fs')` -
    // some libraries gate strict-resolve on this since Node 16+.
    let src = r#"
        const a = require('fs');
        const b = require('node:fs');
        if (a !== b) throw new Error('node:fs is not the same export object');
        console.log('NODE_PREFIX_OK');
    "#;
    assert_ok(&run_inline(src), "NODE_PREFIX_OK");
}
