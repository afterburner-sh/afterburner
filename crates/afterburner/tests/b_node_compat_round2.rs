// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Round-2 Node 20 built-in coverage — every module added to plug
//! the gap between "stubbed" and "actually loadable".
//!
//! Each test runs a small JS program through `burn -e` that imports
//! the new polyfill, exercises its public surface, and asserts the
//! shape matches Node's. Tests are grouped per module; each group
//! covers the API the embedding database UDF / stream-processing
//! workload is most likely to hit.

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", source])
        .output()
        .expect("spawn burn")
}

/// Same as [`run_inline`] but also clears every color-affecting
/// environment variable. The tty / process polyfills now honour
/// `COLORTERM`/`FORCE_COLOR`/`NO_COLOR`/`TERM` for real, so tests
/// that assert deterministic color-depth values need to neutralise
/// the host shell's environment.
fn run_inline_no_color(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .env("NO_COLOR", "1")
        .env_remove("FORCE_COLOR")
        .env_remove("COLORTERM")
        .env_remove("TERM")
        .args(["-A", "-e", source])
        .output()
        .expect("spawn burn")
}

fn assert_ok(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(marker),
        "missing `{marker}`. stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

// ----- perf_hooks ------------------------------------------------------

#[test]
#[serial]
fn perf_hooks_module_loads_and_exposes_performance() {
    let src = r#"
        const ph = require('perf_hooks');
        const checks = [
            typeof ph === 'object',
            typeof ph.performance === 'object',
            typeof ph.performance.now === 'function',
            typeof ph.PerformanceObserver === 'function',
            typeof ph.PerformanceEntry === 'function',
            typeof ph.monitorEventLoopDelay === 'function',
            typeof ph.createHistogram === 'function',
        ];
        if (checks.every(Boolean)) console.log('PERF_SHAPE_OK');
        else { console.error('checks:', checks); process.exit(2); }
    "#;
    assert_ok(&run_inline(src), "PERF_SHAPE_OK");
}

#[test]
#[serial]
fn perf_hooks_mark_and_measure_record_entries() {
    let src = r#"
        const { performance } = require('perf_hooks');
        performance.mark('start');
        for (let i = 0; i < 100; i++) Math.sqrt(i);
        performance.mark('end');
        performance.measure('work', 'start', 'end');
        const measures = performance.getEntriesByType('measure');
        if (measures.length !== 1 || measures[0].name !== 'work') {
            console.error('measures:', JSON.stringify(measures)); process.exit(2);
        }
        if (typeof measures[0].duration !== 'number' || measures[0].duration < 0) {
            console.error('duration:', measures[0].duration); process.exit(3);
        }
        console.log('PERF_MARK_OK');
    "#;
    assert_ok(&run_inline(src), "PERF_MARK_OK");
}

#[test]
#[serial]
fn perf_hooks_observer_buffered_replay() {
    let src = r#"
        const { performance, PerformanceObserver } = require('perf_hooks');
        performance.mark('a');
        performance.mark('b');
        let captured = [];
        const obs = new PerformanceObserver((list) => {
            captured = list.getEntries().map(e => e.name);
        });
        obs.observe({ entryTypes: ['mark'], buffered: true });
        if (captured.length < 2) {
            console.error('captured:', captured); process.exit(2);
        }
        if (captured.indexOf('a') === -1 || captured.indexOf('b') === -1) {
            console.error('missing names:', captured); process.exit(3);
        }
        console.log('PERF_OBS_OK');
    "#;
    assert_ok(&run_inline(src), "PERF_OBS_OK");
}

// ----- async_hooks -----------------------------------------------------

#[test]
#[serial]
fn async_local_storage_basic_run_and_get() {
    let src = r#"
        const { AsyncLocalStorage } = require('async_hooks');
        const als = new AsyncLocalStorage();
        let observed;
        als.run({ requestId: 42 }, () => {
            observed = als.getStore();
        });
        if (!observed || observed.requestId !== 42) {
            console.error(observed); process.exit(2);
        }
        if (als.getStore() !== undefined) {
            console.error('leaked outside run'); process.exit(3);
        }
        console.log('ALS_OK');
    "#;
    assert_ok(&run_inline(src), "ALS_OK");
}

#[test]
#[serial]
fn async_local_storage_nested_runs() {
    let src = r#"
        const { AsyncLocalStorage } = require('async_hooks');
        const als = new AsyncLocalStorage();
        let inner;
        als.run('outer', () => {
            als.run('inner', () => {
                inner = als.getStore();
            });
            if (als.getStore() !== 'outer') {
                console.error('outer store lost'); process.exit(2);
            }
        });
        if (inner !== 'inner') {
            console.error('inner:', inner); process.exit(3);
        }
        console.log('NESTED_OK');
    "#;
    assert_ok(&run_inline(src), "NESTED_OK");
}

#[test]
#[serial]
fn async_resource_runInAsyncScope_invokes_fn() {
    let src = r#"
        const { AsyncResource } = require('async_hooks');
        const res = new AsyncResource('test');
        const value = res.runInAsyncScope(function(a, b) {
            return a + b + this.scale;
        }, { scale: 10 }, 1, 2);
        if (value !== 13) {
            console.error('value:', value); process.exit(2);
        }
        console.log('ASYNC_RES_OK');
    "#;
    assert_ok(&run_inline(src), "ASYNC_RES_OK");
}

// ----- vm --------------------------------------------------------------

#[test]
#[serial]
fn vm_runInThisContext_executes_in_global() {
    let src = r#"
        const vm = require('vm');
        const result = vm.runInThisContext('40 + 2');
        if (result !== 42) {
            console.error('result:', result); process.exit(2);
        }
        console.log('VM_THIS_OK');
    "#;
    assert_ok(&run_inline(src), "VM_THIS_OK");
}

#[test]
#[serial]
fn vm_runInNewContext_isolates_globals() {
    let src = r#"
        const vm = require('vm');
        const sandbox = { x: 10 };
        const value = vm.runInNewContext('x + 5', sandbox);
        if (value !== 15) {
            console.error('value:', value); process.exit(2);
        }
        // Globals leakage check.
        if (typeof globalThis.x !== 'undefined' && globalThis.x === 10) {
            console.error('sandbox leaked into global'); process.exit(3);
        }
        console.log('VM_NEWCTX_OK');
    "#;
    assert_ok(&run_inline(src), "VM_NEWCTX_OK");
}

#[test]
#[serial]
fn vm_script_class_compiles_and_runs() {
    let src = r#"
        const vm = require('vm');
        const script = new vm.Script('1 + 2 + 3');
        const result = script.runInThisContext();
        if (result !== 6) {
            console.error('result:', result); process.exit(2);
        }
        console.log('VM_SCRIPT_OK');
    "#;
    assert_ok(&run_inline(src), "VM_SCRIPT_OK");
}

#[test]
#[serial]
fn vm_compileFunction_produces_callable() {
    let src = r#"
        const vm = require('vm');
        const fn = vm.compileFunction('return a * b', ['a', 'b']);
        if (fn(6, 7) !== 42) {
            console.error('compileFunction result wrong'); process.exit(2);
        }
        console.log('COMPILE_FN_OK');
    "#;
    assert_ok(&run_inline(src), "COMPILE_FN_OK");
}

#[test]
#[serial]
fn vm_isContext_recognizes_created_contexts() {
    let src = r#"
        const vm = require('vm');
        const sandbox = vm.createContext({ a: 1 });
        if (!vm.isContext(sandbox)) {
            console.error('not isContext after createContext'); process.exit(2);
        }
        if (vm.isContext({ plain: true })) {
            console.error('plain object falsely detected as context'); process.exit(3);
        }
        console.log('IS_CTX_OK');
    "#;
    assert_ok(&run_inline(src), "IS_CTX_OK");
}

// ----- v8 --------------------------------------------------------------

#[test]
#[serial]
fn v8_heap_statistics_returns_shape() {
    let src = r#"
        const v8 = require('v8');
        const s = v8.getHeapStatistics();
        const required = ['total_heap_size', 'used_heap_size', 'heap_size_limit'];
        for (const k of required) {
            if (typeof s[k] !== 'number') {
                console.error('missing:', k, s); process.exit(2);
            }
        }
        const spaces = v8.getHeapSpaceStatistics();
        if (!Array.isArray(spaces) || spaces.length === 0) {
            console.error('spaces:', spaces); process.exit(3);
        }
        console.log('V8_STATS_OK');
    "#;
    assert_ok(&run_inline(src), "V8_STATS_OK");
}

#[test]
#[serial]
fn v8_serialize_deserialize_round_trip() {
    let src = r#"
        const v8 = require('v8');
        const original = { a: 1, b: 'two', c: [3, 4, 5] };
        const buf = v8.serialize(original);
        if (!Buffer.isBuffer(buf) && !(buf instanceof Uint8Array)) {
            console.error('not Buffer'); process.exit(2);
        }
        const restored = v8.deserialize(buf);
        if (JSON.stringify(restored) !== JSON.stringify(original)) {
            console.error('mismatch:', restored); process.exit(3);
        }
        console.log('V8_SERIALIZE_OK');
    "#;
    let s = format!("const Buffer = require('buffer').Buffer; {src}");
    assert_ok(&run_inline(&s), "V8_SERIALIZE_OK");
}

// ----- domain ---------------------------------------------------------

#[test]
#[serial]
fn domain_create_and_run_invokes_fn() {
    let src = r#"
        const domain = require('domain');
        const d = domain.create();
        let result;
        d.run(() => { result = 'inside'; });
        if (result !== 'inside') {
            console.error('result:', result); process.exit(2);
        }
        console.log('DOMAIN_OK');
    "#;
    assert_ok(&run_inline(src), "DOMAIN_OK");
}

#[test]
#[serial]
fn domain_run_emits_error_on_throw() {
    let src = r#"
        const domain = require('domain');
        const d = domain.create();
        let captured = null;
        d.on('error', (e) => { captured = e.message; });
        try { d.run(() => { throw new Error('boom'); }); } catch (_) {}
        if (captured !== 'boom') {
            console.error('captured:', captured); process.exit(2);
        }
        console.log('DOMAIN_ERR_OK');
    "#;
    assert_ok(&run_inline(src), "DOMAIN_ERR_OK");
}

// ----- inspector -------------------------------------------------------

#[test]
#[serial]
fn inspector_url_returns_undefined_when_closed() {
    let src = r#"
        const ins = require('inspector');
        if (ins.url() !== undefined) {
            console.error('url before open:', ins.url()); process.exit(2);
        }
        ins.open(9229);
        if (typeof ins.url() !== 'string' || ins.url().indexOf('ws://') !== 0) {
            console.error('url after open:', ins.url()); process.exit(3);
        }
        ins.close();
        if (ins.url() !== undefined) {
            console.error('url after close:', ins.url()); process.exit(4);
        }
        console.log('INSPECTOR_OK');
    "#;
    assert_ok(&run_inline(src), "INSPECTOR_OK");
}

#[test]
#[serial]
fn inspector_session_post_callback_invokes_handler() {
    // Session.post is now backed by a real CDP dispatcher (see R11).
    // Debugger.enable is a real method that returns
    // `{debuggerId: 'burn-debugger'}`; the callback receives no
    // error. Posting WITHOUT calling .connect() still surfaces
    // ERR_INSPECTOR_NOT_CONNECTED, which is checked separately
    // below.
    let src = r#"
        const { Session } = require('inspector');
        const connected = new Session();
        connected.connect();
        connected.post('Debugger.enable', (err, res) => {
            if (err || !res || res.debuggerId === undefined) {
                console.error('connected post bad:', err, res); process.exit(2);
            }
            const detached = new Session();
            detached.post('Debugger.enable', (err2) => {
                if (!err2 || err2.code !== 'ERR_INSPECTOR_NOT_CONNECTED') {
                    console.error('detached err bad:', err2); process.exit(3);
                }
                console.log('SESSION_OK');
                process.exit(0);
            });
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_ok(&run_inline(src), "SESSION_OK");
}

// ----- module ----------------------------------------------------------

#[test]
#[serial]
fn module_builtinModules_lists_node_builtins() {
    let src = r#"
        const Module = require('module');
        const list = Module.builtinModules;
        if (!Array.isArray(list)) {
            console.error('not array'); process.exit(2);
        }
        for (const name of ['fs', 'path', 'http', 'crypto', 'events']) {
            if (list.indexOf(name) === -1) {
                console.error('missing:', name); process.exit(3);
            }
        }
        console.log('BUILTINS_OK');
    "#;
    assert_ok(&run_inline(src), "BUILTINS_OK");
}

#[test]
#[serial]
fn module_isBuiltin_recognizes_node_prefix() {
    let src = r#"
        const Module = require('module');
        const checks = [
            Module.isBuiltin('fs') === true,
            Module.isBuiltin('node:fs') === true,
            Module.isBuiltin('crypto') === true,
            Module.isBuiltin('not-a-builtin') === false,
            Module.isBuiltin(42) === false,
        ];
        if (checks.every(Boolean)) console.log('IS_BUILTIN_OK');
        else { console.error('checks:', checks); process.exit(2); }
    "#;
    assert_ok(&run_inline(src), "IS_BUILTIN_OK");
}

// ----- readline --------------------------------------------------------

#[test]
#[serial]
fn readline_emits_line_per_newline() {
    let src = r#"
        const readline = require('readline');
        const { EventEmitter } = require('events');
        const fakeInput = new EventEmitter();
        const rl = readline.createInterface({ input: fakeInput });
        const lines = [];
        rl.on('line', (l) => lines.push(l));
        fakeInput.emit('data', 'hello\nworld\nlast');
        fakeInput.emit('end');
        if (lines.length !== 3) {
            console.error('lines:', lines); process.exit(2);
        }
        if (lines[0] !== 'hello' || lines[1] !== 'world' || lines[2] !== 'last') {
            console.error('content:', lines); process.exit(3);
        }
        console.log('READLINE_OK');
    "#;
    assert_ok(&run_inline(src), "READLINE_OK");
}

#[test]
#[serial]
fn readline_strips_carriage_return() {
    let src = r#"
        const readline = require('readline');
        const { EventEmitter } = require('events');
        const fakeInput = new EventEmitter();
        const rl = readline.createInterface({ input: fakeInput });
        let line = null;
        rl.on('line', (l) => { line = l; });
        fakeInput.emit('data', 'crlf-line\r\n');
        if (line !== 'crlf-line') {
            console.error('line:', JSON.stringify(line)); process.exit(2);
        }
        console.log('CRLF_OK');
    "#;
    assert_ok(&run_inline(src), "CRLF_OK");
}

// ----- tty -------------------------------------------------------------

#[test]
#[serial]
fn tty_isatty_returns_false() {
    let src = r#"
        const tty = require('tty');
        if (tty.isatty(0) !== false || tty.isatty(1) !== false) {
            console.error('isatty true unexpectedly'); process.exit(2);
        }
        console.log('TTY_OK');
    "#;
    assert_ok(&run_inline(src), "TTY_OK");
}

#[test]
#[serial]
fn tty_writestream_has_terminal_methods() {
    // tty.WriteStream is now real (env-honouring). With NO_COLOR=1
    // and TERM/FORCE_COLOR/COLORTERM unset, getColorDepth must
    // return 1 (mono). The structural surface (isTTY, clearLine,
    // cursorTo) is still asserted.
    let src = r#"
        const tty = require('tty');
        const w = new tty.WriteStream(1);
        if (w.isTTY !== false) {
            console.error('isTTY true'); process.exit(2);
        }
        if (typeof w.clearLine !== 'function' || typeof w.cursorTo !== 'function') {
            console.error('missing methods'); process.exit(3);
        }
        if (w.getColorDepth() !== 1) {
            console.error('colorDepth:', w.getColorDepth()); process.exit(4);
        }
        console.log('TTY_WRITE_OK');
    "#;
    assert_ok(&run_inline_no_color(src), "TTY_WRITE_OK");
}

// ----- util/types ------------------------------------------------------

#[test]
#[serial]
fn util_types_recognizes_typed_arrays() {
    let src = r#"
        const types = require('util/types');
        const u8 = new Uint8Array([1, 2, 3]);
        const u16 = new Uint16Array([1]);
        const checks = [
            types.isUint8Array(u8) === true,
            types.isUint16Array(u16) === true,
            types.isUint8Array(u16) === false,
            types.isTypedArray(u8) === true,
            types.isArrayBuffer(u8.buffer) === true,
            types.isArrayBuffer(u8) === false,
            types.isMap(new Map()) === true,
            types.isSet(new Set()) === true,
            types.isPromise(Promise.resolve()) === true,
            types.isPromise({ then: function() {} }) === true,
            types.isPromise({}) === false,
            types.isRegExp(/foo/) === true,
            types.isDate(new Date()) === true,
        ];
        if (checks.every(Boolean)) console.log('UTIL_TYPES_OK');
        else { console.error('checks:', checks); process.exit(2); }
    "#;
    assert_ok(&run_inline(src), "UTIL_TYPES_OK");
}

// ----- domain --------------------------------------------------------

#[test]
#[serial]
fn cluster_isPrimary_in_main_thread() {
    let src = r#"
        const cluster = require('cluster');
        if (cluster.isPrimary !== true || cluster.isMaster !== true || cluster.isWorker !== false) {
            console.error('flags:', cluster.isPrimary, cluster.isWorker); process.exit(2);
        }
        if (typeof cluster.fork !== 'function') {
            console.error('no fork'); process.exit(3);
        }
        if (typeof cluster.workers !== 'object') {
            console.error('no workers'); process.exit(4);
        }
        console.log('CLUSTER_OK');
    "#;
    assert_ok(&run_inline(src), "CLUSTER_OK");
}

// ----- repl ------------------------------------------------------------

#[test]
#[serial]
fn repl_start_returns_replServer() {
    let src = r#"
        const repl = require('repl');
        const r = repl.start({ prompt: '> ' });
        if (!(r instanceof repl.REPLServer)) {
            console.error('not REPLServer'); process.exit(2);
        }
        if (typeof r.context !== 'object') {
            console.error('no context'); process.exit(3);
        }
        let evalResult = null;
        r.eval('1 + 2', null, '<test>', function(err, v) {
            if (err) { console.error('eval err:', err); process.exit(4); }
            evalResult = v;
        });
        if (evalResult !== 3) {
            console.error('eval result:', evalResult); process.exit(5);
        }
        console.log('REPL_OK');
    "#;
    assert_ok(&run_inline(src), "REPL_OK");
}

// ----- wasi ------------------------------------------------------------

#[test]
#[serial]
fn wasi_class_construction_and_options() {
    let src = r#"
        const { WASI } = require('wasi');
        const w = new WASI({
            args: ['program', 'arg1'],
            env: { FOO: 'bar' },
            preopens: { '/sandbox': '/var/data' },
        });
        if (w.args.length !== 2 || w.args[0] !== 'program') {
            console.error('args:', w.args); process.exit(2);
        }
        if (w.env.FOO !== 'bar') {
            console.error('env:', w.env); process.exit(3);
        }
        const imports = w.getImportObject();
        if (typeof imports !== 'object') {
            console.error('imports:', imports); process.exit(4);
        }
        console.log('WASI_OK');
    "#;
    assert_ok(&run_inline(src), "WASI_OK");
}

// ----- trace_events ----------------------------------------------------

#[test]
#[serial]
fn trace_events_create_tracing_with_categories() {
    let src = r#"
        const te = require('trace_events');
        const t = te.createTracing({ categories: ['node', 'v8'] });
        if (t.enabled !== false) {
            console.error('starts enabled'); process.exit(2);
        }
        t.enable();
        if (t.enabled !== true) {
            console.error('enable failed'); process.exit(3);
        }
        if (t.categories !== 'node,v8') {
            console.error('categories:', t.categories); process.exit(4);
        }
        t.disable();
        try {
            te.createTracing({ categories: [] });
            console.error('expected throw'); process.exit(5);
        } catch (_) { /* ok */ }
        console.log('TRACE_OK');
    "#;
    assert_ok(&run_inline(src), "TRACE_OK");
}

// ----- dgram (surface only, real UDP coordinator pending) -------------

#[test]
#[serial]
fn dgram_createSocket_returns_socket_object() {
    let src = r#"
        const dgram = require('dgram');
        const sock = dgram.createSocket('udp4');
        if (!(sock instanceof dgram.Socket)) {
            console.error('not Socket'); process.exit(2);
        }
        if (sock.type !== 'udp4') {
            console.error('type:', sock.type); process.exit(3);
        }
        if (typeof sock.bind !== 'function' || typeof sock.send !== 'function') {
            console.error('missing methods'); process.exit(4);
        }
        sock.close();
        console.log('DGRAM_OK');
    "#;
    assert_ok(&run_inline(src), "DGRAM_OK");
}

// ----- http2 (surface only, real HTTP/2 coordinator pending) ----------

#[test]
#[serial]
fn http2_module_exposes_constants_and_classes() {
    let src = r#"
        const http2 = require('http2');
        const checks = [
            typeof http2.connect === 'function',
            typeof http2.createServer === 'function',
            typeof http2.createSecureServer === 'function',
            typeof http2.constants === 'object',
            http2.constants.HTTP2_HEADER_METHOD === ':method',
            http2.constants.HTTP2_HEADER_PATH === ':path',
            typeof http2.getDefaultSettings === 'function',
        ];
        const settings = http2.getDefaultSettings();
        const settingsOk = typeof settings === 'object' && settings.maxFrameSize === 16384;
        if (checks.every(Boolean) && settingsOk) console.log('HTTP2_OK');
        else { console.error('checks:', checks, 'settings:', settings); process.exit(2); }
    "#;
    assert_ok(&run_inline(src), "HTTP2_OK");
}

// ----- node:test, stream/web, util/types subpaths ---------------------

#[test]
#[serial]
fn node_subpaths_load_correctly() {
    let src = r#"
        const checks = [
            typeof require('fs/promises') === 'object',
            typeof require('dns/promises') === 'object',
            typeof require('stream/promises') === 'object',
            typeof require('timers/promises') === 'object',
            typeof require('util/types') === 'object',
            typeof require('stream/web') === 'object',
            typeof require('path/posix') === 'object',
            typeof require('path/win32') === 'object',
            require('sys') === require('util'),
        ];
        if (checks.every(Boolean)) console.log('SUBPATHS_OK');
        else { console.error('checks:', checks); process.exit(2); }
    "#;
    assert_ok(&run_inline(src), "SUBPATHS_OK");
}

#[test]
#[serial]
fn timers_promises_setTimeout_resolves_with_value() {
    let src = r#"
        const timers = require('timers/promises');
        timers.setTimeout(10, 'done').then((v) => {
            if (v !== 'done') {
                console.error('value:', v); process.exit(2);
            }
            console.log('TIMERS_PROMISE_OK');
            process.exit(0);
        }).catch((e) => {
            console.error('err:', e.message); process.exit(3);
        });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_ok(&run_inline(src), "TIMERS_PROMISE_OK");
}

// ----- process.nextTick ordering (Phase 0 / Gap E) --------------------

#[test]
#[serial]
fn nexttick_decouples_from_calling_stack() {
    // Pre-Phase-0 our `nextTick` was synchronous (`fn.apply(null, args)`
    // inline), which broke the core nextTick contract: the callback
    // must NOT run on the calling stack — code AFTER the
    // `process.nextTick(...)` line must execute before the callback
    // fires.
    //
    // Express's `finalhandler` depends on this. Sync inline execution
    // would flush the 404 response before the user's `next(err)` line
    // returned, scrambling middleware ordering and producing garbled
    // responses.
    let src = r#"
        const order = [];
        order.push('A');
        process.nextTick(() => order.push('NT'));
        order.push('B');
        setTimeout(() => {
            console.log('ORDER:' + order.join(','));
        }, 0);
    "#;
    assert_ok(&run_inline(src), "ORDER:A,B,NT");
}

#[test]
#[serial]
fn nexttick_runs_before_real_macrotask_timer() {
    // nextTick fires within the current tick, before any real
    // macrotask boundary. We can't probe `setTimeout(0)` (which our
    // polyfill implements as a microtask via `Promise.resolve().then`,
    // identical to nextTick's queueMicrotask), but we CAN probe a
    // host-backed `setTimeout(50)` that crosses a real timer
    // boundary.
    let src = r#"
        const order = [];
        process.nextTick(() => order.push('NT'));
        setTimeout(() => {
            order.push('TIMER50');
            console.log('ORDER:' + order.join(','));
        }, 50);
    "#;
    assert_ok(&run_inline(src), "ORDER:NT,TIMER50");
}

#[test]
#[serial]
fn nexttick_passes_extra_args_through() {
    let src = r#"
        process.nextTick((a, b, c) => {
            if (a + b + c === 6) console.log('NT_ARGS_OK');
            else { console.error('args:', a, b, c); process.exit(2); }
        }, 1, 2, 3);
    "#;
    assert_ok(&run_inline(src), "NT_ARGS_OK");
}

#[test]
#[serial]
fn nexttick_exception_does_not_poison_queue() {
    // Per Node, an exception thrown inside a nextTick callback
    // emits `uncaughtException` but doesn't cancel pending ticks.
    // We log + continue so the second callback still runs.
    let src = r#"
        const order = [];
        process.nextTick(() => { throw new Error('boom'); });
        process.nextTick(() => order.push('after'));
        setTimeout(() => {
            if (order[0] === 'after') console.log('NT_ISO_OK');
            else { console.error('order:', order); process.exit(2); }
        }, 0);
    "#;
    assert_ok(&run_inline(src), "NT_ISO_OK");
}

#[test]
#[serial]
fn nexttick_rejects_non_function_callback() {
    let src = r#"
        try {
            process.nextTick('not-a-function');
            console.error('expected throw'); process.exit(2);
        } catch (e) {
            if (e instanceof TypeError) console.log('NT_TYPE_OK');
            else { console.error('e:', e); process.exit(3); }
        }
    "#;
    assert_ok(&run_inline(src), "NT_TYPE_OK");
}

// ----- process.binding clearer error ----------------------------------

#[test]
#[serial]
fn process_binding_carries_name_in_error() {
    let src = r#"
        try {
            process.binding('uv');
            console.error('expected throw'); process.exit(2);
        } catch (e) {
            if (e.code !== 'ERR_NOT_SUPPORTED_IN_SANDBOX') {
                console.error('code:', e.code); process.exit(3);
            }
            if (e.bindingName !== 'uv') {
                console.error('bindingName:', e.bindingName); process.exit(4);
            }
            if (e.message.indexOf("'uv'") === -1) {
                console.error('msg lacks name:', e.message); process.exit(5);
            }
            console.log('BINDING_ERR_OK');
        }
    "#;
    assert_ok(&run_inline(src), "BINDING_ERR_OK");
}
