// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! Integration tests for `globalThis.WebAssembly` - the host-side
//! wasmtime sub-runner that lets JS load arbitrary `.wasm` modules
//! at runtime. This is the architectural escape hatch for the long
//! tail of npm packages that ship a pre-compiled WASM build (sql.js,
//! @jsquash/*, libheif-js, …).
//!
//! Each test runs a small JS program through `burn -e` that:
//!   1. Constructs a tiny WASM module from hand-encoded bytes,
//!   2. Compiles + instantiates it via `WebAssembly.compile` /
//!      `WebAssembly.instantiate`,
//!   3. Calls into it / introspects it / round-trips memory,
//!   4. Asserts the expected JS-side behavior.
//!
//! Coverage:
//!   * Compile + instantiate (Promise + sync `Module()` + `Instance()`)
//!   * BufferSource shapes: Uint8Array / Buffer / ArrayBuffer
//!   * `validate()` true / false
//!   * `Module.exports()` / `Module.imports()` introspection
//!   * Function exports - i32 in / out, multiple args
//!   * Exported memory - read / write / `.buffer` snapshot
//!   * Error paths - invalid bytes, missing export, wrong arg count,
//!     unsatisfied imports, compileStreaming rejected
//!   * Typed errors - CompileError / LinkError / RuntimeError shape

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Compile a WAT (WebAssembly text format) snippet to bytes.
/// Used so test fixtures stay readable; hand-encoding binary
/// modules invites typos that surface as opaque parse errors.
fn wat_to_bytes(wat: &str) -> Vec<u8> {
    wat::parse_str(wat).expect("WAT should compile")
}

fn add_wasm() -> Vec<u8> {
    wat_to_bytes(
        r#"
        (module
            (func (export "add") (param i32 i32) (result i32)
                local.get 0
                local.get 1
                i32.add))
        "#,
    )
}

/// Format a byte slice as a JavaScript array literal (`[0x12, 0x34, ...]`).
fn js_byte_array(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 6);
    out.push('[');
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("0x{b:02x}"));
    }
    out.push(']');
    out
}

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
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

// ----- happy path ------------------------------------------------------

#[test]
#[serial]
fn webassembly_global_is_present() {
    let out = run_inline(
        r#"
            const checks = [
                typeof WebAssembly === 'object',
                typeof WebAssembly.compile === 'function',
                typeof WebAssembly.instantiate === 'function',
                typeof WebAssembly.validate === 'function',
                typeof WebAssembly.Module === 'function',
                typeof WebAssembly.Instance === 'function',
                typeof WebAssembly.Memory === 'function',
                typeof WebAssembly.CompileError === 'function',
                typeof WebAssembly.LinkError === 'function',
                typeof WebAssembly.RuntimeError === 'function',
            ];
            if (checks.every(Boolean)) console.log('SHAPE_OK');
            else { console.error('checks:', checks); process.exit(2); }
        "#,
    );
    assert_ok(&run_inline(""), ""); // warm up burn (smoke)
    assert_ok(&out, "SHAPE_OK");
}

#[test]
#[serial]
fn instantiate_from_uint8array() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const bytes = new Uint8Array({bytes_js});
            WebAssembly.instantiate(bytes).then(({{ module, instance }}) => {{
                if (typeof instance.exports.add !== 'function') {{
                    console.error('no add export'); process.exit(2);
                }}
                if (instance.exports.add(7, 35) !== 42) {{
                    console.error('add result wrong'); process.exit(3);
                }}
                console.log('U8_OK');
                process.exit(0);
            }}).catch((e) => {{
                console.error('catch:', e.message); process.exit(4);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    assert_ok(&run_inline(&src), "U8_OK");
}

#[test]
#[serial]
fn instantiate_from_buffer() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const {{ Buffer }} = require('buffer');
            const buf = Buffer.from(new Uint8Array({bytes_js}));
            WebAssembly.instantiate(buf).then(({{ instance }}) => {{
                if (instance.exports.add(1, 2) !== 3) {{
                    console.error('add wrong'); process.exit(2);
                }}
                console.log('BUF_OK');
                process.exit(0);
            }}).catch((e) => {{
                console.error(e.message); process.exit(3);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    assert_ok(&run_inline(&src), "BUF_OK");
}

#[test]
#[serial]
fn instantiate_from_arraybuffer() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const u8 = new Uint8Array({bytes_js});
            const ab = u8.buffer;
            WebAssembly.instantiate(ab).then(({{ instance }}) => {{
                console.log('AB_OK add=' + instance.exports.add(10, 20));
                process.exit(0);
            }}).catch((e) => {{
                console.error(e.message); process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    assert_ok(&run_inline(&src), "AB_OK add=30");
}

#[test]
#[serial]
fn module_then_instance_separately() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const bytes = new Uint8Array({bytes_js});
            const mod = new WebAssembly.Module(bytes);
            const inst = new WebAssembly.Instance(mod);
            if (inst.exports.add(40, 2) !== 42) {{
                console.error('add wrong'); process.exit(2);
            }}
            console.log('SYNC_OK');
        "#
    );
    assert_ok(&run_inline(&src), "SYNC_OK");
}

#[test]
#[serial]
fn instantiate_with_module_handle() {
    // `WebAssembly.instantiate(module)` returns Instance, not
    // {module, instance} - different return shape from the bytes
    // overload. Test both.
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const mod = new WebAssembly.Module(new Uint8Array({bytes_js}));
            WebAssembly.instantiate(mod).then((instance) => {{
                if (instance instanceof WebAssembly.Instance === false) {{
                    // Spec compat: should be an Instance, not a {{module, instance}}.
                    console.error('not Instance'); process.exit(2);
                }}
                if (instance.exports.add(1, 1) !== 2) {{
                    console.error('add wrong'); process.exit(3);
                }}
                console.log('MOD_OK');
                process.exit(0);
            }}).catch((e) => {{
                console.error(e.message); process.exit(4);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    assert_ok(&run_inline(&src), "MOD_OK");
}

// ----- validate -------------------------------------------------------

#[test]
#[serial]
fn validate_returns_true_for_valid_module() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const ok = WebAssembly.validate(new Uint8Array({bytes_js}));
            console.log('VALID=' + ok);
        "#
    );
    assert_ok(&run_inline(&src), "VALID=true");
}

#[test]
#[serial]
fn validate_returns_false_for_garbage() {
    let src = r#"
        const ok = WebAssembly.validate(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
        console.log('VALID=' + ok);
    "#;
    assert_ok(&run_inline(src), "VALID=false");
}

// ----- introspection --------------------------------------------------

#[test]
#[serial]
fn module_exports_introspection() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const mod = new WebAssembly.Module(new Uint8Array({bytes_js}));
            const exps = WebAssembly.Module.exports(mod);
            if (!Array.isArray(exps) || exps.length !== 1) {{
                console.error('exps:', JSON.stringify(exps)); process.exit(2);
            }}
            if (exps[0].name !== 'add' || exps[0].kind !== 'function') {{
                console.error('shape:', JSON.stringify(exps[0])); process.exit(3);
            }}
            console.log('EXPORTS_OK');
        "#
    );
    assert_ok(&run_inline(&src), "EXPORTS_OK");
}

#[test]
#[serial]
fn module_imports_empty_for_no_imports() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const mod = new WebAssembly.Module(new Uint8Array({bytes_js}));
            const imps = WebAssembly.Module.imports(mod);
            if (!Array.isArray(imps) || imps.length !== 0) {{
                console.error('imps:', JSON.stringify(imps)); process.exit(2);
            }}
            console.log('NO_IMPORTS_OK');
        "#
    );
    assert_ok(&run_inline(&src), "NO_IMPORTS_OK");
}

#[test]
#[serial]
fn module_imports_lists_required_imports() {
    // (module (import "env" "log" (func (param i32))))
    let bytes: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x01, 0x7f, 0x00,
        0x02, 0x0b, 0x01, 0x03, b'e', b'n', b'v', 0x03, b'l', b'o', b'g', 0x00, 0x00,
    ];
    let bytes_js = js_byte_array(&bytes);
    let src = format!(
        r#"
            const mod = new WebAssembly.Module(new Uint8Array({bytes_js}));
            const imps = WebAssembly.Module.imports(mod);
            if (imps.length !== 1) {{
                console.error('imps len:', imps.length); process.exit(2);
            }}
            const imp = imps[0];
            if (imp.module !== 'env' || imp.name !== 'log' || imp.kind !== 'function') {{
                console.error('shape:', JSON.stringify(imp)); process.exit(3);
            }}
            console.log('IMPORTS_OK');
        "#
    );
    assert_ok(&run_inline(&src), "IMPORTS_OK");
}

// ----- memory ---------------------------------------------------------

fn memory_wasm() -> Vec<u8> {
    wat_to_bytes(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "read_first") (result i32)
                i32.const 0
                i32.load))
        "#,
    )
}

#[test]
#[serial]
fn memory_export_round_trips() {
    let bytes_js = js_byte_array(&memory_wasm());
    let src = format!(
        r#"
            const {{ Buffer }} = require('buffer');
            const mod = new WebAssembly.Module(new Uint8Array({bytes_js}));
            const inst = new WebAssembly.Instance(mod);
            const mem = inst.exports.memory;
            if (!(mem instanceof WebAssembly.Memory)) {{
                console.error('memory wrong type'); process.exit(2);
            }}
            // Write little-endian 42.
            mem.write(0, Buffer.from([0x2a, 0x00, 0x00, 0x00]));
            const out = inst.exports.read_first();
            if (out !== 42) {{
                console.error('read_first:', out); process.exit(3);
            }}
            // Read back via mem.read.
            const back = mem.read(0, 4);
            if (back.length !== 4 || back[0] !== 0x2a) {{
                console.error('back:', back.toString('hex')); process.exit(4);
            }}
            console.log('MEM_OK');
        "#
    );
    assert_ok(&run_inline(&src), "MEM_OK");
}

#[test]
#[serial]
fn memory_buffer_returns_arraybuffer_snapshot() {
    let bytes_js = js_byte_array(&memory_wasm());
    let src = format!(
        r#"
            const {{ Buffer }} = require('buffer');
            const inst = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array({bytes_js})));
            const mem = inst.exports.memory;
            mem.write(0, Buffer.from([0x01, 0x02, 0x03, 0x04]));
            const buf = mem.buffer;
            if (!(buf instanceof ArrayBuffer)) {{
                console.error('not ArrayBuffer'); process.exit(2);
            }}
            // 1 page = 64 KiB.
            if (buf.byteLength !== 64 * 1024) {{
                console.error('size:', buf.byteLength); process.exit(3);
            }}
            const view = new Uint8Array(buf);
            if (view[0] !== 1 || view[1] !== 2 || view[2] !== 3 || view[3] !== 4) {{
                console.error('first 4:', view.slice(0, 4)); process.exit(4);
            }}
            console.log('BUFFER_OK');
        "#
    );
    assert_ok(&run_inline(&src), "BUFFER_OK");
}

// ----- error paths ----------------------------------------------------

#[test]
#[serial]
fn compile_invalid_bytes_rejects() {
    let src = r#"
        WebAssembly.compile(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
            .then(() => { console.error('expected reject'); process.exit(2); })
            .catch((e) => {
                if (e.name !== 'CompileError') {
                    console.error('wrong err:', e.name); process.exit(3);
                }
                console.log('COMPILE_REJ_OK');
                process.exit(0);
            });
        setTimeout(() => process.exit(99), 30000);
    "#;
    assert_ok(&run_inline(src), "COMPILE_REJ_OK");
}

#[test]
#[serial]
fn missing_export_call_throws_runtime_error() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const inst = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array({bytes_js})));
            if (inst.exports.does_not_exist !== undefined) {{
                console.error('found phantom export'); process.exit(2);
            }}
            console.log('MISSING_EXPORT_OK');
        "#
    );
    assert_ok(&run_inline(&src), "MISSING_EXPORT_OK");
}

#[test]
#[serial]
fn wrong_arg_count_runtime_errors() {
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const inst = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array({bytes_js})));
            try {{
                inst.exports.add(1);  // expects 2 args
                console.error('expected throw'); process.exit(2);
            }} catch (e) {{
                if (e.name !== 'RuntimeError') {{
                    console.error('wrong err:', e.name); process.exit(3);
                }}
                console.log('ARG_COUNT_OK');
            }}
        "#
    );
    assert_ok(&run_inline(&src), "ARG_COUNT_OK");
}

#[test]
#[serial]
fn unsatisfied_imports_link_error() {
    let bytes: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x01, 0x7f, 0x00,
        0x02, 0x0b, 0x01, 0x03, b'e', b'n', b'v', 0x03, b'l', b'o', b'g', 0x00, 0x00,
    ];
    let bytes_js = js_byte_array(&bytes);
    let src = format!(
        r#"
            try {{
                const inst = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array({bytes_js})));
                console.error('expected throw'); process.exit(2);
            }} catch (e) {{
                if (e.name !== 'LinkError') {{
                    console.error('wrong err:', e.name); process.exit(3);
                }}
                console.log('LINK_REJ_OK');
            }}
        "#
    );
    assert_ok(&run_inline(&src), "LINK_REJ_OK");
}

#[test]
#[serial]
fn instantiate_streaming_with_response_resolves() {
    // `WebAssembly.instantiateStreaming(Promise<Response>, imports)`
    // is now implemented end-to-end: it awaits the Response, reads
    // the bytes via the same path as `instantiate(buffer)`, and
    // resolves to `{ module, instance }`. Earlier rounds rejected
    // with "streaming not supported"; the surface is wired now.
    //
    // We feed it a real (`add`-exporting) module so the host-side
    // wasm parser is happy - wasmtime rejects the bare 8-byte magic-
    // and-version module that the WAT/wasm spec calls "minimum
    // valid". Same `add_wasm()` helper the other tests use.
    let bytes_js = js_byte_array(&add_wasm());
    let src = format!(
        r#"
            const bytes = new Uint8Array({bytes_js});
            const resp = new Response(bytes, {{ headers: {{ 'content-type': 'application/wasm' }} }});
            WebAssembly.instantiateStreaming(Promise.resolve(resp), {{}})
                .then((result) => {{
                    if (
                        result &&
                        result.module instanceof WebAssembly.Module &&
                        result.instance instanceof WebAssembly.Instance &&
                        typeof result.instance.exports.add === 'function' &&
                        result.instance.exports.add(2, 3) === 5
                    ) {{
                        console.log('STREAMING_OK');
                        process.exit(0);
                    }}
                    console.error('wrong result shape:', Object.keys(result || {{}}).join(','));
                    process.exit(3);
                }})
                .catch((e) => {{
                    console.error('rejected:', e && e.message); process.exit(4);
                }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    assert_ok(&run_inline(&src), "STREAMING_OK");
}

#[test]
#[serial]
fn standalone_memory_construction_yields_buffer() {
    // `new WebAssembly.Memory({ initial: N })` is now a real
    // standalone Memory backed by host-side wasmtime::Memory.
    // `.buffer` returns an ArrayBuffer of `initial * 64KB` bytes.
    let src = r#"
        const mem = new WebAssembly.Memory({ initial: 1 });
        if (!(mem instanceof WebAssembly.Memory)) {
            console.error('not a Memory'); process.exit(2);
        }
        if (!(mem.buffer instanceof ArrayBuffer)) {
            console.error('buffer not ArrayBuffer:', typeof mem.buffer); process.exit(3);
        }
        if (mem.buffer.byteLength !== 65536) {
            console.error('wrong byteLength:', mem.buffer.byteLength); process.exit(4);
        }
        console.log('STANDALONE_MEM_OK');
    "#;
    assert_ok(&run_inline(src), "STANDALONE_MEM_OK");
}

#[test]
#[serial]
fn typed_errors_are_distinguishable() {
    let src = r#"
        const ce = WebAssembly.CompileError('x');
        const le = WebAssembly.LinkError('y');
        const re = WebAssembly.RuntimeError('z');
        if (ce.name !== 'CompileError' || le.name !== 'LinkError' || re.name !== 'RuntimeError') {
            console.error('names:', ce.name, le.name, re.name); process.exit(2);
        }
        console.log('NAMES_OK');
    "#;
    assert_ok(&run_inline(src), "NAMES_OK");
}

// ----- argument coercion ----------------------------------------------

fn sum_f64_wasm() -> Vec<u8> {
    wat_to_bytes(
        r#"
        (module
            (func (export "sumf") (param f64 f64) (result f64)
                local.get 0
                local.get 1
                f64.add))
        "#,
    )
}

#[test]
#[serial]
fn float_args_round_trip() {
    let bytes_js = js_byte_array(&sum_f64_wasm());
    let src = format!(
        r#"
            const inst = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array({bytes_js})));
            const sum = inst.exports.sumf(1.5, 2.25);
            if (Math.abs(sum - 3.75) > 1e-9) {{
                console.error('sumf:', sum); process.exit(2);
            }}
            console.log('FLOAT_OK ' + sum);
        "#
    );
    assert_ok(&run_inline(&src), "FLOAT_OK 3.75");
}

#[test]
#[serial]
fn isolation_two_instances_dont_share_memory() {
    let bytes_js = js_byte_array(&memory_wasm());
    let src = format!(
        r#"
            const {{ Buffer }} = require('buffer');
            const mod = new WebAssembly.Module(new Uint8Array({bytes_js}));
            const a = new WebAssembly.Instance(mod);
            const b = new WebAssembly.Instance(mod);
            a.exports.memory.write(0, Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]));
            const aRead = a.exports.memory.read(0, 4);
            const bRead = b.exports.memory.read(0, 4);
            if (aRead[0] !== 0xaa) {{
                console.error('a read:', aRead.toString('hex')); process.exit(2);
            }}
            if (bRead[0] !== 0x00) {{
                console.error('b leaked:', bRead.toString('hex')); process.exit(3);
            }}
            console.log('ISOLATED_OK');
        "#
    );
    assert_ok(&run_inline(&src), "ISOLATED_OK");
}
