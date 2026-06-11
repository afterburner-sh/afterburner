// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Engine ceiling #4 close: real `WebAssembly.Memory.grow`,
//! `WebAssembly.Global.value`, `WebAssembly.Table.{length,get,grow}`.

use serial_test::serial;
use std::process::Command;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", src])
        .output()
        .expect("spawn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "status={:?}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains(marker),
        "missing `{marker}`\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
}

/// Tiny wasm module - exports a memory `memory` initial=1 max=4 pages.
/// Hand-encoded so the test is hermetic: no wabt / wasm-tools dep.
fn wasm_memory_only() -> &'static str {
    // (module (memory (export "memory") 1 4))
    "new Uint8Array([0,0x61,0x73,0x6d,1,0,0,0,5,4,1,1,1,4,7,0x0a,1,6,0x6d,0x65,0x6d,0x6f,0x72,0x79,2,0])"
}

/// Tiny wasm module - exports memory + a global `g` (mut i32, init 7).
fn wasm_memory_and_global() -> &'static str {
    // (module
    //   (memory (export "memory") 1 4)
    //   (global (export "g") (mut i32) (i32.const 7)))
    //
    // Section 7 (export) size: count(1) + memory-export(9) + global-export(4) = 14 = 0x0e
    "new Uint8Array([\
        0,0x61,0x73,0x6d,1,0,0,0,\
        5,4,1,1,1,4,\
        6,6,1,0x7f,1,0x41,7,0x0b,\
        7,0x0e,2,6,0x6d,0x65,0x6d,0x6f,0x72,0x79,2,0,1,0x67,3,0\
    ])"
}

/// Tiny wasm module - exports memory + a function table `t`
/// (funcref, initial 1, max 4) + the constant zero function used to
/// fill the initial slot.
fn wasm_memory_and_table() -> &'static str {
    // (module
    //   (type (func))
    //   (func (export "noop"))
    //   (table (export "t") 1 4 funcref)
    //   (memory (export "memory") 1 4))
    //
    // Section 7 (export) size: count(1) + memory(9) + table(4) + noop(7) = 21 = 0x15
    "new Uint8Array([\
        0,0x61,0x73,0x6d,1,0,0,0,\
        1,4,1,0x60,0,0,\
        3,2,1,0,\
        4,5,1,0x70,1,1,4,\
        5,4,1,1,1,4,\
        7,0x15,3,6,0x6d,0x65,0x6d,0x6f,0x72,0x79,2,0,1,0x74,1,0,4,0x6e,0x6f,0x6f,0x70,0,0,\
        0x0a,4,1,2,0,0x0b\
    ])"
}

#[test]
#[serial]
fn memory_grow_returns_previous_pages() {
    let src = format!(
        r#"
            const bytes = {bytes};
            const mod = new WebAssembly.Module(bytes);
            const inst = new WebAssembly.Instance(mod);
            const mem = inst.exports.memory;
            const before = mem.buffer.byteLength;
            const prev = mem.grow(2);
            if (prev !== 1) {{
                console.error('expected prev=1, got', prev); process.exit(2);
            }}
            const after = mem.buffer.byteLength;
            if (after !== before + 2 * 65536) {{
                console.error('size mismatch:', before, after); process.exit(3);
            }}
            console.log('MEM_GROW_OK prev=' + prev);
        "#,
        bytes = wasm_memory_only()
    );
    assert_marker(&run_inline(&src), "MEM_GROW_OK");
}

#[test]
#[serial]
fn memory_grow_rejects_beyond_maximum() {
    let src = format!(
        r#"
            const bytes = {bytes};
            const mod = new WebAssembly.Module(bytes);
            const inst = new WebAssembly.Instance(mod);
            const mem = inst.exports.memory;
            let threw = false;
            try {{
                mem.grow(10);
            }} catch (e) {{
                threw = true;
            }}
            if (!threw) {{
                console.error('expected RangeError'); process.exit(2);
            }}
            console.log('MEM_GROW_MAX_OK');
        "#,
        bytes = wasm_memory_only()
    );
    assert_marker(&run_inline(&src), "MEM_GROW_MAX_OK");
}

#[test]
#[serial]
fn global_value_read_write() {
    let src = format!(
        r#"
            const bytes = {bytes};
            const mod = new WebAssembly.Module(bytes);
            const inst = new WebAssembly.Instance(mod);
            const g = inst.exports.g;
            if (g.value !== 7) {{ console.error('initial:', g.value); process.exit(2); }}
            g.value = 42;
            if (g.value !== 42) {{ console.error('after set:', g.value); process.exit(3); }}
            console.log('GLOBAL_OK');
        "#,
        bytes = wasm_memory_and_global()
    );
    assert_marker(&run_inline(&src), "GLOBAL_OK");
}

#[test]
#[serial]
fn table_length_and_grow() {
    let src = format!(
        r#"
            const bytes = {bytes};
            const mod = new WebAssembly.Module(bytes);
            const inst = new WebAssembly.Instance(mod);
            const t = inst.exports.t;
            if (t.length !== 1) {{ console.error('initial len:', t.length); process.exit(2); }}
            const prev = t.grow(2);
            if (prev !== 1) {{ console.error('grow prev:', prev); process.exit(3); }}
            if (t.length !== 3) {{ console.error('after grow:', t.length); process.exit(4); }}
            const slot = t.get(1);
            if (slot !== null) {{ console.error('slot 1:', slot); process.exit(5); }}
            console.log('TABLE_OK');
        "#,
        bytes = wasm_memory_and_table()
    );
    assert_marker(&run_inline(&src), "TABLE_OK");
}
