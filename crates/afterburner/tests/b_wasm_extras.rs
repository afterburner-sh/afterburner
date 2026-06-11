// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
#![allow(non_snake_case)]
//! Final API-surface gap closes:
//!
//! * `WebAssembly.compileStreaming` / `instantiateStreaming` over a
//!   real `Response`-like object.
//! * `new WebAssembly.Memory({initial,maximum})` standalone - backed
//!   by `wasmtime::Memory::new` in its own Store.
//! * `new WebAssembly.Global({value:'i32', mutable:true}, init)`
//!   standalone - value get/set through `__host_wasm_global_*_sa`.
//! * `new WebAssembly.Table({element:'anyfunc', initial, maximum})`
//!   standalone - `.length`, `.grow(delta)`.
//! * `node:wasi` - real `wasi.start(module)` runs a WASI preview1
//!   module through `wasmtime-wasi`, surfaces the exit code.

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

#[test]
#[serial]
fn standalone_memory_grow_and_buffer() {
    let src = r#"
        const m = new WebAssembly.Memory({ initial: 1, maximum: 4 });
        if (m.buffer.byteLength !== 65536) {
            console.error('initial buf:', m.buffer.byteLength); process.exit(2);
        }
        const prev = m.grow(2);
        if (prev !== 1) { console.error('prev:', prev); process.exit(3); }
        if (m.buffer.byteLength !== 65536 * 3) {
            console.error('after grow:', m.buffer.byteLength); process.exit(4);
        }
        console.log('STANDALONE_MEM_OK');
    "#;
    assert_marker(&run_inline(src), "STANDALONE_MEM_OK");
}

#[test]
#[serial]
fn standalone_global_read_write() {
    let src = r#"
        const g = new WebAssembly.Global({ value: 'i32', mutable: true }, 100);
        if (g.value !== 100) { console.error('initial:', g.value); process.exit(2); }
        g.value = 200;
        if (g.value !== 200) { console.error('after set:', g.value); process.exit(3); }
        console.log('STANDALONE_GLOBAL_OK');
    "#;
    assert_marker(&run_inline(src), "STANDALONE_GLOBAL_OK");
}

#[test]
#[serial]
fn standalone_table_length_and_grow() {
    let src = r#"
        const t = new WebAssembly.Table({ element: 'anyfunc', initial: 2, maximum: 8 });
        if (t.length !== 2) { console.error('initial len:', t.length); process.exit(2); }
        const prev = t.grow(3);
        if (prev !== 2) { console.error('grow prev:', prev); process.exit(3); }
        if (t.length !== 5) { console.error('after grow:', t.length); process.exit(4); }
        console.log('STANDALONE_TABLE_OK');
    "#;
    assert_marker(&run_inline(src), "STANDALONE_TABLE_OK");
}

#[test]
#[serial]
fn compileStreaming_from_response() {
    let src = r#"
        // Minimal valid wasm module - empty module with no exports.
        const bytes = new Uint8Array([0,0x61,0x73,0x6d,1,0,0,0]);
        // Fake Response-like with an arrayBuffer() method.
        const fakeResponse = {
            arrayBuffer: function() {
                return Promise.resolve(bytes.buffer.slice(
                    bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
            },
        };
        WebAssembly.compileStreaming(fakeResponse)
            .then(mod => {
                if (!(mod instanceof WebAssembly.Module)) {
                    console.error('not Module'); process.exit(2);
                }
                console.log('COMPILE_STREAM_OK');
                process.exit(0);
            })
            .catch(e => { console.error('err:', e.message); process.exit(3); });
        setTimeout(() => process.exit(99), 3000);
    "#;
    assert_marker(&run_inline(src), "COMPILE_STREAM_OK");
}

#[test]
#[serial]
fn wasi_runs_module_with_exit_code() {
    // Minimal WASI preview1 module that calls proc_exit(7).
    // (module
    //   (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    //   (memory 1)
    //   (func (export "_start") (call $exit (i32.const 7)))
    //   (export "memory" (memory 0)))
    //
    // wasmtime-wasi's preview1 implementation requires the module to
    // export `memory` even when the syscalls it calls don't read /
    // write any pointer - the linker's setup checks the export up
    // front.
    let src = r#"
        const bytes = new Uint8Array([
            0,0x61,0x73,0x6d,1,0,0,0,
            // type section
            1,8,2, 0x60,0,0, 0x60,1,0x7f,0,
            // import section
            2,0x24,1,
                0x16,0x77,0x61,0x73,0x69,0x5f,0x73,0x6e,0x61,0x70,0x73,0x68,0x6f,0x74,0x5f,0x70,0x72,0x65,0x76,0x69,0x65,0x77,0x31,
                9,0x70,0x72,0x6f,0x63,0x5f,0x65,0x78,0x69,0x74, 0,1,
            // func section
            3,2,1,0,
            // memory section - 1 page, no max
            5,3,1,0,1,
            // export section: _start (func[1]) + memory (mem[0])
            // _start export(9) + memory export(9) + count(1) = 19 = 0x13
            7,0x13,2,
                6,0x5f,0x73,0x74,0x61,0x72,0x74,0,1,
                6,0x6d,0x65,0x6d,0x6f,0x72,0x79,2,0,
            // code section
            0x0a,8,1,6,0,0x41,7,0x10,0,0x0b
        ]);
        const wasi = new (require('wasi').WASI)({
            args: ['burn-wasi'],
            env: {},
            preopens: {},
        });
        WebAssembly.compile(bytes).then(mod => {
            const code = wasi.start(mod);
            if (code !== 7) {
                console.error('exit code:', code); process.exit(2);
            }
            console.log('WASI_EXIT_OK code=' + code);
            process.exit(0);
        }).catch(e => { console.error('err:', e.message); process.exit(3); });
        setTimeout(() => process.exit(99), 30000);
    "#;
    assert_marker(&run_inline(src), "WASI_EXIT_OK");
}
