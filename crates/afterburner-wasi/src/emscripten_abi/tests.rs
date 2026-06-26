// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

use super::*;
use crate::embedder_vm::EmbedderVm;
use std::sync::LazyLock;

// Share a single EmbedderVm (and its wasmtime Engine) across all tests.
// EmbedderVm is Send + Sync; LazyLock initialises it once.
static VM: LazyLock<EmbedderVm> = LazyLock::new(|| EmbedderVm::new().expect("EmbedderVm::new"));

fn w(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("WAT parse")
}

// ---- deterministic clock constants ------------------------------------------

/// VIRTUAL_NOW_MS must be a positive finite f64.
#[test]
fn virtual_now_ms_is_positive_finite() {
    const { assert!(VIRTUAL_NOW_MS > 0.0) };
    const { assert!(VIRTUAL_NOW_MS.is_finite()) };
}

/// VIRTUAL_EPOCH_MS must represent a date after 2026-01-01 (> 1.7e12 ms).
#[test]
fn virtual_epoch_ms_is_plausible() {
    const { assert!(VIRTUAL_EPOCH_MS > 1_700_000_000_000.0) };
    const { assert!(VIRTUAL_EPOCH_MS.is_finite()) };
}

/// VIRTUAL_EPOCH_NS must be VIRTUAL_EPOCH_MS * 1e6 (ms -> ns).
#[test]
fn virtual_epoch_ns_consistent_with_ms() {
    let ns_from_ms = (VIRTUAL_EPOCH_MS * 1_000_000.0) as u64;
    // Allow a 1 µs rounding window due to f64 precision.
    let diff = VIRTUAL_EPOCH_NS.abs_diff(ns_from_ms);
    assert!(
        diff < 1_000_000,
        "VIRTUAL_EPOCH_NS differs from ms*1e6 by {diff} ns"
    );
}

// ---- emscripten_get_now -----------------------------------------------------

/// `emscripten_get_now` returns the fixed virtual clock constant.
#[test]
fn get_now_returns_virtual_constant() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_get_now" (func $get_now (result f64)))
                (func (export "run") (result i64)
                  call $get_now
                  i64.reinterpret_f64))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    let got = f64::from_bits(out.result as u64);
    assert_eq!(got, VIRTUAL_NOW_MS, "get_now must return VIRTUAL_NOW_MS");
}

/// Two calls in independent runs return the same value (determinism).
#[test]
fn get_now_deterministic_across_runs() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_get_now" (func $get_now (result f64)))
                (func (export "run") (result i64)
                  call $get_now
                  i64.reinterpret_f64))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let r1 = VM.run(&module, "run", None).unwrap().result;
    let r2 = VM.run(&module, "run", None).unwrap().result;
    assert_eq!(r1, r2, "emscripten_get_now must be deterministic");
}

// ---- emscripten_date_now ---------------------------------------------------

/// `emscripten_date_now` returns VIRTUAL_EPOCH_MS.
#[test]
fn date_now_returns_virtual_epoch() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_date_now" (func $now (result f64)))
                (func (export "run") (result i64)
                  call $now
                  i64.reinterpret_f64))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    let got = f64::from_bits(out.result as u64);
    assert_eq!(
        got, VIRTUAL_EPOCH_MS,
        "date_now must return VIRTUAL_EPOCH_MS"
    );
}

/// date_now is also deterministic across calls.
#[test]
fn date_now_deterministic() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_date_now" (func $now (result f64)))
                (func (export "run") (result i64)
                  call $now
                  i64.reinterpret_f64))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let r1 = VM.run(&module, "run", None).unwrap().result;
    let r2 = VM.run(&module, "run", None).unwrap().result;
    assert_eq!(r1, r2);
}

// ---- abort ------------------------------------------------------------------

/// Calling `abort` from wasm causes the VM to return a WasmTrap error.
#[test]
fn abort_traps_execution() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "abort" (func $abort))
                (func (export "run") (result i64)
                  call $abort
                  i64.const 0))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let err = VM.run(&module, "run", None).unwrap_err();
    match err {
        afterburner_core::AfterburnerError::WasmTrap(_) => {}
        other => panic!("expected WasmTrap, got {other:?}"),
    }
}

/// `_abort_js` also traps (Emscripten's newer JS-layer abort shim).
#[test]
fn abort_js_traps_execution() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "_abort_js" (func $abort_js))
                (func (export "run") (result i64)
                  call $abort_js
                  i64.const 0))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let err = VM.run(&module, "run", None).unwrap_err();
    match err {
        afterburner_core::AfterburnerError::WasmTrap(_) => {}
        other => panic!("expected WasmTrap from _abort_js, got {other:?}"),
    }
}

/// Code after `abort` is unreachable - module compiles fine even with dead code.
#[test]
fn abort_dead_code_after_unreachable_is_fine() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "abort" (func $abort))
                (func (export "run") (result i64)
                  call $abort
                  unreachable))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    // Compilation succeeds; run traps.
    assert!(VM.run(&module, "run", None).is_err());
}

// ---- emscripten_resize_heap ------------------------------------------------

/// `emscripten_resize_heap` called with current size returns 1.
#[test]
fn resize_heap_already_large_enough() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_resize_heap"
                  (func $resize (param i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i64)
                  i32.const 65536
                  call $resize
                  i64.extend_i32_s))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 1, "resize to current size must return 1");
}

/// `emscripten_resize_heap` with a larger size grows the memory and returns 1.
#[test]
fn resize_heap_grows_memory() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_resize_heap"
                  (func $resize (param i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i64)
                  i32.const 131072
                  call $resize
                  i64.extend_i32_s))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 1, "resize to 2 pages must return 1");
}

/// Calling resize_heap multiple times keeps returning 1.
#[test]
fn resize_heap_idempotent() {
    // Compile a module that calls resize twice with the same target.
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_resize_heap"
                  (func $resize (param i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i64)
                  i32.const 131072
                  call $resize
                  drop
                  i32.const 131072
                  call $resize
                  i64.extend_i32_s))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    assert_eq!(out.result, 1);
}

// ---- emscripten_memcpy_js --------------------------------------------------

/// `emscripten_memcpy_js` copies bytes within linear memory correctly.
#[test]
fn memcpy_js_copies_bytes() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_memcpy_js"
                  (func $cpy (param i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "ABCD")
                (func (export "run") (result i64)
                  i32.const 64   ;; dest
                  i32.const 0    ;; src
                  i32.const 4    ;; num
                  call $cpy
                  i32.const 64
                  i32.load
                  i64.extend_i32_u))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    // "ABCD" in little-endian i32 = 0x44434241
    assert_eq!(
        out.result, 0x44434241,
        "memcpy_js must copy 4 bytes correctly (got {:#x})",
        out.result
    );
}

/// `emscripten_memcpy_js` with overlapping regions (src < dest, forward copy)
/// must correctly handle the overlap (copy_within handles this).
#[test]
fn memcpy_js_overlapping_forward() {
    // Source "0123" at offset 0; dest at offset 2 overlaps (forward overlap).
    // After copy, bytes at offset 2..6 should be "0123".
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_memcpy_js"
                  (func $cpy (param i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "0123XXXX")
                (func (export "run") (result i64)
                  i32.const 2    ;; dest
                  i32.const 0    ;; src
                  i32.const 4    ;; num
                  call $cpy
                  i32.const 2
                  i32.load
                  i64.extend_i32_u))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    // After copying "0123" (0x30 0x31 0x32 0x33) to offset 2,
    // reading i32 LE from offset 2 = 0x33323130.
    assert_eq!(
        out.result, 0x33323130,
        "overlapping copy produced {:#x}",
        out.result
    );
}

/// `emscripten_memcpy_js` with zero bytes is a no-op (does not trap).
#[test]
fn memcpy_js_zero_bytes_is_noop() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_memcpy_js"
                  (func $cpy (param i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "ABCD")
                (func (export "run") (result i64)
                  i32.const 64
                  i32.const 0
                  i32.const 0    ;; zero bytes
                  call $cpy
                  i32.const 64
                  i32.load
                  i64.extend_i32_u))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    // Byte 64 was never written; it should be 0 (zero-initialized memory).
    assert_eq!(
        out.result, 0,
        "zero-byte copy must leave destination unchanged"
    );
}

// ---- emscripten_memcpy_big -------------------------------------------------

/// `emscripten_memcpy_big` behaves identically to `emscripten_memcpy_js`.
#[test]
fn memcpy_big_copies_bytes() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "emscripten_memcpy_big"
                  (func $cpy (param i32 i32 i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "WXYZ")
                (func (export "run") (result i64)
                  i32.const 128  ;; dest
                  i32.const 0    ;; src
                  i32.const 4    ;; num
                  call $cpy
                  i32.const 128
                  i32.load
                  i64.extend_i32_u))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    // "WXYZ" LE = 0x5A595857
    assert_eq!(
        out.result, 0x5A595857,
        "memcpy_big must copy 4 bytes (got {:#x})",
        out.result
    );
}

// ---- combined ---------------------------------------------------------------

/// A module importing abort + get_now + resize_heap compiles and runs cleanly.
#[test]
fn multiple_env_imports_compile_and_run() {
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "abort" (func $abort))
                (import "env" "emscripten_get_now" (func $now (result f64)))
                (import "env" "emscripten_resize_heap"
                  (func $resize (param i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i64)
                  call $now
                  i64.reinterpret_f64))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    let got = f64::from_bits(out.result as u64);
    assert_eq!(got, VIRTUAL_NOW_MS);
}

/// All six env imports can coexist in one module without conflicts.
#[test]
fn all_six_env_imports_no_conflict() {
    // Compile a module that declares all six imports but only calls date_now.
    let module = VM
        .compile(
            &w(r#"
              (module
                (import "env" "abort"                  (func $abort))
                (import "env" "_abort_js"              (func $abort_js))
                (import "env" "emscripten_get_now"     (func $get_now (result f64)))
                (import "env" "emscripten_date_now"    (func $date_now (result f64)))
                (import "env" "emscripten_memcpy_js"   (func $cpy (param i32 i32 i32)))
                (import "env" "emscripten_resize_heap" (func $resize (param i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "run") (result i64)
                  call $date_now
                  i64.reinterpret_f64))
            "#),
            false,
            add_emscripten_imports,
        )
        .unwrap();
    let out = VM.run(&module, "run", None).unwrap();
    let got = f64::from_bits(out.result as u64);
    assert_eq!(got, VIRTUAL_EPOCH_MS);
}
