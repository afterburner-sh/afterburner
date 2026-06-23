// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Tests for the invoke_dispatch trampoline (emscripten_invoke.rs).
//!
//! The load-bearing contract: params[0] is the table index, params[1..] are
//! forwarded to the callee with EXACT arity matching - pad with 0 if callee
//! expects more args, truncate if it expects fewer.  This is the CPython
//! 3.13 emscripten_trampoline.c pad-to-arity contract.
//!
//! Each test compiles a tiny wasm module that imports one invoke_* variant
//! and an indirect_function_table, installs a callee into the table, and
//! drives the trampoline.  All trampoline variants are registered via
//! wire_invoke_trampolines so type-checking is live.

use super::*;
use crate::embedder_vm::EmbedderState;
use std::sync::LazyLock;
use wasmtime::{AsContextMut, Config, Engine, Linker, Module, Ref, Store, Table, TableType};

// ---- shared engine ----------------------------------------------------------

static ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    let mut cfg = Config::new();
    cfg.consume_fuel(true);
    Engine::new(&cfg).expect("test engine")
});

// ---- store builder ----------------------------------------------------------
//
// Build a Store with EmbedderState::headless() and a small funcref table
// wired as pyodide_table.  All invoke_* trampolines are registered in the
// linker so callee type-checking is live.

fn make_store_and_linker(n_slots: u32) -> (Store<EmbedderState>, Linker<EmbedderState>) {
    let engine = &ENGINE;
    let mut store = Store::new(engine, EmbedderState::headless());
    store.set_fuel(100_000_000).expect("set_fuel");

    let tbl_ty = TableType::new(wasmtime::RefType::FUNCREF, n_slots, None);
    let table = Table::new(&mut store, tbl_ty, Ref::Func(None)).expect("table");
    store.data_mut().pyodide_table = Some(table);

    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    wire_invoke_trampolines(engine, &mut linker).expect("wire");
    // Expose the table for modules that import __indirect_function_table.
    linker
        .define(
            &mut store,
            "env",
            "__indirect_function_table",
            wasmtime::Extern::Table(table),
        )
        .expect("define table");

    (store, linker)
}

// Install a callee of a given arity into the table at `slot`.
// The callee function:
//   arity 0: returns 1000
//   arity N: returns sum of all N i32 params
fn install_callee(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    slot: u64,
    arity: usize,
) {
    let params: String = (0..arity)
        .map(|_| "(param i32)")
        .collect::<Vec<_>>()
        .join(" ");
    let body = if arity == 0 {
        "i32.const 1000".to_owned()
    } else {
        let mut s = "local.get 0".to_owned();
        for i in 1..arity {
            s.push_str(&format!(" local.get {i} i32.add"));
        }
        s
    };
    let wat_src = format!(r#"(module (func (export "f") {params} (result i32) {body}))"#);
    let wasm = wat::parse_str(&wat_src).expect("WAT callee");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut *store, &module)
        .expect("instantiate callee");
    let func = instance.get_func(&mut *store, "f").expect("export f");
    let tbl = store.data().pyodide_table.expect("table");
    tbl.set(store.as_context_mut(), slot, Ref::Func(Some(func)))
        .expect("table set");
}

// Drive an invoke_* trampoline through a tiny wasm module.
//
// The invoke_* naming convention in emscripten_invoke.rs:
//   - the first i32 param is ALWAYS the table index (slot)
//   - remaining params are forwarded args
//   - the suffix letter count (excluding the result prefix) indicates forwarded args
//
// invoke_iii: (i32, i32, i32) -> i32  [index + 2 forwarded = 3 total]
// invoke_iiii: (i32, i32, i32, i32) -> i32 [index + 3 forwarded = 4 total]
// invoke_iiiii: (i32, i32, i32, i32, i32) -> i32 [index + 4 forwarded = 5 total]
//
// We use invoke_iiii (4 params = index + 3 forwarded args) to deliver 3 args
// to callees of arity 0..=5, exercising pad-to-arity and truncation.

fn drive_invoke_iiii(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    table_idx: i32,
    arg1: i32,
    arg2: i32,
    arg3: i32,
) -> i32 {
    // invoke_iiii linker type: (i32, i32, i32, i32) -> i32
    // param layout: [table_index, forwarded_arg1, forwarded_arg2, forwarded_arg3]
    let wat_src = format!(
        r#"(module
          (import "env" "__indirect_function_table"
            (table $tbl 1 funcref))
          (import "env" "invoke_iiii"
            (func $inv (param i32 i32 i32 i32) (result i32)))
          (func (export "run") (result i32)
            i32.const {table_idx}
            i32.const {arg1}
            i32.const {arg2}
            i32.const {arg3}
            call $inv))"#
    );
    let wasm = wat::parse_str(&wat_src).expect("WAT driver");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut *store, &module)
        .expect("instantiate driver");
    instance
        .get_typed_func::<(), i32>(&mut *store, "run")
        .expect("run")
        .call(&mut *store, ())
        .expect("call")
}

// ---- arity tests ------------------------------------------------------------
//
// Each callee is installed at a unique table slot.  The trampoline is called
// via invoke_iii (which provides 3 forwarded args).

/// Arity 0 callee: receives no args; trampoline drops all 3 forwarded args.
/// Expected: 1000 (the constant the callee returns).
#[test]
fn trampoline_arity0_truncates_extra_args() {
    let (mut store, linker) = make_store_and_linker(8);
    install_callee(&mut store, &linker, 1, 0);
    let result = drive_invoke_iiii(&mut store, &linker, 1, 10, 20, 30);
    assert_eq!(
        result, 1000,
        "arity-0 callee must return 1000 (extra args dropped)"
    );
}

/// Arity 1 callee: receives first forwarded arg (10); extras dropped.
#[test]
fn trampoline_arity1_passes_first_arg() {
    let (mut store, linker) = make_store_and_linker(8);
    install_callee(&mut store, &linker, 2, 1);
    let result = drive_invoke_iiii(&mut store, &linker, 2, 10, 20, 30);
    assert_eq!(result, 10, "arity-1 callee returns first arg only");
}

/// Arity 2 callee: receives arg0=10, arg1=20; arg2=30 dropped.
#[test]
fn trampoline_arity2_passes_two_args() {
    let (mut store, linker) = make_store_and_linker(8);
    install_callee(&mut store, &linker, 3, 2);
    let result = drive_invoke_iiii(&mut store, &linker, 3, 10, 20, 30);
    assert_eq!(
        result, 30,
        "arity-2 callee returns sum of first two args (10+20=30)"
    );
}

/// Arity 3 callee: all 3 forwarded args used; none padded.
#[test]
fn trampoline_arity3_passes_three_args() {
    let (mut store, linker) = make_store_and_linker(8);
    install_callee(&mut store, &linker, 4, 3);
    let result = drive_invoke_iiii(&mut store, &linker, 4, 10, 20, 30);
    assert_eq!(
        result, 60,
        "arity-3 callee returns sum of all three args (10+20+30=60)"
    );
}

/// Arity 4 callee (METH_FASTCALL|METH_KEYWORDS pattern): 3 forwarded args plus
/// one padded zero.  This is the exact case that fixed `import typing` in CPython.
/// Drive via invoke_iiii (idx + 4 forwarded args), providing only 3.
#[test]
fn trampoline_arity4_pads_missing_fourth_with_zero() {
    let (mut store, linker) = make_store_and_linker(8);
    install_callee(&mut store, &linker, 5, 4);
    // invoke_iiii: (table_idx, a, b, c, d) -> i32 where d is NOT provided by
    // this particular call pattern.  Use invoke_iii which provides 3 args so
    // the callee (arity 4) sees arg3=0 (padded).
    let result = drive_invoke_iiii(&mut store, &linker, 5, 10, 20, 30);
    // callee returns 10+20+30+0 = 60
    assert_eq!(
        result, 60,
        "arity-4 callee: 4th arg must be padded with 0 (10+20+30+0=60)"
    );
}

/// Arity 5 callee: 3 forwarded args plus two padded zeros.
#[test]
fn trampoline_arity5_pads_two_missing_args_with_zero() {
    let (mut store, linker) = make_store_and_linker(8);
    install_callee(&mut store, &linker, 6, 5);
    let result = drive_invoke_iiii(&mut store, &linker, 6, 10, 20, 30);
    // callee returns 10+20+30+0+0 = 60
    assert_eq!(
        result, 60,
        "arity-5 callee: missing args 4 and 5 must be padded with 0 (10+20+30+0+0=60)"
    );
}

// ---- error / edge cases -----------------------------------------------------

/// Null table slot: invoke_dispatch returns an error for an absent funcref.
/// The error propagates as a wasmtime trap through the wasm caller.
/// Verify it does not panic (the error path is exercised, not Ok).
#[test]
fn trampoline_null_slot_returns_error() {
    let (mut store, linker) = make_store_and_linker(8);
    // slot 7 is null (never installed).  Build the driver module manually
    // so we can call it and catch the trap without panicking.
    let wat_src = r#"(module
      (import "env" "__indirect_function_table" (table $tbl 1 funcref))
      (import "env" "invoke_iiii"
        (func $inv (param i32 i32 i32 i32) (result i32)))
      (func (export "run") (result i32)
        i32.const 7
        i32.const 1
        i32.const 2
        i32.const 3
        call $inv))"#;
    let wasm = wat::parse_str(wat_src).expect("WAT");
    let module = Module::new(&ENGINE, &wasm).expect("module");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
    let run = instance
        .get_typed_func::<(), i32>(&mut store, "run")
        .expect("run");
    // null slot -> invoke_dispatch returns an Err -> wasmtime propagates as trap
    let result = run.call(&mut store, ());
    assert!(
        result.is_err(),
        "null table slot must produce an error/trap"
    );
}

/// wire_invoke_trampolines registers all variants without error and the linker
/// successfully resolves invoke_iii, invoke_v, invoke_iiiii, invoke_viiii.
#[test]
fn wire_invoke_trampolines_registers_all_variants() {
    let engine = &ENGINE;
    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    wire_invoke_trampolines(engine, &mut linker).expect("wire ok");

    // Spot-check: compile a module that imports several variants.
    let wat_src = r#"
        (module
          (import "env" "invoke_v"    (func $a (param i32)))
          (import "env" "invoke_i"    (func $b (param i32) (result i32)))
          (import "env" "invoke_iii"  (func $c (param i32 i32 i32) (result i32)))
          (import "env" "invoke_viiii" (func $d (param i32 i32 i32 i32 i32)))
          (func (export "run") (result i32)
            i32.const 0))"#;
    let wasm = wat::parse_str(wat_src).expect("WAT");
    let module = Module::new(engine, &wasm).expect("module");
    let mut store = Store::new(engine, EmbedderState::headless());
    store.set_fuel(1_000_000).expect("fuel");
    linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
}

/// _PyEM_TrampolineCall_JS and _PyImport_InitFunc_TrampolineCall are wired
/// with their correct signatures.
#[test]
fn wire_invoke_trampolines_includes_pyodide_trampoline_names() {
    let engine = &ENGINE;
    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    wire_invoke_trampolines(engine, &mut linker).expect("wire ok");

    let wat_src = r#"
        (module
          (import "env" "_PyEM_TrampolineCall_JS"
            (func $t (param i32 i32 i32 i32) (result i32)))
          (import "env" "_PyImport_InitFunc_TrampolineCall"
            (func $t2 (param i32) (result i32)))
          (func (export "run") (result i32) i32.const 0))"#;
    let wasm = wat::parse_str(wat_src).expect("WAT");
    let module = Module::new(engine, &wasm).expect("module");
    let mut store = Store::new(engine, EmbedderState::headless());
    store.set_fuel(1_000_000).expect("fuel");
    linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
}
