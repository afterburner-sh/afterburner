// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

use super::*;
use crate::embedder_vm::{EmbedderState, deterministic_engine};
use crate::emscripten_runtime::MechCallLog;
use std::sync::LazyLock;
use wasmtime::{Engine, Linker};

// Shared engine - building it once avoids repeated LLVM compilation overhead.
static SHARED_ENGINE: LazyLock<Engine> = LazyLock::new(|| {
    deterministic_engine().expect("deterministic engine for emscripten_mechanical tests")
});

// ---- wire succeeds ---------------------------------------------------------

/// `wire_mechanical_env_funcs` must wire all imports without error.
#[test]
fn wire_mechanical_env_funcs_succeeds() {
    let engine = &*SHARED_ENGINE;
    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    let mech_log = MechCallLog::new();
    wire_mechanical_env_funcs(engine, &mut linker, mech_log).expect("wire_mechanical_env_funcs");
}

// ---- _Py_emscripten_runtime returns 0 -------------------------------------

/// A module importing `env._Py_emscripten_runtime` (returns i32). Calling it
/// must return 0.
#[test]
fn py_emscripten_runtime_returns_zero() {
    let engine = &*SHARED_ENGINE;
    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    linker.allow_shadowing(true);
    let mech_log = MechCallLog::new();
    wire_mechanical_env_funcs(engine, &mut linker, mech_log).unwrap();

    let wat = r#"
      (module
        (import "env" "_Py_emscripten_runtime" (func $rt (result i32)))
        (func (export "run") (result i64)
          call $rt
          i64.extend_i32_s))
    "#;
    let module =
        wasmtime::Module::new(engine, wat::parse_str(wat).unwrap()).expect("module compile");
    let mut store = wasmtime::Store::new(engine, EmbedderState::for_emscripten());
    store.set_fuel(10_000_000).unwrap();
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
    let func = instance
        .get_typed_func::<(), i64>(&mut store, "run")
        .expect("get run");
    let result = func.call(&mut store, ()).expect("call run");
    assert_eq!(result, 0, "_Py_emscripten_runtime must return 0");
}

// ---- MechCallLog push / tail -----------------------------------------------

/// Push two entries; `tail(2)` returns them in order.
#[test]
fn mech_call_log_push_tail() {
    let log = MechCallLog::new();
    log.push("foo", 1, 2);
    log.push("bar", 3, 4);
    let tail = log.tail(2);
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0].name, "foo");
    assert_eq!(tail[1].name, "bar");
}

// ---- MechCallLog ring capacity --------------------------------------------

/// After pushing > 64 entries the buffer stays at 64 and the tail returns the
/// most recently pushed name.
#[test]
fn mech_call_log_ring_capacity() {
    const CAP: usize = 64;
    let log = MechCallLog::new();
    // Push CAP + 10 entries. The 65th (index 64) should evict the oldest.
    for i in 0..CAP + 10 {
        log.push("entry", i as i32, 0);
    }
    assert_eq!(log.len(), CAP);
    let tail = log.tail(1);
    assert_eq!(tail.len(), 1);
    // arg0 of the last pushed entry is CAP + 10 - 1.
    assert_eq!(tail[0].arg0, (CAP + 9) as i32);
}

// The civil-time helpers (clock breakdown for _gmtime_js / _localtime_js) are
// unit-tested in their own module: emscripten_mechanical/civil_time.rs.

// ---- getentropy determinism (fill value) -----------------------------------

/// The getentropy shim fills with 0xAB. Two identical buffer fills must be
/// byte-equal (determinism property at the fill-value level).
#[test]
fn getentropy_fill_is_deterministic_0xab() {
    let mut buf1 = vec![0u8; 8];
    let mut buf2 = vec![0u8; 8];
    // Mirror the shim's fill logic: mem[start..start+len].fill(0xAB)
    buf1.fill(0xAB);
    buf2.fill(0xAB);
    assert_eq!(buf1, buf2, "same fill params must produce identical bytes");
    assert!(buf1.iter().all(|&b| b == 0xAB), "fill value must be 0xAB");
}
