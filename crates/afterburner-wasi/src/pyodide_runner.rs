// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Minimal helper for booting the Pyodide 0.28+ Wasm binary in the
//! deterministic embedder and capturing its stdout.
//!
//! The binary at `wasm_path` must already be translated from the legacy
//! exception-handling proposal to the exnref proposal via:
//!
//! ```text
//! wasm-opt --translate-to-exnref --enable-exception-handling \
//!   --enable-reference-types --enable-bulk-memory --enable-simd \
//!   --enable-sign-ext --enable-nontrapping-float-to-int \
//!   --enable-mutable-globals pyodide-new.asm.wasm -o pyodide-exnref.wasm
//! ```
//!
//! If either the wasm binary or the stdlib zip is absent, the function returns
//! `Err` so integration-test callers can skip gracefully.

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{
    FuncType, Global, GlobalType, Linker, Module, Mutability, Store, Tag, TagType, Val, ValType,
};

use crate::{
    embedder_vm::{EmbedderState, deterministic_engine},
    emscripten_dylink::{
        fill_got_table_slots, parse_got_name_to_slot, wire_got_func_stubs_from_module,
    },
    emscripten_fs::mount_zip_into_fs,
    emscripten_invoke::wire_invoke_trampolines,
    emscripten_mechanical::wire_pyodide028_env_stubs,
    emscripten_runtime::{
        MechCallLog, NoopCallLog, PYODIDE_STACK_BASE, fill_unknown_imports_as_noops,
        wire_env_memory_and_table_in_store, wire_wasi_only,
    },
    emscripten_syscall::wire_fs_env_funcs,
};

/// Instruction budget - CPython 3.13 static init is heavy.
const PYODIDE_FUEL: u64 = 500_000_000_000;

/// Output from a [`boot_pyodide`] call.
pub struct PyodideBootOutput {
    /// Bytes the module wrote to its wasi_stdout during `__wasm_call_ctors`.
    pub stdout: Vec<u8>,
}

/// Boot the Pyodide 0.28+ Wasm binary up to `__wasm_call_ctors` (CPython static
/// init) and return the stdout captured during that phase.
///
/// Returns `Err` if:
/// - `wasm_path` or `stdlib_zip_path` are unreadable,
/// - the binary fails to compile (wrong format or missing exnref translation),
/// - wiring, instantiation, or `__wasm_call_ctors` trap.
///
/// Integration tests should check [`std::path::Path::exists`] on `wasm_path`
/// before calling and skip (not fail) when the file is absent.
pub fn boot_pyodide(wasm_path: &str, stdlib_zip_path: &str) -> Result<PyodideBootOutput> {
    let wasm_bytes = std::fs::read(wasm_path)
        .map_err(|e| AfterburnerError::Engine(format!("read {wasm_path}: {e}")))?;

    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, 1);

    let engine = deterministic_engine()?;
    let module = Module::new(&engine, &wasm_bytes)
        .map_err(|e| AfterburnerError::Engine(format!("compile pyodide: {e}")))?;

    let mut linker: Linker<EmbedderState> = Linker::new(&engine);
    linker.allow_shadowing(true);

    wire_wasi_only(&mut linker)?;
    wire_invoke_trampolines(&engine, &mut linker)?;

    let mech_log = MechCallLog::new();
    wire_fs_env_funcs(&mut linker, mech_log)?;
    wire_pyodide028_env_stubs(&engine, &mut linker)?;

    // sentinel stubs (exnref-translated binary).
    let is_ty = FuncType::new(&engine, [ValType::EXTERNREF], [ValType::I32]);
    linker
        .func_new("sentinel", "is_sentinel", is_ty, |_, _, results| {
            results[0] = Val::I32(0);
            Ok(())
        })
        .map_err(|e| AfterburnerError::Engine(format!("sentinel::is_sentinel: {e}")))?;
    let create_ty = FuncType::new(&engine, [], [ValType::EXTERNREF]);
    linker
        .func_new("sentinel", "create_sentinel", create_ty, |_, _, results| {
            results[0] = Val::ExternRef(None);
            Ok(())
        })
        .map_err(|e| AfterburnerError::Engine(format!("sentinel::create_sentinel: {e}")))?;

    let mut store = Store::new(&engine, EmbedderState::for_emscripten());
    store
        .set_fuel(PYODIDE_FUEL)
        .map_err(|e| AfterburnerError::Engine(format!("set_fuel: {e}")))?;

    let got_globals =
        wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, 1, PYODIDE_STACK_BASE)?;

    // Native-EH tags: env.__c_longjmp and env.__cpp_exception.
    let tag_func_ty = FuncType::new(&engine, [ValType::I32], []);
    let tag_ty = TagType::new(tag_func_ty);
    let c_longjmp = Tag::new(&mut store, &tag_ty)
        .map_err(|e| AfterburnerError::Engine(format!("tag __c_longjmp: {e}")))?;
    linker
        .define(&mut store, "env", "__c_longjmp", c_longjmp)
        .map_err(|e| AfterburnerError::Engine(format!("define __c_longjmp: {e}")))?;
    let cpp_exc = Tag::new(&mut store, &tag_ty)
        .map_err(|e| AfterburnerError::Engine(format!("tag __cpp_exception: {e}")))?;
    linker
        .define(&mut store, "env", "__cpp_exception", cpp_exc)
        .map_err(|e| AfterburnerError::Engine(format!("define __cpp_exception: {e}")))?;

    // Auto-fill extra GOT globals (Pyodide 0.28 has more than 0.26.4).
    let got_ty = GlobalType::new(ValType::I32, Mutability::Var);
    for import in module.imports() {
        let mod_name = import.module();
        if mod_name != "GOT.func" && mod_name != "GOT.mem" {
            continue;
        }
        if linker.get(&mut store, mod_name, import.name()).is_ok() {
            continue;
        }
        let g = Global::new(&mut store, got_ty.clone(), Val::I32(0))
            .map_err(|e| AfterburnerError::Engine(format!("GOT {}: {e}", import.name())))?;
        linker
            .define(&mut store, mod_name, import.name(), g)
            .map_err(|e| AfterburnerError::Engine(format!("define GOT {}: {e}", import.name())))?;
    }

    // Mount stdlib zip.
    if let Ok(zip_bytes) = std::fs::read(stdlib_zip_path) {
        store
            .data_mut()
            .fs
            .insert_file("/lib/python313.zip", zip_bytes.clone());
        let _ = mount_zip_into_fs(&mut store.data_mut().fs, "/lib/python3.13", &zip_bytes);
    }
    store.data_mut().fs.mkdir_p("/tmp");

    wire_got_func_stubs_from_module(&mut store, &mut linker, &module)?;

    let noop_log = NoopCallLog::new();
    fill_unknown_imports_as_noops(&mut store, &mut linker, &module, noop_log);

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| AfterburnerError::Engine(format!("instantiate: {e}")))?;

    fill_got_table_slots(
        &mut store,
        &linker,
        &instance,
        &got_globals,
        &name_to_slot,
        &module,
    )?;

    if let Some(f) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        f.call(&mut store, &[], &mut [])
            .map_err(|e| AfterburnerError::Engine(format!("__wasm_apply_data_relocs: {e}")))?;
    }

    if let Some(f) = instance.get_func(&mut store, "__wasm_call_ctors") {
        f.call(&mut store, &[], &mut [])
            .map_err(|e| AfterburnerError::Engine(format!("__wasm_call_ctors: {e}")))?;
    }

    let stdout = store.data().wasi_stdout.clone();
    Ok(PyodideBootOutput { stdout })
}
