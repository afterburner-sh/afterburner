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
    FuncType, Global, GlobalType, Instance, Linker, Module, Mutability, Store, Tag, TagType, Val,
    ValType,
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
        MainModuleLayout, MechCallLog, NoopCallLog, fill_unknown_imports_as_noops,
        wire_env_memory_and_table_in_store, wire_wasi_only,
    },
    emscripten_syscall::wire_fs_env_funcs,
};

/// Instruction budget - CPython 3.13 static init is heavy.
///
/// vertexia: global fuel budget; per-phase sub-budgets would let us measure
/// which init phase consumes the most instructions.
const PYODIDE_FUEL: u64 = 500_000_000_000;

/// Output from a [`boot_pyodide`] call.
pub struct PyodideBootOutput {
    /// Bytes the module wrote to its wasi_stdout during `__wasm_call_ctors`.
    pub stdout: Vec<u8>,
}

/// Output from a [`run_pyodide_source`] call.
pub struct PyodideRunOutput {
    /// Bytes written to wasi_stdout (stdout of the Python process).
    pub stdout: Vec<u8>,
    /// Exit code returned by `run_main()` / `pymain_run_python()`.
    pub exit_code: i32,
}

// ---- private boot helper ---------------------------------------------------

/// Boot the Pyodide 0.28+ Wasm binary through `__wasm_call_ctors`.
///
/// Returns `(store, instance, got_globals)` ready for the run phase.
/// Both [`boot_pyodide`] and [`run_pyodide_source`] call this so the heavy
/// wiring logic lives in one place.
fn boot_pyodide_instance(
    wasm_path: &str,
    stdlib_zip_path: &str,
) -> Result<(
    Store<EmbedderState>,
    Instance,
    std::collections::HashMap<String, wasmtime::Global>,
)> {
    let wasm_bytes = std::fs::read(wasm_path)
        .map_err(|e| AfterburnerError::Engine(format!("read {wasm_path}: {e}")))?;

    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, 1);
    let layout = MainModuleLayout::from_main_wasm(&wasm_bytes);

    let engine = deterministic_engine()?;
    let module = Module::new(&engine, &wasm_bytes)
        .map_err(|e| AfterburnerError::Engine(format!("compile python runtime: {e}")))?;

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

    let got_globals = wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, &layout)?;

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
        layout.host_got_base(),
    )?;

    if let Some(f) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        f.call(&mut store, &[], &mut [])
            .map_err(|e| AfterburnerError::Engine(format!("__wasm_apply_data_relocs: {e}")))?;
    }

    if let Some(f) = instance.get_func(&mut store, "__wasm_call_ctors") {
        f.call(&mut store, &[], &mut [])
            .map_err(|e| AfterburnerError::Engine(format!("__wasm_call_ctors: {e}")))?;
    }

    Ok((store, instance, got_globals))
}

// ---- alloc helper -----------------------------------------------------------

/// Write a NUL-terminated byte string into a freshly grown wasm memory page.
///
/// Grows by exactly one page (64 KiB) so the write never overlaps data
/// CPython placed during `__wasm_call_ctors`. Returns the wasm guest address.
fn alloc_cstr(store: &mut Store<EmbedderState>, s: &[u8]) -> Result<u32> {
    let mem = store
        .data()
        .pyodide_memory
        .ok_or_else(|| AfterburnerError::Engine("pyodide_memory not set".into()))?;
    let prev = mem
        .grow(&mut *store, 1)
        .map_err(|e| AfterburnerError::Engine(format!("memory.grow: {e}")))?;
    let base = (prev as usize) * 65536;
    let mem_len = mem.data_size(&*store);
    if base + s.len() > mem_len {
        return Err(AfterburnerError::Engine(format!(
            "alloc_cstr: [{base:#x}..{:#x}) exceeds memory {mem_len:#x}",
            base + s.len()
        )));
    }
    mem.data_mut(&mut *store)[base..base + s.len()].copy_from_slice(s);
    Ok(base as u32)
}

/// Write four wasm32 pointers (4 bytes each, little-endian) starting at a
/// freshly grown page. Returns the guest base address of the pointer table.
fn alloc_argv_table(store: &mut Store<EmbedderState>, p0: u32, p1: u32, p2: u32) -> Result<i32> {
    let mem = store
        .data()
        .pyodide_memory
        .ok_or_else(|| AfterburnerError::Engine("pyodide_memory not set".into()))?;
    let prev = mem
        .grow(&mut *store, 1)
        .map_err(|e| AfterburnerError::Engine(format!("memory.grow (argv table): {e}")))?;
    let base = (prev as usize) * 65536;
    let data = mem.data_mut(&mut *store);
    data[base..base + 4].copy_from_slice(&p0.to_le_bytes());
    data[base + 4..base + 8].copy_from_slice(&p1.to_le_bytes());
    data[base + 8..base + 12].copy_from_slice(&p2.to_le_bytes());
    data[base + 12..base + 16].copy_from_slice(&0u32.to_le_bytes());
    Ok(base as i32)
}

// ---- public API ------------------------------------------------------------

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
    let (store, _instance, _got_globals) = boot_pyodide_instance(wasm_path, stdlib_zip_path)?;
    let stdout = store.data().wasi_stdout.clone();
    Ok(PyodideBootOutput { stdout })
}

/// Boot Pyodide, run `python -c <python_source>`, and return stdout + exit code.
///
/// The source string is passed verbatim as the `-c` argument to CPython.
/// Output from `print()` is captured via `EmbedderState::wasi_stdout` and
/// returned in [`PyodideRunOutput::stdout`].
///
/// # Errors
///
/// Returns `Err` when:
/// - `wasm_path` or `stdlib_zip_path` are unreadable (caller should check existence first),
/// - the binary fails to compile or instantiate,
/// - `__wasm_call_ctors` or `__main_argc_argv` trap,
/// - the runtime exports neither `run_main` nor `pymain_run_python`.
pub fn run_pyodide_source(
    wasm_path: &str,
    stdlib_zip_path: &str,
    python_source: &str,
) -> Result<PyodideRunOutput> {
    let (mut store, instance, _got_globals) = boot_pyodide_instance(wasm_path, stdlib_zip_path)?;
    // Clear any stdout emitted during boot before running user code.
    store.data_mut().wasi_stdout.clear();

    // Build argv in wasm memory: ["python\0", "-c\0", <source>\0] + pointer table.
    // Layout (wasm32 = 4-byte pointers, little-endian):
    //   arg0_ptr -> "python\0"
    //   arg1_ptr -> "-c\0"
    //   arg2_ptr -> python_source with NUL terminator
    //   argv_ptr -> [arg0_ptr, arg1_ptr, arg2_ptr, 0]
    let arg0_ptr = alloc_cstr(&mut store, b"python\0")?;
    let arg1_ptr = alloc_cstr(&mut store, b"-c\0")?;

    // NUL-terminate the source string.
    let mut source_bytes = python_source.as_bytes().to_vec();
    source_bytes.push(0);
    let arg2_ptr = alloc_cstr(&mut store, &source_bytes)?;

    let argv_ptr = alloc_argv_table(&mut store, arg0_ptr, arg1_ptr, arg2_ptr)?;

    // __main_argc_argv(argc=3, argv=argv_ptr): calls Py_Initialize with -c argv.
    // MUST be called EXACTLY ONCE; CPython is not initialized after __wasm_call_ctors.
    let main_fn = instance
        .get_func(&mut store, "__main_argc_argv")
        .ok_or_else(|| {
            AfterburnerError::Engine(
                "__main_argc_argv not exported; cannot initialize CPython".into(),
            )
        })?;

    let mut main_ret = [wasmtime::Val::I32(-99)];
    main_fn
        .call(
            &mut store,
            &[wasmtime::Val::I32(3), wasmtime::Val::I32(argv_ptr)],
            &mut main_ret,
        )
        .map_err(|e| AfterburnerError::Engine(format!("__main_argc_argv trapped: {e}")))?;

    let main_exitcode = match main_ret[0] {
        wasmtime::Val::I32(v) => v,
        _ => -99,
    };
    if main_exitcode != 0 {
        let wasi_out = store.data().wasi_stdout.clone();
        return Ok(PyodideRunOutput {
            stdout: wasi_out,
            exit_code: main_exitcode,
        });
    }

    // Clear any stdout emitted by Py_Initialize before running the -c code.
    store.data_mut().wasi_stdout.clear();

    // run_main() calls pymain_run_python which executes the -c command.
    // Prefer run_main (EMSCRIPTEN_KEEPALIVE); fall back to pymain_run_python.
    let run_fn = instance
        .get_func(&mut store, "run_main")
        .or_else(|| instance.get_func(&mut store, "pymain_run_python"))
        .ok_or_else(|| {
            AfterburnerError::Engine(
                "neither run_main nor pymain_run_python exported by the python runtime".into(),
            )
        })?;

    let mut run_ret = [wasmtime::Val::I32(-99)];
    run_fn
        .call(&mut store, &[], &mut run_ret)
        .map_err(|e| AfterburnerError::Engine(format!("run_main trapped: {e}")))?;

    let exit_code = match run_ret[0] {
        wasmtime::Val::I32(v) => v,
        _ => -99,
    };

    let stdout = store.data().wasi_stdout.clone();
    Ok(PyodideRunOutput { stdout, exit_code })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";
    const TEST_STDLIB_PATH: &str = "/tmp/python_stdlib.zip";

    #[test]
    #[ignore = "requires /tmp/pyodide-exnref.wasm and /tmp/python_stdlib.zip"]
    fn run_pyodide_source_sum_range() {
        if !std::path::Path::new(TEST_WASM_PATH).exists()
            || !std::path::Path::new(TEST_STDLIB_PATH).exists()
        {
            eprintln!("skip: python runtime artifacts not found at {TEST_WASM_PATH}");
            return;
        }
        let out = run_pyodide_source(TEST_WASM_PATH, TEST_STDLIB_PATH, "print(sum(range(101)))")
            .expect("run_pyodide_source failed");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            text.contains("5050"),
            "expected 5050 in stdout, got: {text:?}"
        );
    }
}
