// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Bring-up probe for Pyodide 0.28.3 (`pyodide.asm.wasm`) with native Wasm EH.
//!
//! Pyodide 0.28+ is compiled with Emscripten `-fwasm-exceptions`. This emits
//! native Wasm `try`/`catch`/`throw`/`rethrow` instructions (the legacy
//! exceptions wasm proposal, NOT the newer exnref/try_table form) and two
//! exception tag imports (`env.__c_longjmp`, `env.__cpp_exception`).
//!
//! This probe attempts:
//!
//! 1. Engine creation with `wasm_legacy_exceptions(true)` to enable
//!    `WasmFeatures::LEGACY_EXCEPTIONS`. Reports whether wasmtime 44 accepts it.
//! 2. If step 1 fails, falls back to no-EH engine and attempts `Module::new`
//!    to show exactly where Cranelift fails on the `try` instruction.
//! 3. If step 1 succeeds (future wasmtime), continues bring-up through
//!    instantiate -> relocs -> ctors -> interpreter.
//!
//! # Key deliverable (step 1)
//!
//! Whether cranelift compiles the native-EH module. If not, the exact error
//! names the blocker (wasmtime version, proposal support status).
//!
//! # Verified binary facts (pre-run, from wasm-tools)
//!
//! - Pyodide 0.28.3, CPython 3.13.2
//! - 0 `invoke_*` imports (no legacy EH shims)
//! - 2 tag imports: `env.__c_longjmp`, `env.__cpp_exception` (type: (i32) -> ())
//! - 252 env function imports, 280 GOT.func imports
//! - 2 `sentinel` imports: `sentinel::is_sentinel`, `sentinel::create_sentinel`
//! - wasm-tools validate confirmed: uses `try` instruction (legacy exceptions)
//! - Table initial: 6073; Memory: 320 pages initial, max 65536
//!
//! # Usage
//!
//!   cargo run -p afterburner-wasi --example pyodide028_probe
//!
//! Download first:
//!
//!   curl -fsSL -o /tmp/pyodide-new.asm.wasm \
//!       https://cdn.jsdelivr.net/pyodide/v0.28.3/full/pyodide.asm.wasm
//!   curl -fsSL -o /tmp/python_stdlib.zip \
//!       https://cdn.jsdelivr.net/pyodide/v0.28.3/full/python_stdlib.zip

use std::fs;

use afterburner_wasi::embedder_vm::EmbedderState;
use afterburner_wasi::emscripten_dylink::{
    fill_got_table_slots, parse_got_name_to_slot, wire_got_func_stubs_from_module,
};
use afterburner_wasi::emscripten_fs::mount_zip_into_fs;
use afterburner_wasi::emscripten_runtime::{
    JsFfiCallLog, PYODIDE_STACK_BASE, add_pyodide_imports, fill_unknown_imports_as_traps,
    wire_env_memory_and_table_in_store,
};
use wasmtime::{
    Config, Engine, FuncType, Global, GlobalType, Linker, Module, Mutability, OptLevel, Store, Tag,
    TagType, Val, ValType, WasmBacktraceDetails,
};

const MECH_TRACE_TAIL: usize = 40;

/// Path to Pyodide 0.28.3 wasm binary.
const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-new.asm.wasm";

/// Path to the Pyodide 0.28.3 Python stdlib zip.
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";

/// CPython 3.13 stdlib directory prefix.
const STDLIB_MOUNT_PREFIX: &str = "/lib/python3.13";

/// Raw zip mount path (zipimport bootstrap entry).
const STDLIB_ZIP_MOUNT_PATH: &str = "/lib/python313.zip";

/// Instruction budget. CPython 3.13 static init is heavy.
///
/// vertexia: global fuel budget; upgrade path is per-phase sub-budgets to
/// measure which init phases consume the most instructions.
const PROBE_FUEL: u64 = 500_000_000_000;

fn main() {
    let outcome = run_probe();
    println!("\n=== PROBE OUTCOME ===");
    println!("{outcome}");
}

/// Build the deterministic engine base config (without EH flags).
fn base_engine_cfg() -> Config {
    let mut cfg = Config::new();
    cfg.cranelift_opt_level(OptLevel::Speed)
        .cranelift_nan_canonicalization(true)
        .wasm_relaxed_simd(true)
        .relaxed_simd_deterministic(true)
        .wasm_threads(false)
        .consume_fuel(true)
        .wasm_backtrace_details(WasmBacktraceDetails::Enable);
    cfg
}

fn run_probe() -> String {
    // ---- load the wasm bytes -------------------------------------------------

    let wasm_bytes = match fs::read(PYODIDE_WASM_PATH) {
        Ok(b) => b,
        Err(e) => {
            return format!(
                "LOAD FAILED: cannot read {PYODIDE_WASM_PATH}: {e}\n\
                 Download with:\n\
                 curl -fsSL -o /tmp/pyodide-new.asm.wasm \\\n\
                     https://cdn.jsdelivr.net/pyodide/v0.28.3/full/pyodide.asm.wasm"
            );
        }
    };
    eprintln!(
        "[probe] loaded {} ({} bytes)",
        PYODIDE_WASM_PATH,
        wasm_bytes.len()
    );

    eprintln!("[probe] parsing GOT symbol map...");
    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, /* table_base */ 1);
    eprintln!("[probe] parsed {} GOT entries", name_to_slot.len());

    // ---- STEP 1: attempt Engine::new with wasm_legacy_exceptions(true) -------
    //
    // Pyodide 0.28 uses Emscripten -fwasm-exceptions, which emits the legacy
    // wasm exception proposal (try/catch/rethrow, NOT try_table). Wasmtime's
    // API exposes this as Config::wasm_legacy_exceptions(true), setting
    // WasmFeatures::LEGACY_EXCEPTIONS.
    //
    // On wasmtime 44: LEGACY_EXCEPTIONS is NOT in the "features known to
    // wasmtime" set in Config::validate, so Engine::new returns an error.
    // Cranelift itself also rejects Catch/Rethrow with "legacy exception
    // handling proposal is not supported" in func_environ.rs.
    //
    // This step reports the exact error so the caller can decide whether to
    // bump wasmtime to a version that supports it.

    let mut eh_cfg = base_engine_cfg();
    #[allow(deprecated)]
    eh_cfg.wasm_legacy_exceptions(true);

    eprintln!("[probe] STEP 1: attempting Engine::new with wasm_legacy_exceptions(true)...");
    match Engine::new(&eh_cfg) {
        Ok(engine) => {
            eprintln!("[probe] Engine::new SUCCEEDED with native-EH config");
            eprintln!("[probe] STEP 1 KEY DELIVERABLE MET: wasmtime accepts LEGACY_EXCEPTIONS");
            // Engine supports it - proceed with Module::new and full bring-up.
            step1_succeeded(engine, &wasm_bytes, &name_to_slot)
        }
        Err(e) => {
            let eh_engine_err = format!("{e}");
            eprintln!("[probe] Engine::new FAILED with native-EH config: {eh_engine_err}");
            eprintln!("[probe] Falling back: testing Module::new without EH flag...");

            // Fallback: plain engine (no EH flag). Shows where Cranelift fails.
            let plain_cfg = base_engine_cfg();
            match Engine::new(&plain_cfg) {
                Ok(plain_engine) => {
                    eprintln!("[probe] plain engine OK; attempting Module::new...");
                    let module_result = Module::new(&plain_engine, &wasm_bytes);
                    let module_err = match &module_result {
                        Ok(_) => {
                            // Unexpected: compiled fine without EH flag. This
                            // would mean the binary does NOT actually use try/catch.
                            "Module::new SUCCEEDED without EH flag (unexpected - \
                             wasm-tools validate said legacy_exceptions required)"
                                .to_owned()
                        }
                        Err(e) => format!("Module::new FAILED: {e}"),
                    };
                    let module_err_short = &module_err[..module_err.len().min(500)];

                    format!(
                        "STEP 1 FAILED: wasmtime 44 does not support LEGACY_EXCEPTIONS.\n\
                         \n\
                         Engine::new error (with wasm_legacy_exceptions=true):\n\
                         {eh_engine_err}\n\
                         \n\
                         Root cause: WasmFeatures::LEGACY_EXCEPTIONS is not in the set of\n\
                         features known to wasmtime 44 (Config::compiler_panicking_wasm_features).\n\
                         Cranelift 44 also explicitly returns an error for Catch/Rethrow/Delegate\n\
                         instructions: 'legacy exception handling proposal is not supported'\n\
                         (wasmtime-internal-cranelift/src/translate/code_translator.rs:604).\n\
                         \n\
                         Fallback Module::new result (plain engine, no EH flag):\n\
                         {module_err_short}\n\
                         \n\
                         --- BINARY ANALYSIS (pre-run, from wasm-tools) ---\n\
                         Pyodide 0.28.3 uses Emscripten -fwasm-exceptions (legacy EH proposal).\n\
                         wasm-tools validate confirmed: 'legacy_exceptions feature required for\n\
                         try instruction (at offset 0x4a30c0)'.\n\
                         The binary has 0 invoke_* imports and 2 tag imports:\n\
                         env.__c_longjmp and env.__cpp_exception (type: (i32) -> ()).\n\
                         \n\
                         --- PIVOT VIABILITY ---\n\
                         NOT viable on wasmtime 44. The native-EH pivot requires a wasmtime\n\
                         version where LEGACY_EXCEPTIONS is supported by Cranelift.\n\
                         Wasmtime 44 Cranelift supports try_table (new exnref proposal) but NOT\n\
                         try/catch/rethrow (legacy proposal). A bump to a wasmtime that adds\n\
                         Cranelift legacy EH, or a Pyodide build with try_table, is needed.\n\
                         \n\
                         Alternatively: stay on Pyodide 0.26.4 and diagnose the func-551\n\
                         trap root cause without the EH pivot."
                    )
                }
                Err(e2) => format!(
                    "STEP 1 FAILED: Engine::new(legacy_EH=true): {eh_engine_err}\n\
                     ALSO FAILED: Engine::new(plain): {e2}"
                ),
            }
        }
    }
}

/// Continue the bring-up once the engine accepts native EH (step 1 passed).
/// Only reached if a future wasmtime version supports LEGACY_EXCEPTIONS.
fn step1_succeeded(
    engine: Engine,
    wasm_bytes: &[u8],
    name_to_slot: &std::collections::HashMap<String, u32>,
) -> String {
    eprintln!("[probe] attempting Module::new with native-EH engine...");
    let module = match Module::new(&engine, wasm_bytes) {
        Ok(m) => m,
        Err(e) => {
            return format!(
                "COMPILE FAILED (step 1 key deliverable - Engine OK but Module::new failed)\n\
                 Error: {e}\n\
                 Finding: cranelift cannot compile the native-EH module; \
                 check the error for the specific instruction or proposal mismatch."
            );
        }
    };
    let import_count = module.imports().count();
    eprintln!("[probe] COMPILE SUCCEEDED - step 1 key deliverable MET ({import_count} imports)");

    let log = JsFfiCallLog::new();
    let mut linker: Linker<EmbedderState> = Linker::new(&engine);

    let mech_log = match add_pyodide_imports(&engine, &mut linker, log.clone()) {
        Ok(ml) => ml,
        Err(e) => return format!("IMPORT SETUP FAILED: {e}"),
    };

    if let Err(e) = linker.func_wrap("sentinel", "is_sentinel", |_: i32| -> i32 { 0 }) {
        return format!("IMPORT SETUP FAILED: sentinel::is_sentinel: {e}");
    }
    if let Err(e) = linker.func_wrap("sentinel", "create_sentinel", || -> i32 { 0 }) {
        return format!("IMPORT SETUP FAILED: sentinel::create_sentinel: {e}");
    }
    eprintln!("[probe] wired sentinel stubs");

    let mut store = Store::new(&engine, EmbedderState::for_emscripten());
    store
        .set_fuel(PROBE_FUEL)
        .expect("set_fuel on consume_fuel engine");

    let got_globals =
        match wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, 1, PYODIDE_STACK_BASE)
        {
            Ok(g) => g,
            Err(e) => return format!("MEMORY/TABLE SETUP FAILED: {e}"),
        };

    // Wire the 2 native-EH exception tags: (i32) -> ().
    // Wasmtime handles throw/catch natively once the tags are defined.
    let tag_func_ty = FuncType::new(&engine, [ValType::I32], []);
    let tag_ty = TagType::new(tag_func_ty);
    let c_longjmp_tag = match Tag::new(&mut store, &tag_ty) {
        Ok(t) => t,
        Err(e) => return format!("TAG CREATION FAILED: env.__c_longjmp: {e}"),
    };
    if let Err(e) = linker.define(&mut store, "env", "__c_longjmp", c_longjmp_tag) {
        return format!("TAG DEFINE FAILED: env.__c_longjmp: {e}");
    }
    let cpp_exception_tag = match Tag::new(&mut store, &tag_ty) {
        Ok(t) => t,
        Err(e) => return format!("TAG CREATION FAILED: env.__cpp_exception: {e}"),
    };
    if let Err(e) = linker.define(&mut store, "env", "__cpp_exception", cpp_exception_tag) {
        return format!("TAG DEFINE FAILED: env.__cpp_exception: {e}");
    }
    eprintln!("[probe] wired env.__c_longjmp and env.__cpp_exception as host tags");

    // Auto-fill GOT.func/GOT.mem globals missing from the 0.26.4 list.
    // Pyodide 0.28 has 280 GOT.func imports vs 169 in 0.26.4.
    let got_ty = GlobalType::new(ValType::I32, Mutability::Var);
    let mut extra_got_filled = 0usize;
    for import in module.imports() {
        if import.module() != "GOT.func" && import.module() != "GOT.mem" {
            continue;
        }
        if linker
            .get(&mut store, import.module(), import.name())
            .is_ok()
        {
            continue;
        }
        let g = match Global::new(&mut store, got_ty.clone(), Val::I32(0)) {
            Ok(g) => g,
            Err(e) => {
                return format!(
                    "GOT AUTO-FILL FAILED: {}::{}: {e}",
                    import.module(),
                    import.name()
                );
            }
        };
        if let Err(e) = linker.define(&mut store, import.module(), import.name(), g) {
            return format!(
                "GOT AUTO-FILL DEFINE FAILED: {}::{}: {e}",
                import.module(),
                import.name()
            );
        }
        extra_got_filled += 1;
    }
    eprintln!("[probe] auto-filled {extra_got_filled} extra GOT globals (0.28 additions)");

    match fs::read(PYTHON_STDLIB_ZIP_PATH) {
        Ok(zip_bytes) => {
            store
                .data_mut()
                .fs
                .insert_file(STDLIB_ZIP_MOUNT_PATH, zip_bytes.clone());
            match mount_zip_into_fs(&mut store.data_mut().fs, STDLIB_MOUNT_PREFIX, &zip_bytes) {
                Ok(n) => eprintln!("[probe] mounted {n} stdlib files at {STDLIB_MOUNT_PREFIX}"),
                Err(e) => eprintln!("[probe] WARN: stdlib mount error: {e}"),
            }
        }
        Err(e) => eprintln!("[probe] WARN: stdlib not available: {e}"),
    }

    match wire_got_func_stubs_from_module(&mut store, &mut linker, &module) {
        Ok(n) => eprintln!("[probe] wired {n} GOT.func stubs"),
        Err(e) => return format!("GOT STUB WIRING FAILED: {e}"),
    }

    let auto_filled = fill_unknown_imports_as_traps(&mut store, &mut linker, &module);
    eprintln!(
        "[probe] {} imports auto-filled as trap stubs",
        auto_filled.len()
    );

    eprintln!("[probe] instantiating...");
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            return format!(
                "INSTANTIATION FAILED\n\
                 Error: {e}\n\
                 JS-FFI calls: {}\n\
                 Auto-filled: {}",
                log.total_calls(),
                auto_filled.len()
            );
        }
    };
    eprintln!("[probe] instantiation succeeded");

    let fuel_after_inst = store.get_fuel().unwrap_or(0);
    eprintln!(
        "[probe] fuel consumed by instantiation: {}",
        PROBE_FUEL.saturating_sub(fuel_after_inst)
    );

    eprintln!("[probe] resolving GOT entries...");
    match fill_got_table_slots(
        &mut store,
        &linker,
        &instance,
        &got_globals,
        name_to_slot,
        &module,
    ) {
        Ok(r) => eprintln!(
            "[probe] GOT: {} elem, {} export, {} stub, {} mem",
            r.funcs_from_elem, r.funcs_from_export, r.funcs_stubbed, r.mem_resolved
        ),
        Err(e) => return format!("GOT RESOLUTION FAILED: {e}"),
    }

    if let Some(func) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        eprintln!("[probe] calling __wasm_apply_data_relocs...");
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("RELOC FAILED: {e}");
        }
        eprintln!("[probe] __wasm_apply_data_relocs OK");
    }

    let ctors_summary: String;
    if let Some(func) = instance.get_func(&mut store, "__wasm_call_ctors") {
        eprintln!("[probe] calling __wasm_call_ctors (CPython 3.13 static init)...");
        match func.call(&mut store, &[], &mut []) {
            Ok(_) => {
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
                ctors_summary = format!(
                    "CTORS SUCCEEDED\n\
                     Fuel consumed: {total_fuel}\n\
                     JS-FFI calls: {}\n\
                     WASI stdout ({} bytes): {wasi_text:?}",
                    log.total_calls(),
                    wasi_out.len()
                );
                eprintln!("[probe] {ctors_summary}");
            }
            Err(e) => {
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
                let err_str = format!("{e}");
                let trap_kind = e
                    .downcast_ref::<wasmtime::Trap>()
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| format!("(not a Trap): {e:?}"));
                let trap_frames = e
                    .downcast_ref::<wasmtime::WasmBacktrace>()
                    .map(|bt| {
                        bt.frames()
                            .iter()
                            .take(5)
                            .map(|f| format!("func[{}]", f.func_index()))
                            .collect::<Vec<_>>()
                            .join(" <- ")
                    })
                    .unwrap_or_else(|| "(no backtrace)".to_owned());

                let mech_tail = mech_log.tail(MECH_TRACE_TAIL);
                let mut mech_trace = String::new();
                for (i, entry) in mech_tail.iter().enumerate() {
                    let line = if entry.arg0 != 0 || entry.arg1 != 0 {
                        format!(
                            "  [{:>3}] {} (arg0={}, arg1={})\n",
                            i + 1,
                            entry.name,
                            entry.arg0,
                            entry.arg1
                        )
                    } else {
                        format!("  [{:>3}] {}\n", i + 1, entry.name)
                    };
                    mech_trace.push_str(&line);
                }

                let finding = if err_str.contains("OutOfFuel") || err_str.contains("out of fuel") {
                    "fuel exhausted"
                } else if err_str.contains("proc_exit") {
                    "CPython proc_exit"
                } else if err_str.contains("unimplemented import") {
                    "hit an auto-filled trap stub"
                } else {
                    "trap in ABI or module code"
                };

                let throw_count = store.data().cxa_throw_count;
                let fs_paths: Vec<String> = store.data().fs_path_log.iter().cloned().collect();
                return format!(
                    "BOOT FAILED at __wasm_call_ctors\n\
                     Error: {e}\n\
                     Trap kind: {trap_kind}\n\
                     Trap frames: {trap_frames}\n\
                     Fuel consumed: {total_fuel}\n\
                     JS-FFI calls: {}\n\
                     C++ throws: {throw_count}\n\
                     Last 12 FS paths: {fs_paths:?}\n\
                     WASI stdout ({} bytes): {wasi_text:?}\n\
                     Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                     Finding: {finding}",
                    log.total_calls(),
                    wasi_out.len()
                );
            }
        }
    } else {
        ctors_summary = "CTORS: not exported (skipped)".to_owned();
    }

    run_python_phase(&instance, &mut store, &log, &mech_log, &ctors_summary)
}

const SCRATCH_OFFSET: u32 = 32 * 1024 * 1024;

fn run_python_phase(
    instance: &wasmtime::Instance,
    store: &mut Store<EmbedderState>,
    log: &JsFfiCallLog,
    mech_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::MechCallLog>,
    ctors_summary: &str,
) -> String {
    store.data_mut().wasi_stdout.clear();

    if let Some(func) = instance.get_func(&mut *store, "__main_argc_argv") {
        eprintln!("[probe P5] calling __main_argc_argv(0, 0)...");
        let mut results = [wasmtime::Val::I32(0)];
        match func.call(
            &mut *store,
            &[wasmtime::Val::I32(0), wasmtime::Val::I32(0)],
            &mut results,
        ) {
            Ok(_) => {
                let ret = match &results[0] {
                    wasmtime::Val::I32(v) => *v,
                    _ => -1,
                };
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                return format!(
                    "{ctors_summary}\n\
                     --- phase 5: __main_argc_argv(0,0) ---\n\
                     Return: {ret}\n\
                     Fuel consumed: {total_fuel}\n\
                     JS-FFI calls: {}\n\
                     WASI stdout ({} bytes): {wasi_text:?}",
                    log.total_calls(),
                    wasi_out.len()
                );
            }
            Err(e) => {
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                let err_str = format!("{e}");
                let finding = classify_python_error(&err_str, log.total_calls());
                let mech_tail = mech_log.tail(MECH_TRACE_TAIL);
                let mut mech_trace = String::new();
                for (i, entry) in mech_tail.iter().enumerate() {
                    mech_trace.push_str(&format!(
                        "  [{:>3}] {} (arg0={}, arg1={})\n",
                        i + 1,
                        entry.name,
                        entry.arg0,
                        entry.arg1
                    ));
                }
                let throw_count = store.data().cxa_throw_count;
                let fs_paths: Vec<String> = store.data().fs_path_log.iter().cloned().collect();
                return format!(
                    "{ctors_summary}\n\
                     --- phase 5: __main_argc_argv(0,0) ---\n\
                     TRAPPED: {e}\n\
                     Fuel consumed: {total_fuel}\n\
                     JS-FFI calls: {}\n\
                     C++ throws: {throw_count}\n\
                     Last 12 FS paths: {fs_paths:?}\n\
                     WASI stdout ({} bytes): {wasi_text:?}\n\
                     Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                     Finding: {finding}",
                    log.total_calls(),
                    wasi_out.len()
                );
            }
        }
    }

    eprintln!("[probe P5] __main_argc_argv not found; using C API path");

    let py_init = match instance.get_func(&mut *store, "Py_InitializeEx") {
        Some(f) => f,
        None => {
            return format!(
                "{ctors_summary}\n\
                 --- phase 5: C API path ---\n\
                 Finding: Py_InitializeEx not exported"
            );
        }
    };

    eprintln!("[probe P5] calling Py_InitializeEx(0)...");
    if let Err(e) = py_init.call(&mut *store, &[wasmtime::Val::I32(0)], &mut []) {
        let wasi_out = store.data().wasi_stdout.clone();
        let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
        let err_str = format!("{e}");
        let finding = classify_python_error(&err_str, log.total_calls());
        return format!(
            "{ctors_summary}\n\
             --- phase 5: C API path ---\n\
             TRAPPED at Py_InitializeEx(0): {e}\n\
             Fuel consumed: {total_fuel}\n\
             JS-FFI calls: {}\n\
             WASI stdout ({} bytes): {wasi_text:?}\n\
             Finding: {finding}",
            log.total_calls(),
            wasi_out.len()
        );
    }

    let py_run = match instance.get_func(&mut *store, "PyRun_SimpleString") {
        Some(f) => f,
        None => {
            let wasi_out = store.data().wasi_stdout.clone();
            let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
            return format!(
                "{ctors_summary}\n\
                 --- phase 5: C API path ---\n\
                 Py_InitializeEx(0) succeeded\n\
                 Finding: PyRun_SimpleString not exported\n\
                 WASI stdout ({} bytes): {wasi_text:?}",
                wasi_out.len()
            );
        }
    };

    let src = b"print('hello from cpython 3.13 on afterburner')\n\0";
    let maybe_mem = store.data().pyodide_memory;
    let scratch_ptr = match maybe_mem {
        Some(mem) => {
            let offset = SCRATCH_OFFSET as usize;
            let mem_len = mem.data_size(&*store);
            if offset + src.len() > mem_len {
                return format!(
                    "{ctors_summary}\n\
                     --- phase 5: C API path ---\n\
                     Finding: memory too small for scratch write"
                );
            }
            mem.data_mut(&mut *store)[offset..offset + src.len()].copy_from_slice(src);
            offset as i32
        }
        None => {
            return format!(
                "{ctors_summary}\n\
                 --- phase 5: C API path ---\n\
                 Finding: pyodide_memory not set"
            );
        }
    };

    store.data_mut().wasi_stdout.clear();
    eprintln!("[probe P5] calling PyRun_SimpleString(ptr={scratch_ptr:#x})...");
    let run_result = py_run.call(
        &mut *store,
        &[wasmtime::Val::I32(scratch_ptr)],
        &mut [wasmtime::Val::I32(0)],
    );

    let wasi_out = store.data().wasi_stdout.clone();
    let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
    let fuel_remaining = store.get_fuel().unwrap_or(0);
    let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);

    match run_result {
        Ok(()) => format!(
            "{ctors_summary}\n\
             --- phase 5: C API path ---\n\
             PyRun_SimpleString returned (no trap)\n\
             Fuel consumed: {total_fuel}\n\
             JS-FFI calls: {}\n\
             WASI stdout ({} bytes): {wasi_text:?}",
            log.total_calls(),
            wasi_out.len()
        ),
        Err(e) => {
            let err_str = format!("{e}");
            let finding = classify_python_error(&err_str, log.total_calls());
            format!(
                "{ctors_summary}\n\
                 --- phase 5: C API path ---\n\
                 TRAPPED at PyRun_SimpleString: {e}\n\
                 Fuel consumed: {total_fuel}\n\
                 JS-FFI calls: {}\n\
                 WASI stdout ({} bytes): {wasi_text:?}\n\
                 Finding: {finding}",
                log.total_calls(),
                wasi_out.len()
            )
        }
    }
}

fn classify_python_error(err_str: &str, js_calls: usize) -> &'static str {
    if err_str.contains("OutOfFuel") || err_str.contains("out of fuel") {
        "fuel exhausted; increase PROBE_FUEL"
    } else if err_str.contains("proc_exit") {
        "CPython called proc_exit"
    } else if err_str.contains("encodings") || err_str.contains("No module named") {
        "Python stdlib not found; needs mounting at /lib/python3.13"
    } else if err_str.contains("prefix") || err_str.contains("path configuration") {
        "Python path configuration error; stdlib at /lib/python3.13 needed"
    } else if err_str.contains("unimplemented import") {
        "hit an auto-filled trap stub"
    } else if js_calls > 0 {
        "JS-FFI stub returned 0/null and caused a downstream trap"
    } else {
        "trapped in Emscripten ABI or module code; check WASI stdout"
    }
}
