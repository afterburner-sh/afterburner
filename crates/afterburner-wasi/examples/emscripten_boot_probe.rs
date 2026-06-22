// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Boot probe for `pyodide.asm.wasm` on the afterburner deterministic engine.
//!
//! Attempts to instantiate Pyodide's CPython Wasm module with a purely
//! Rust host, providing all 288+ Emscripten env.* imports and GOT globals.
//! Reports honest findings: success, first blocking import, or trap site.
//!
//! # Usage
//!
//!   cargo run -p afterburner-wasi --example emscripten_boot_probe
//!
//! The module is loaded from `/tmp/pyodide.asm.wasm` at runtime. Download it
//! first:
//!
//!   curl -fsSL -o /tmp/pyodide.asm.wasm \
//!       https://cdn.jsdelivr.net/pyodide/v0.26.4/full/pyodide.asm.wasm
//!
//! # What this tests
//!
//! Pyodide 0.26.4 (`pyodide.asm.wasm`) is a Wasm dynamic library compiled
//! by Emscripten. It imports its linear memory and indirect function table
//! from the host, uses the `dylink.0` section for GOT patching, and depends
//! on ~290 host functions split between:
//!
//! 1. Mechanical Emscripten ABI (syscalls, memory, C++ exceptions, invoke
//!    trampolines) - these are implementable in pure Rust.
//! 2. JS-FFI bridge (Js* / JsProxy* functions that marshal Python objects
//!    to/from JS) - these are recording stubs in this probe.
//!
//! The probe drives boot in phases:
//!
//! 1. Compile `pyodide.asm.wasm` with Cranelift (deterministic profile).
//! 2. Instantiate with all imports provided.
//! 3. Call `__wasm_apply_data_relocs` (patches GOT entries).
//! 4. Call `__wasm_call_ctors` (runs C++ static constructors = CPython init).
//! 5. Report the outcome.
//!
//! If any phase fails, the probe reports the exact trap or error message.
//! The findings are HONEST: no fabricated results.

use std::fs;

use afterburner_wasi::embedder_vm::{EmbedderState, deterministic_engine};
use afterburner_wasi::emscripten_runtime::{
    JsFfiCallLog, PYODIDE_STACK_BASE, add_pyodide_imports, fill_unknown_imports_as_traps,
    wire_env_memory_and_table_in_store,
};
use wasmtime::{Linker, Module, Store};

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide.asm.wasm";

/// Instruction budget for the boot probe. CPython static init is heavy.
/// 5 billion instructions; adjust if needed.
///
/// vertexia: global fuel budget; upgrade path is per-phase sub-budgets to
/// measure which init phases consume the most instructions.
const PROBE_FUEL: u64 = 5_000_000_000;

fn main() {
    let outcome = run_probe();
    println!("\n=== PROBE OUTCOME ===");
    println!("{outcome}");
}

fn run_probe() -> String {
    // ---- load the wasm bytes ------------------------------------------------

    let wasm_bytes = match fs::read(PYODIDE_WASM_PATH) {
        Ok(b) => b,
        Err(e) => {
            return format!(
                "LOAD FAILED: cannot read {PYODIDE_WASM_PATH}: {e}\n\
                 Download with:\n\
                 curl -fsSL -o /tmp/pyodide.asm.wasm \\\n\
                     https://cdn.jsdelivr.net/pyodide/v0.26.4/full/pyodide.asm.wasm"
            );
        }
    };
    eprintln!(
        "[probe] loaded {} ({} bytes)",
        PYODIDE_WASM_PATH,
        wasm_bytes.len()
    );

    // ---- build the deterministic engine -------------------------------------

    let engine = match deterministic_engine() {
        Ok(e) => e,
        Err(e) => return format!("ENGINE FAILED: {e}"),
    };

    // ---- compile the module -------------------------------------------------

    eprintln!("[probe] compiling pyodide.asm.wasm with Cranelift (this takes ~30s)...");
    let module = match Module::new(&engine, &wasm_bytes) {
        Ok(m) => m,
        Err(e) => return format!("COMPILE FAILED: {e}"),
    };
    eprintln!("[probe] compilation succeeded");

    // Report what the module imports (for diagnosis).
    let import_list: Vec<_> = module
        .imports()
        .map(|i| format!("  {}::{} ({:?})", i.module(), i.name(), i.ty()))
        .collect();
    eprintln!("[probe] module has {} imports", import_list.len());

    // ---- build linker and wire imports --------------------------------------

    let log = JsFfiCallLog::new();
    let mut linker: Linker<EmbedderState> = Linker::new(&engine);

    if let Err(e) = add_pyodide_imports(&engine, &mut linker, log.clone()) {
        return format!("IMPORT SETUP FAILED: {e}");
    }
    eprintln!("[probe] wired env.* functions and GOT.* globals");

    // ---- build a store and wire memory/table --------------------------------

    let mut store = Store::new(&engine, EmbedderState::with_wasi());
    store
        .set_fuel(PROBE_FUEL)
        .expect("set_fuel on consume_fuel engine");

    if let Err(e) = wire_env_memory_and_table_in_store(
        &mut store,
        &mut linker,
        /* memory_base */ 0,
        /* table_base */ 1,
        /* stack_base */ PYODIDE_STACK_BASE,
    ) {
        return format!("MEMORY/TABLE SETUP FAILED: {e}");
    }
    eprintln!("[probe] wired env.memory, env.__indirect_function_table, env.__*_base globals");

    // Fill any remaining unsatisfied function imports with trap stubs.
    let auto_filled = fill_unknown_imports_as_traps(&mut store, &mut linker, &module);
    if !auto_filled.is_empty() {
        eprintln!(
            "[probe] {} imports auto-filled as trap stubs (unexpected):",
            auto_filled.len()
        );
        for name in &auto_filled {
            eprintln!("  {name}");
        }
    } else {
        eprintln!("[probe] all imports are explicitly wired (no auto-fill needed)");
    }

    // ---- phase 1: instantiate -----------------------------------------------

    eprintln!("[probe] instantiating...");
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            return format!(
                "INSTANTIATION FAILED\n\
                 Error: {e}\n\
                 JS-FFI calls before failure: {}\n\
                 Auto-filled imports: {}\n\
                 Finding: the module cannot instantiate; the error message names the\n\
                 first blocking import or a type mismatch.",
                log.total_calls(),
                auto_filled.len()
            );
        }
    };
    eprintln!("[probe] instantiation succeeded");

    let fuel_after_inst = store.get_fuel().unwrap_or(0);
    let inst_fuel = PROBE_FUEL.saturating_sub(fuel_after_inst);
    eprintln!("[probe] fuel consumed by instantiation: {inst_fuel}");

    // ---- phase 2: __wasm_apply_data_relocs ----------------------------------

    if let Some(func) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        eprintln!("[probe] calling __wasm_apply_data_relocs...");
        match func.call(&mut store, &[], &mut []) {
            Ok(_) => eprintln!("[probe] __wasm_apply_data_relocs succeeded"),
            Err(e) => {
                return format!(
                    "RELOC FAILED\n\
                     __wasm_apply_data_relocs trapped: {e}\n\
                     JS-FFI calls so far: {} ({:?})\n\
                     Finding: data relocation step cannot complete without JS-FFI support.",
                    log.total_calls(),
                    log.snapshot()
                );
            }
        }
    } else {
        eprintln!("[probe] __wasm_apply_data_relocs not found (skipping)");
    }

    // ---- phase 3: __wasm_call_ctors (CPython static init) -------------------

    if let Some(func) = instance.get_func(&mut store, "__wasm_call_ctors") {
        eprintln!("[probe] calling __wasm_call_ctors (CPython static init)...");
        match func.call(&mut store, &[], &mut []) {
            Ok(_) => {
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                let js_calls = log.total_calls();
                let js_names = log.snapshot();

                if js_calls == 0 {
                    format!(
                        "BOOT SUCCEEDED (no JS-FFI calls required)\n\
                         Total fuel consumed: {total_fuel}\n\
                         JS-FFI calls: 0\n\
                         Finding: Pyodide CPython static init completed without any\n\
                         JS-FFI calls. The module CAN boot headless up to static init.\n\
                         Next step: probe Python interpreter entry points."
                    )
                } else {
                    format!(
                        "BOOT SUCCEEDED (JS-FFI calls were logged but returned safe defaults)\n\
                         Total fuel consumed: {total_fuel}\n\
                         JS-FFI call count: {js_calls}\n\
                         JS-FFI functions called: {js_names:?}\n\
                         Finding: CPython static init completed but invoked JS-FFI stubs.\n\
                         These stubs returned 0/null; real JS would be needed to pass them."
                    )
                }
            }
            Err(e) => {
                let js_calls = log.total_calls();
                let js_names = log.snapshot();
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);

                // Classify the error.
                let err_str = format!("{e}");
                let finding = if err_str.contains("OutOfFuel") || err_str.contains("out of fuel") {
                    "fuel exhausted before boot completed; increase PROBE_FUEL"
                } else if err_str.contains("unimplemented import") {
                    "hit an auto-filled trap stub (unexpected import not in our list)"
                } else if js_calls > 0 {
                    "CPython static init hit a JS-FFI stub that returned 0/null and caused a downstream trap"
                } else {
                    "CPython static init trapped in a mechanical Emscripten ABI function or in module code"
                };

                format!(
                    "BOOT FAILED at __wasm_call_ctors\n\
                     Error: {e}\n\
                     Fuel consumed: {total_fuel}\n\
                     JS-FFI call count: {js_calls}\n\
                     JS-FFI functions called: {js_names:?}\n\
                     Auto-filled imports: {auto_filled:?}\n\
                     Finding: {finding}"
                )
            }
        }
    } else {
        format!(
            "NO BOOT ENTRY FOUND\n\
             The module exports neither __wasm_call_ctors nor _start.\n\
             Instantiation succeeded and data relocs ran (if present).\n\
             Exports available: {:?}\n\
             JS-FFI calls during instantiation: {}",
            instance
                .exports(&mut store)
                .map(|e| e.name().to_owned())
                .collect::<Vec<_>>(),
            log.total_calls()
        )
    }
}
