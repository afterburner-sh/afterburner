// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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
//! 5. Run Python: try `__main_argc_argv(0,0)` first; if absent, call
//!    `Py_InitializeEx(0)` then `PyRun_SimpleString("print(...)")`.
//! 6. Report the outcome.
//!
//! If any phase fails, the probe reports the exact trap or error message.
//! The findings are HONEST: no fabricated results.

use std::fs;

use afterburner_wasi::embedder_vm::{EmbedderState, deterministic_engine};
use afterburner_wasi::emscripten_dylink::{
    fill_got_table_slots, parse_got_name_to_slot, wire_got_func_stubs_from_module,
};
use afterburner_wasi::emscripten_fs::mount_zip_into_fs;
use afterburner_wasi::emscripten_runtime::{
    JsFfiCallLog, MainModuleLayout, add_pyodide_imports, fill_unknown_imports_as_traps,
    wire_env_memory_and_table_in_store,
};

const MECH_TRACE_TAIL: usize = 40;
use wasmtime::{Linker, Module, Store};

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide.asm.wasm";
/// Path to the Pyodide Python stdlib zip. Download before running:
///   curl -fsSL -o /tmp/python_stdlib.zip \
///       https://cdn.jsdelivr.net/pyodide/v0.26.4/full/python_stdlib.zip
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";
/// The prefix at which CPython 3.12 (via Pyodide 0.26.4) expects the stdlib.
/// CPython's path-config output (captured from the probe) shows:
///   sys.path = ['/lib/python312.zip', '/lib/python3.12', '/lib/python3.12/lib-dynload']
///   stdlib dir = '/lib/python3.12'
/// The stdlib zip is flat (entries like 'encodings/__init__.py', 'abc.py'),
/// so mounting at this prefix places them at '/lib/python3.12/encodings/__init__.py', etc.
const STDLIB_MOUNT_PREFIX: &str = "/lib/python3.12";
/// Path CPython checks first (before the directory). Mounting the raw zip bytes
/// here lets the zipimport bootstrap find 'encodings' even before the dir walk.
const STDLIB_ZIP_MOUNT_PATH: &str = "/lib/python312.zip";

/// Instruction budget for the boot probe. CPython static init is heavy, and
/// `Py_InitializeEx` (phase 5) is similarly expensive.
/// 50 billion instructions; adjust if needed.
///
/// vertexia: global fuel budget; upgrade path is per-phase sub-budgets to
/// measure which init phases consume the most instructions.
const PROBE_FUEL: u64 = 500_000_000_000;

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

    // ---- parse name section + element segments (before engine init) ----------
    //
    // table_base = 1 matches the value passed to wire_env_memory_and_table_in_store.
    eprintln!("[probe] parsing wasm name section + element segments for GOT resolution...");
    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, /* table_base */ 1);
    eprintln!(
        "[probe] parsed {} name->table_slot entries",
        name_to_slot.len()
    );
    let layout = MainModuleLayout::from_main_wasm(&wasm_bytes);

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

    let mech_log = match add_pyodide_imports(&engine, &mut linker, log.clone()) {
        Ok(ml) => ml,
        Err(e) => return format!("IMPORT SETUP FAILED: {e}"),
    };
    eprintln!("[probe] wired env.* functions and GOT.* globals");

    // ---- build a store and wire memory/table --------------------------------

    // Use for_emscripten (not with_wasi): pyodide.asm.wasm imports its linear
    // memory as env.memory and does NOT export it. The standard wasmtime-wasi
    // preview-1 accessor calls caller.get_export("memory") which fails for this
    // module. Custom WASI shims in emscripten_wasi read memory via
    // EmbedderState::pyodide_memory, set by wire_env_memory_and_table_in_store.
    let mut store = Store::new(&engine, EmbedderState::for_emscripten());
    store
        .set_fuel(PROBE_FUEL)
        .expect("set_fuel on consume_fuel engine");

    let got_globals = match wire_env_memory_and_table_in_store(
        &mut store,
        &mut linker,
        /* memory_base */ 0,
        /* layout */ &layout,
        /* module */ &module,
    ) {
        Ok(g) => g,
        Err(e) => return format!("MEMORY/TABLE SETUP FAILED: {e}"),
    };
    eprintln!(
        "[probe] wired env.memory, env.__indirect_function_table, env.__*_base globals, \
         GOT.func (pre-filled with slot indices), GOT.mem (pre-filled with symbol addresses)"
    );

    // ---- mount Python stdlib into the in-memory filesystem ------------------
    //
    // CPython path-config (captured from WASI stdout) shows:
    //   sys.path = ['/lib/python312.zip', '/lib/python3.12', '/lib/python3.12/lib-dynload']
    //   stdlib dir = '/lib/python3.12'
    // Two mounts are needed:
    //   1. Extracted tree at STDLIB_MOUNT_PREFIX (/lib/python3.12/encodings/__init__.py, ...)
    //      - covers the directory-based import path CPython walks first via stat64.
    //   2. Raw zip bytes at STDLIB_ZIP_MOUNT_PATH (/lib/python312.zip)
    //      - covers the zipimport bootstrap path (first sys.path entry).
    match fs::read(PYTHON_STDLIB_ZIP_PATH) {
        Ok(zip_bytes) => {
            // Mount raw zip at /lib/python312.zip for the zipimport path.
            store
                .data_mut()
                .fs
                .insert_file(STDLIB_ZIP_MOUNT_PATH, zip_bytes.clone());
            eprintln!(
                "[probe] mounted raw zip ({} bytes) at {STDLIB_ZIP_MOUNT_PATH}",
                zip_bytes.len()
            );

            // Mount extracted files at /lib/python3.12 for the directory path.
            match mount_zip_into_fs(&mut store.data_mut().fs, STDLIB_MOUNT_PREFIX, ::std::sync::Arc::from(zip_bytes.clone())) {
                Ok(n) => eprintln!(
                    "[probe] mounted {n} stdlib files from {PYTHON_STDLIB_ZIP_PATH} at {STDLIB_MOUNT_PREFIX}"
                ),
                Err(e) => eprintln!("[probe] WARN: stdlib mount error: {e}"),
            }
        }
        Err(e) => {
            eprintln!(
                "[probe] WARN: cannot read {PYTHON_STDLIB_ZIP_PATH}: {e}\n\
                 CPython will likely fail with 'No module named encodings'.\n\
                 Download with:\n\
                 curl -fsSL -o /tmp/python_stdlib.zip \\\n\
                     https://cdn.jsdelivr.net/pyodide/v0.26.4/full/python_stdlib.zip"
            );
        }
    }

    // Wire correctly-typed stubs for any GOT.func env.* imports not yet in the
    // linker (emscripten_gl*, emscripten_console_*, etc.). Must happen before
    // instantiation so the stubs are available for Path-3 in fill_got_table_slots.
    match wire_got_func_stubs_from_module(&mut store, &mut linker, &module) {
        Ok(n) => eprintln!("[probe] wired {n} GOT.func env.* stubs from module import section"),
        Err(e) => return format!("GOT STUB WIRING FAILED: {e}"),
    }

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

    // ---- phase 2: GOT resolution (assignGOTEntries) -------------------------
    //
    // Place host funcrefs into the pre-reserved table slots and write the
    // correct symbol addresses into GOT.mem globals. GOT.func globals were
    // already pre-filled with slot indices by wire_env_memory_and_table_in_store.

    eprintln!("[probe] resolving GOT entries...");
    match fill_got_table_slots(
        &mut store,
        &linker,
        &instance,
        &got_globals,
        &name_to_slot,
        &module,
        layout.host_got_base(),
    ) {
        Ok(report) => {
            eprintln!(
                "[probe] GOT resolved: {} from elem-seg, {} from export, {} stub (unresolved), {} mem",
                report.funcs_from_elem,
                report.funcs_from_export,
                report.funcs_stubbed,
                report.mem_resolved
            );
        }
        Err(e) => {
            return format!("GOT RESOLUTION FAILED: {e}");
        }
    }

    // ---- phase 3: __wasm_apply_data_relocs ----------------------------------

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

    // ---- phase 4: __wasm_call_ctors (CPython static init) -------------------

    let ctors_summary: String;
    if let Some(func) = instance.get_func(&mut store, "__wasm_call_ctors") {
        eprintln!("[probe] calling __wasm_call_ctors (CPython static init)...");
        match func.call(&mut store, &[], &mut []) {
            Ok(_) => {
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                let js_calls = log.total_calls();
                let js_names = log.snapshot();
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();

                if js_calls == 0 {
                    ctors_summary = format!(
                        "CTORS SUCCEEDED (no JS-FFI calls required)\n\
                         Total fuel consumed so far: {total_fuel}\n\
                         JS-FFI calls: 0\n\
                         WASI stdout after ctors ({} bytes): {wasi_text:?}",
                        wasi_out.len()
                    );
                } else {
                    ctors_summary = format!(
                        "CTORS SUCCEEDED (JS-FFI calls were logged but returned safe defaults)\n\
                         Total fuel consumed so far: {total_fuel}\n\
                         JS-FFI call count: {js_calls}\n\
                         JS-FFI functions called: {js_names:?}\n\
                         WASI stdout after ctors ({} bytes): {wasi_text:?}",
                        wasi_out.len()
                    );
                }
                eprintln!("[probe] {ctors_summary}");
            }
            Err(e) => {
                let js_calls = log.total_calls();
                let js_names = log.snapshot();
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();

                // Mechanical trace: last N env.* calls before the trap.
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

                // Classify the error.
                let err_str = format!("{e}");
                let trap_kind = e
                    .downcast_ref::<wasmtime::Trap>()
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| format!("(not a wasmtime::Trap); debug chain: {e:?}"));
                // Capture the wasm backtrace to surface the trapped function index.
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
                    .unwrap_or_else(|| "(no wasm backtrace)".to_owned());
                let finding = if err_str.contains("OutOfFuel") || err_str.contains("out of fuel") {
                    "fuel exhausted before boot completed; increase PROBE_FUEL"
                } else if err_str.contains("unimplemented import") {
                    "hit an auto-filled trap stub (unexpected import not in our list)"
                } else if err_str.contains("proc_exit") {
                    "CPython called proc_exit (clean or error exit via WASI)"
                } else if js_calls > 0 {
                    "CPython static init hit a JS-FFI stub that returned 0/null and caused a downstream trap"
                } else {
                    "CPython static init trapped in a mechanical Emscripten ABI function or in module code"
                };

                let last_invoke = store.data().last_invoke_idx;
                let last_invoke_str = if last_invoke == u64::MAX {
                    "none (invoke_dispatch not reached)".to_owned()
                } else {
                    format!("table[{last_invoke}]")
                };
                let throw_count = store.data().cxa_throw_count;
                let throw_log = store.data().cxa_throw_log.clone();
                let last_throw = throw_log.last().cloned();
                let mut throw_trace = String::new();
                for (n, name) in &throw_log {
                    throw_trace.push_str(&format!("  [throw #{n}] {name:?}\n"));
                }
                let fs_paths: Vec<String> = store.data().fs_path_log.iter().cloned().collect();
                return format!(
                    "BOOT FAILED at __wasm_call_ctors\n\
                     Error: {e}\n\
                     Trap kind: {trap_kind}\n\
                     Trap frames (innermost first): {trap_frames}\n\
                     Last invoke_dispatch table index: {last_invoke_str}\n\
                     Fuel consumed: {total_fuel}\n\
                     JS-FFI call count: {js_calls}\n\
                     JS-FFI functions called: {js_names:?}\n\
                     WASI stdout ({} bytes): {wasi_text:?}\n\
                     Auto-filled imports: {auto_filled:?}\n\
                     \n\
                     --- C++ exception throw log ({throw_count} total) ---\n\
                     {throw_trace}\
                     Last (escaping) throw: {last_throw:?}\n\
                     \n\
                     --- last 12 FS paths before escape ---\n\
                     {fs_paths:?}\n\
                     \n\
                     --- last {MECH_TRACE_TAIL} mechanical env.* calls before trap ---\n\
                     {mech_trace}\
                     Finding: {finding}",
                    wasi_out.len()
                );
            }
        }
    } else {
        eprintln!("[probe] __wasm_call_ctors not found; skipping to phase 5");
        ctors_summary = "CTORS: __wasm_call_ctors not exported (skipped)".to_owned();
    }

    // ---- phase 5: run the CPython interpreter --------------------------------
    //
    // Strategy A: `__main_argc_argv` is exported - call it with argc=0, argv=0.
    //   This is the standard Emscripten app entry; it drives full Python init
    //   and processes the interpreter flags baked in at compile time.
    //
    // Strategy B: No usable `main` - use the C API:
    //   1. Call `Py_InitializeEx(0)` (suppress signal registration).
    //   2. Write the print statement into guest memory at a scratch offset
    //      above the heap/stack area.
    //   3. Call `PyRun_SimpleString(ptr)`.
    //
    // The most likely outcome from either path is a CPython fatal error such as
    // "No module named 'encodings'" because `python_stdlib.zip` is not mounted
    // into the MEMFS. That error message is the primary deliverable of this
    // phase: it names the next layer to implement.
    run_python_phase(&instance, &mut store, &log, &mech_log, &ctors_summary)
}

/// Scratch offset in guest linear memory for small C-string arguments.
/// Placed well above `__heap_base` (4_632_232) and the stack region.
/// 32 MiB gives comfortable distance from both data and stack.
const SCRATCH_OFFSET: u32 = 32 * 1024 * 1024;

/// Drive the Python interpreter (phase 5) after ctors have completed.
///
/// Returns a human-readable outcome string (honest - no fabricated success).
fn run_python_phase(
    instance: &wasmtime::Instance,
    store: &mut Store<EmbedderState>,
    log: &JsFfiCallLog,
    mech_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::MechCallLog>,
    ctors_summary: &str,
) -> String {
    // Drain stdout accumulated during ctors before phase 5 starts.
    store.data_mut().wasi_stdout.clear();

    // DIAG: read global[175]+20 to see if the type-reflection struct was written.
    // global[175] is the first defined global (init=3246520); +20 is the reflection
    // function pointer slot checked in func 2176 before choosing reflection vs trampoline.
    if let Some(mem) = store.data().pyodide_memory {
        let mem_data = mem.data(&*store);
        let g175_addr: usize = 3246520;
        let check_addr = g175_addr + 20;
        if check_addr + 4 <= mem_data.len() {
            let word = i32::from_le_bytes(mem_data[check_addr..check_addr + 4].try_into().unwrap());
            eprintln!("[probe P5 DIAG] *(global175+20) @ 0x{check_addr:x} = {word}");
        }
        // Also check a wider view of the struct at global175
        if g175_addr + 64 <= mem_data.len() {
            let mut view = String::new();
            for off in (0..64).step_by(4) {
                let word = i32::from_le_bytes(
                    mem_data[g175_addr + off..g175_addr + off + 4]
                        .try_into()
                        .unwrap(),
                );
                view.push_str(&format!("  +{off}: {word}\n"));
            }
            eprintln!("[probe P5 DIAG] struct at global175 (3246520):\n{view}");
        }
    }

    // Strategy A: `__main_argc_argv(0, 0)` - Emscripten app entry.
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
                let js_calls = log.total_calls();
                return format!(
                    "{ctors_summary}\n\
                     \n\
                     --- phase 5: __main_argc_argv(0,0) ---\n\
                     Entry: __main_argc_argv\n\
                     Return value: {ret}\n\
                     Total fuel consumed: {total_fuel}\n\
                     JS-FFI calls total: {js_calls}\n\
                     WASI stdout ({} bytes): {wasi_text:?}",
                    wasi_out.len()
                );
            }
            Err(e) => {
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
                let fuel_remaining = store.get_fuel().unwrap_or(0);
                let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
                let js_calls = log.total_calls();
                let err_str = format!("{e}");
                let finding = classify_python_error(&err_str, js_calls);
                // Capture trap kind and wasm function index from the backtrace.
                let trap_kind = e
                    .downcast_ref::<wasmtime::Trap>()
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|| format!("(not a wasmtime::Trap); debug chain: {e:?}"));
                let trap_frames = e
                    .downcast_ref::<wasmtime::WasmBacktrace>()
                    .map(|bt| {
                        bt.frames()
                            .iter()
                            .take(20)
                            .map(|f| format!("func[{}]", f.func_index()))
                            .collect::<Vec<_>>()
                            .join(" <- ")
                    })
                    .unwrap_or_else(|| "(no wasm backtrace)".to_owned());
                // Mechanical trace from last N env.* calls before the trap.
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
                let last_invoke = store.data().last_invoke_idx;
                let last_invoke_str = if last_invoke == u64::MAX {
                    "none (invoke_dispatch not reached)".to_owned()
                } else {
                    format!("table[{last_invoke}]")
                };
                // C++ exception throw log: all recorded throws + last one (the escape candidate).
                let throw_count = store.data().cxa_throw_count;
                let throw_log = store.data().cxa_throw_log.clone();
                let last_throw = throw_log.last().cloned();
                let mut throw_trace = String::new();
                for (n, name) in &throw_log {
                    throw_trace.push_str(&format!("  [throw #{n}] {name:?}\n"));
                }
                // Last 12 FS paths before the exception escaped.
                let fs_paths: Vec<String> = store.data().fs_path_log.iter().cloned().collect();
                return format!(
                    "{ctors_summary}\n\
                     \n\
                     --- phase 5: __main_argc_argv(0,0) ---\n\
                     Entry: __main_argc_argv\n\
                     TRAPPED: {e}\n\
                     Trap kind: {trap_kind}\n\
                     Trap frames (innermost first, up to 20): {trap_frames}\n\
                     Last invoke_dispatch table index: {last_invoke_str}\n\
                     Total fuel consumed: {total_fuel}\n\
                     JS-FFI calls total: {js_calls}\n\
                     WASI stdout ({} bytes): {wasi_text:?}\n\
                     \n\
                     --- C++ exception throw log ({throw_count} total) ---\n\
                     {throw_trace}\
                     Last (escaping) throw: {last_throw:?}\n\
                     \n\
                     --- last 12 FS paths before escape ---\n\
                     {fs_paths:?}\n\
                     \n\
                     --- last {MECH_TRACE_TAIL} mechanical env.* calls before trap ---\n\
                     {mech_trace}\
                     Finding: {finding}",
                    wasi_out.len()
                );
            }
        }
    }

    // Strategy B: C API - Py_InitializeEx + PyRun_SimpleString.
    eprintln!("[probe P5] __main_argc_argv not found; using C API path");

    // Step B1: Py_InitializeEx(0).
    let py_init = match instance.get_func(&mut *store, "Py_InitializeEx") {
        Some(f) => f,
        None => {
            return format!(
                "{ctors_summary}\n\
                 \n\
                 --- phase 5: C API path ---\n\
                 Finding: Py_InitializeEx not exported; cannot initialize interpreter"
            );
        }
    };

    eprintln!("[probe P5] calling Py_InitializeEx(0)...");
    match py_init.call(&mut *store, &[wasmtime::Val::I32(0)], &mut []) {
        Ok(_) => {
            let wasi_after_init = store.data().wasi_stdout.clone();
            let init_text = String::from_utf8_lossy(&wasi_after_init).into_owned();
            eprintln!(
                "[probe P5] Py_InitializeEx returned; stdout so far ({} bytes): {init_text:?}",
                wasi_after_init.len()
            );
        }
        Err(e) => {
            let wasi_out = store.data().wasi_stdout.clone();
            let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
            let fuel_remaining = store.get_fuel().unwrap_or(0);
            let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
            let js_calls = log.total_calls();
            let err_str = format!("{e}");
            let finding = classify_python_error(&err_str, js_calls);
            return format!(
                "{ctors_summary}\n\
                 \n\
                 --- phase 5: C API path ---\n\
                 Entry: Py_InitializeEx(0)\n\
                 TRAPPED at Py_InitializeEx: {e}\n\
                 Total fuel consumed: {total_fuel}\n\
                 JS-FFI calls total: {js_calls}\n\
                 WASI stdout ({} bytes): {wasi_text:?}\n\
                 Finding: {finding}",
                wasi_out.len()
            );
        }
    }

    // Step B2: write the Python source into guest memory and call PyRun_SimpleString.
    let py_run = match instance.get_func(&mut *store, "PyRun_SimpleString") {
        Some(f) => f,
        None => {
            let wasi_out = store.data().wasi_stdout.clone();
            let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
            return format!(
                "{ctors_summary}\n\
                 \n\
                 --- phase 5: C API path ---\n\
                 Entry: Py_InitializeEx(0) succeeded\n\
                 Finding: PyRun_SimpleString not exported; cannot run code\n\
                 WASI stdout ({} bytes): {wasi_text:?}",
                wasi_out.len()
            );
        }
    };

    // Write a null-terminated Python one-liner into guest memory.
    let src = b"print('hello from cpython on afterburner')\n\0";

    // Borrow check note: Memory is Copy; extract the handle first, then write.
    let maybe_mem = store.data().pyodide_memory;
    let scratch_ptr = match maybe_mem {
        Some(mem) => {
            let offset = SCRATCH_OFFSET as usize;
            let mem_len = mem.data_size(&*store);
            if offset + src.len() > mem_len {
                let wasi_out = store.data().wasi_stdout.clone();
                let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
                return format!(
                    "{ctors_summary}\n\
                     \n\
                     --- phase 5: C API path ---\n\
                     Entry: Py_InitializeEx(0) succeeded\n\
                     Finding: cannot write to guest memory at SCRATCH_OFFSET={SCRATCH_OFFSET} \
                     (offset+len={} > mem_size={mem_len})\n\
                     WASI stdout ({} bytes): {wasi_text:?}",
                    offset + src.len(),
                    wasi_out.len()
                );
            }
            let data = mem.data_mut(&mut *store);
            data[offset..offset + src.len()].copy_from_slice(src);
            eprintln!(
                "[probe P5] wrote {} bytes to guest memory at 0x{offset:x}",
                src.len()
            );
            offset as i32
        }
        None => {
            let wasi_out = store.data().wasi_stdout.clone();
            let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
            return format!(
                "{ctors_summary}\n\
                 \n\
                 --- phase 5: C API path ---\n\
                 Entry: Py_InitializeEx(0) succeeded\n\
                 Finding: cannot write to guest memory at SCRATCH_OFFSET={SCRATCH_OFFSET} \
                 (memory too small or not yet set)\n\
                 WASI stdout ({} bytes): {wasi_text:?}",
                wasi_out.len()
            );
        }
    };

    // Drain init stdout before the run call.
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
    let js_calls = log.total_calls();

    match run_result {
        Ok(()) => {
            format!(
                "{ctors_summary}\n\
                 \n\
                 --- phase 5: C API path ---\n\
                 Entry: Py_InitializeEx(0) then PyRun_SimpleString\n\
                 PyRun_SimpleString returned (no trap)\n\
                 Total fuel consumed: {total_fuel}\n\
                 JS-FFI calls total: {js_calls}\n\
                 WASI stdout ({} bytes): {wasi_text:?}",
                wasi_out.len()
            )
        }
        Err(e) => {
            let err_str = format!("{e}");
            let finding = classify_python_error(&err_str, js_calls);
            format!(
                "{ctors_summary}\n\
                 \n\
                 --- phase 5: C API path ---\n\
                 Entry: Py_InitializeEx(0) then PyRun_SimpleString\n\
                 TRAPPED at PyRun_SimpleString: {e}\n\
                 Total fuel consumed: {total_fuel}\n\
                 JS-FFI calls total: {js_calls}\n\
                 WASI stdout ({} bytes): {wasi_text:?}\n\
                 Finding: {finding}",
                wasi_out.len()
            )
        }
    }
}

/// Classify a Python-phase error string into a human-readable finding.
fn classify_python_error(err_str: &str, js_calls: usize) -> &'static str {
    if err_str.contains("OutOfFuel") || err_str.contains("out of fuel") {
        "fuel exhausted; increase PROBE_FUEL"
    } else if err_str.contains("proc_exit") {
        "CPython called proc_exit (fatal init failure or clean exit)"
    } else if err_str.contains("encodings") || err_str.contains("No module named") {
        "Python stdlib not found: python_stdlib.zip is not mounted in MEMFS; next step is MEMFS"
    } else if err_str.contains("prefix") || err_str.contains("path configuration") {
        "Python path configuration error: no prefix/exec-prefix set; MEMFS with stdlib needed"
    } else if err_str.contains("unimplemented import") {
        "hit an auto-filled trap stub (unexpected import)"
    } else if js_calls > 0 {
        "JS-FFI stub returned 0/null and caused a downstream trap"
    } else {
        "trapped in Emscripten ABI or module code; check WASI stdout for Python fatal message"
    }
}
