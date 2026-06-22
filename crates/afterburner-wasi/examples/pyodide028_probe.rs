// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Bring-up probe for Pyodide 0.28.3 (`pyodide.asm.wasm`) via the exnref bridge.
//!
//! # Background
//!
//! Pyodide 0.28+ is compiled with Emscripten `-fwasm-exceptions`, which emits
//! the legacy Wasm exceptions proposal (`try`/`catch`/`rethrow`). Cranelift 44
//! does NOT compile that form. However, Binaryen wasm-opt v130 can translate it
//! to the new exnref proposal (`try_table`/`throw_ref`), which Cranelift 44 DOES
//! compile when `wasm_function_references(true)` + `wasm_gc(true)` +
//! `wasm_exceptions(true)` are set on the engine config.
//!
//! # Approach (exnref bridge)
//!
//! 1. Pre-translate `pyodide-new.asm.wasm` with wasm-opt to produce
//!    `pyodide-exnref.wasm` (try_table form). Done offline; see path constant.
//! 2. Build an engine with the new-EH config (function-references + gc + exceptions).
//! 3. `Module::new` compiles the translated binary. Key deliverable: does it compile?
//! 4. Wire imports (Emscripten ABI + sentinel stubs + EH tags) and boot CPython.
//!
//! # Verified binary facts (from wasm-tools on the TRANSLATED binary)
//!
//! - Pyodide 0.28.3, CPython 3.13.2
//! - 0 `invoke_*` imports (none needed - native EH)
//! - 2 tag imports: `env.__c_longjmp`, `env.__cpp_exception` (type: (i32) -> ())
//! - 252 env function imports, 280 GOT.func imports
//! - 2 `sentinel` imports: `sentinel::is_sentinel`, `sentinel::create_sentinel`
//! - After translation: 1142 `try_table` instructions; 0 legacy `try` instructions
//! - Table initial: 6073; Memory: 320 pages initial, max 65536
//!
//! # Usage
//!
//! Translate first (one-time, ~5 seconds):
//!
//!   ~/.local/bin/wasm-opt --translate-to-exnref \
//!     --enable-exception-handling --enable-reference-types \
//!     --enable-bulk-memory --enable-simd --enable-sign-ext \
//!     --enable-nontrapping-float-to-int --enable-mutable-globals \
//!     /tmp/pyodide-new.asm.wasm -o /tmp/pyodide-exnref.wasm
//!
//! Then run:
//!
//!   cargo run -p afterburner-wasi --example pyodide028_probe

use std::fs;

use afterburner_wasi::embedder_vm::EmbedderState;
use afterburner_wasi::emscripten_dylink::{
    fill_got_table_slots, parse_got_name_to_slot, wire_got_func_stubs_from_module,
};
use afterburner_wasi::emscripten_fs::mount_zip_into_fs;
use afterburner_wasi::emscripten_invoke::wire_invoke_trampolines;
use afterburner_wasi::emscripten_mechanical::wire_pyodide028_env_stubs;
use afterburner_wasi::emscripten_runtime::{
    JsFfiCallLog, MechCallLog, NoopCallLog, PYODIDE_STACK_BASE, fill_unknown_imports_as_noops,
    wire_env_memory_and_table_in_store, wire_wasi_only,
};
use afterburner_wasi::emscripten_syscall::wire_fs_env_funcs;
use wasmtime::{
    Config, Engine, FuncType, Global, GlobalType, Linker, Module, Mutability, OptLevel, Store, Tag,
    TagType, Val, ValType, WasmBacktraceDetails,
};

const MECH_TRACE_TAIL: usize = 40;

/// Path to Pyodide 0.28.3 wasm binary (exnref-translated via wasm-opt --translate-to-exnref).
/// Produce with: ~/.local/bin/wasm-opt --translate-to-exnref --enable-exception-handling
///   --enable-reference-types --enable-bulk-memory --enable-simd --enable-sign-ext
///   --enable-nontrapping-float-to-int --enable-mutable-globals
///   /tmp/pyodide-new.asm.wasm -o /tmp/pyodide-exnref.wasm
const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";

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

/// Build the exnref engine config: new exceptions proposal (try_table / throw_ref)
/// plus the function-references and GC proposals it depends on. Cranelift 44
/// supports this path; it does NOT support the legacy try/catch form.
///
/// The input binary must be pre-translated via:
///   wasm-opt --translate-to-exnref ... pyodide-new.asm.wasm -o pyodide-exnref.wasm
fn exnref_engine_cfg() -> Config {
    let mut cfg = Config::new();
    cfg.cranelift_opt_level(OptLevel::Speed)
        .cranelift_nan_canonicalization(true)
        .wasm_relaxed_simd(true)
        .relaxed_simd_deterministic(true)
        .wasm_threads(false)
        .consume_fuel(true)
        // New exceptions proposal (try_table / throw_ref / exnref). Requires
        // function-references + GC as the exnref type depends on them.
        .wasm_function_references(true)
        .wasm_gc(true)
        .wasm_exceptions(true)
        .wasm_backtrace_details(WasmBacktraceDetails::Enable);
    cfg
}

fn run_probe() -> String {
    // ---- load the wasm bytes -------------------------------------------------
    // Expects /tmp/pyodide-exnref.wasm: the Pyodide 0.28.3 binary translated
    // from legacy-EH (try/catch) to the new exnref proposal (try_table) by:
    //   ~/.local/bin/wasm-opt --translate-to-exnref \
    //     --enable-exception-handling --enable-reference-types \
    //     --enable-bulk-memory --enable-simd --enable-sign-ext \
    //     --enable-nontrapping-float-to-int --enable-mutable-globals \
    //     /tmp/pyodide-new.asm.wasm -o /tmp/pyodide-exnref.wasm

    let wasm_bytes = match fs::read(PYODIDE_WASM_PATH) {
        Ok(b) => b,
        Err(e) => {
            return format!(
                "LOAD FAILED: cannot read {PYODIDE_WASM_PATH}: {e}\n\
                 Translate with:\n\
                 ~/.local/bin/wasm-opt --translate-to-exnref \\\n\
                   --enable-exception-handling --enable-reference-types \\\n\
                   --enable-bulk-memory --enable-simd --enable-sign-ext \\\n\
                   --enable-nontrapping-float-to-int --enable-mutable-globals \\\n\
                   /tmp/pyodide-new.asm.wasm -o /tmp/pyodide-exnref.wasm"
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

    // ---- STEP 1: Engine::new with exnref config + Module::new ---------------
    //
    // The binary at PYODIDE_WASM_PATH has been translated from legacy-EH
    // (try/catch) to the new exnref proposal (try_table / throw_ref) by
    // wasm-opt v130. Cranelift 44 supports try_table; it rejects the legacy
    // try/catch form. Enabling wasm_function_references + wasm_gc + wasm_exceptions
    // is what allows Cranelift to compile the translated module.
    //
    // Key deliverable (step 1): does Module::new succeed?

    let cfg = exnref_engine_cfg();
    eprintln!("[probe] STEP 1: Engine::new with exnref config (wasm_exceptions + gc)...");
    let engine = match Engine::new(&cfg) {
        Ok(e) => {
            eprintln!("[probe] Engine::new SUCCEEDED");
            e
        }
        Err(e) => {
            return format!(
                "STEP 1 FAILED: Engine::new(exnref config): {e}\n\
                 Expected: wasmtime 44 + gc feature should accept this config."
            );
        }
    };

    step1_succeeded(engine, &wasm_bytes, &name_to_slot)
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
    let noop_log = NoopCallLog::new();
    let mut linker: Linker<EmbedderState> = Linker::new(&engine);

    // Wire only the WASI shims (wasi_snapshot_preview1.*). All env.* imports
    // (mechanical + jsffi) are auto-filled from the module's actual types below,
    // because the exnref translation changed many env.* signatures (externref
    // now appears where i32 was in 0.26.4). Pre-registering 0.26.4-typed stubs
    // causes wasmtime type-mismatch at instantiation.
    if let Err(e) = wire_wasi_only(&mut linker) {
        return format!("IMPORT SETUP FAILED (wasi): {e}");
    }
    // Wire invoke_* and PyCFunction trampolines. _PyEM_TrampolineCall_JS uses
    // the same pure-i32 signature in 0.28 (the exnref translation only adds
    // externref to JS-FFI stubs, not to these table-dispatch trampolines).
    // Without this, the no-op stub returns NULL to every PyCFunction call, and
    // CPython corrupts its heap on the way into malloc.
    if let Err(e) = wire_invoke_trampolines(&engine, &mut linker) {
        return format!("IMPORT SETUP FAILED (trampolines): {e}");
    }
    let mech_log = MechCallLog::new();
    // Wire __syscall_* FS functions. All are pure i32 (no externref in 0.28);
    // the no-op stubs make getcwd/openat return 0/null and CPython's path
    // evaluation fails before it can load any module.
    if let Err(e) = wire_fs_env_funcs(&mut linker, mech_log.clone()) {
        return format!("IMPORT SETUP FAILED (syscalls): {e}");
    }
    // Wire output-capture and PyCFunction-trampoline helpers for Pyodide 0.28.
    // This must happen BEFORE fill_got_table_slots so that emscripten_out and
    // emscripten_err are placed in the GOT.func table (Path 3 resolution),
    // making CPython print() write to wasi_stdout.
    if let Err(e) = wire_pyodide028_env_stubs(&engine, &mut linker) {
        return format!("IMPORT SETUP FAILED (pyodide028 stubs): {e}");
    }

    // sentinel::is_sentinel: (externref) -> i32
    // sentinel::create_sentinel: () -> externref
    // After exnref translation the JS-sentinel types use externref. Wire them
    // with func_new + explicit FuncType (func_wrap cannot express externref).
    let is_sentinel_ty = FuncType::new(&engine, [ValType::EXTERNREF], [ValType::I32]);
    if let Err(e) = linker.func_new(
        "sentinel",
        "is_sentinel",
        is_sentinel_ty,
        |_caller, _params, results| {
            results[0] = Val::I32(0);
            Ok(())
        },
    ) {
        return format!("IMPORT SETUP FAILED: sentinel::is_sentinel: {e}");
    }
    let create_sentinel_ty = FuncType::new(&engine, [], [ValType::EXTERNREF]);
    if let Err(e) = linker.func_new(
        "sentinel",
        "create_sentinel",
        create_sentinel_ty,
        |_caller, _params, results| {
            results[0] = Val::ExternRef(None);
            Ok(())
        },
    ) {
        return format!("IMPORT SETUP FAILED: sentinel::create_sentinel: {e}");
    }
    eprintln!("[probe] wired sentinel stubs (externref types)");

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

    // Use no-ops (not traps) for remaining unknown imports so CPython boot can
    // proceed past Pyodide 0.28 JS-FFI stubs that don't exist in 0.26.4.
    // A no-op returns zero/null; unknown stubs that matter will surface as
    // downstream errors (wrong return value) rather than immediate traps.
    let auto_filled =
        fill_unknown_imports_as_noops(&mut store, &mut linker, &module, noop_log.clone());
    eprintln!(
        "[probe] {} imports auto-filled as no-op stubs",
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
                let noop_calls = noop_log.snapshot();
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
                     Noop stubs called ({} unique): {noop_calls:?}\n\
                     Finding: {finding}",
                    log.total_calls(),
                    wasi_out.len(),
                    noop_calls.len()
                );
            }
        }
    } else {
        ctors_summary = "CTORS: not exported (skipped)".to_owned();
    }

    run_python_phase(
        &instance,
        &mut store,
        &log,
        &mech_log,
        &noop_log,
        &ctors_summary,
    )
}

/// Python code passed as the `-c` argument to `__main_argc_argv`.
///
/// NUL-terminated. Written into wasm memory and pointed to by argv[2].
/// The newline before the NUL is required by CPython's `-c` parser.
const PYTHON_CODE: &[u8] =
    b"print('hello from cpython on afterburner')\nimport sys\nprint('pyver', sys.version.split()[0])\nprint('sum', sum(range(100)))\n\0";

/// Write a NUL-terminated C string into a newly grown wasm memory page.
///
/// Grows memory by one page (64 KiB) so the write never overlaps anything
/// CPython placed during `__wasm_call_ctors`. Returns the wasm guest address.
fn alloc_cstr(store: &mut Store<EmbedderState>, s: &[u8]) -> Result<u32, String> {
    let mem = store
        .data()
        .pyodide_memory
        .ok_or_else(|| "pyodide_memory not set".to_owned())?;
    let prev = mem
        .grow(&mut *store, 1)
        .map_err(|e| format!("memory.grow: {e}"))?;
    let base = (prev as usize) * 65536;
    let mem_len = mem.data_size(&*store);
    if base + s.len() > mem_len {
        return Err(format!(
            "alloc_cstr: [{base:#x}..{:#x}) exceeds memory {mem_len:#x}",
            base + s.len()
        ));
    }
    mem.data_mut(&mut *store)[base..base + s.len()].copy_from_slice(s);
    Ok(base as u32)
}

/// Verify fd_write shim reachable via direct `write` export (pre-Python).
/// "PROBE-WRITE-DIRECT\n" in wasi_stdout = fd_write shim is wired correctly.
/// Empty = Emscripten FS layer intercepts writes before they reach the shim.
fn probe_direct_write(instance: &wasmtime::Instance, store: &mut Store<EmbedderState>) {
    const MSG: &[u8] = b"PROBE-WRITE-DIRECT\n";
    let buf_ptr = match alloc_cstr(store, MSG) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[probe_direct_write] alloc_cstr failed: {e}");
            return;
        }
    };
    eprintln!(
        "[probe_direct_write] calling write(1, {buf_ptr:#x}, {}) via wasm export...",
        MSG.len()
    );
    let write_fn = match instance.get_func(&mut *store, "write") {
        Some(f) => f,
        None => {
            eprintln!("[probe_direct_write] 'write' not exported - skip");
            return;
        }
    };
    let mut results = [wasmtime::Val::I32(-1)];
    match write_fn.call(
        &mut *store,
        &[
            wasmtime::Val::I32(1),
            wasmtime::Val::I32(buf_ptr as i32),
            wasmtime::Val::I32(MSG.len() as i32),
        ],
        &mut results,
    ) {
        Ok(_) => {
            let ret = match results[0] {
                wasmtime::Val::I32(v) => v,
                _ => -1,
            };
            let captured = store.data().wasi_stdout.len();
            let snippet = String::from_utf8_lossy(&store.data().wasi_stdout).into_owned();
            eprintln!("[probe_direct_write] write() ret={ret} captured={captured}: {snippet:?}");
        }
        Err(e) => eprintln!("[probe_direct_write] write() trapped: {e}"),
    }
    store.data_mut().wasi_stdout.clear();
}

/// Source-faithful boot sequence (main.c authoritative):
///
/// 1. `__main_argc_argv(3, argv_ptr)` with argv = ["python", "-c", CODE].
///    This is the Emscripten `__main_argc_argv` which calls
///    `PyImport_AppendInittab` then `initialize_python` (Py_Initialize).
///    CPython is NOT yet initialized after `__wasm_call_ctors`; that only
///    ran C++ static constructors. `__main_argc_argv` MUST run EXACTLY ONCE.
///    If it returns non-zero the probe reports the exit code and wasi_stdout.
///
/// 2. `run_main()` - calls `pymain_run_python` which executes the -c command.
///    Returns i32 exitcode (0 = success).
///
/// 3. Read and print `wasi_stdout` verbatim.
fn run_python_phase(
    instance: &wasmtime::Instance,
    store: &mut Store<EmbedderState>,
    log: &JsFfiCallLog,
    mech_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::MechCallLog>,
    noop_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::NoopCallLog>,
    ctors_summary: &str,
) -> String {
    // Verify fd_write shim reachable before Python (diagnostic only).
    probe_direct_write(instance, store);
    store.data_mut().wasi_stdout.clear();

    // Report which exports are present.
    let has_main = instance.get_func(&mut *store, "__main_argc_argv").is_some();
    let has_run_main = instance.get_func(&mut *store, "run_main").is_some();
    let has_pymain = instance
        .get_func(&mut *store, "pymain_run_python")
        .is_some();
    eprintln!(
        "[probe P5] exports: __main_argc_argv={has_main} run_main={has_run_main} \
         pymain_run_python={has_pymain}"
    );

    // __main_argc_argv is required: it calls Py_Initialize with the -c argv.
    let main_fn = match instance.get_func(&mut *store, "__main_argc_argv") {
        Some(f) => f,
        None => {
            let wasi_out = store.data().wasi_stdout.clone();
            let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
            return format!(
                "{ctors_summary}\n\
                 --- phase 5: __main_argc_argv ---\n\
                 exports: __main_argc_argv={has_main} run_main={has_run_main}\n\
                 BLOCKED: __main_argc_argv not exported; cannot initialize CPython.\n\
                 WASI stdout ({} bytes):\n{wasi_text}",
                wasi_out.len()
            );
        }
    };

    // Build argv in wasm memory: ["python\0", "-c\0", CODE\0] + pointer table.
    // Layout (all wasm32 = 4-byte pointers, little-endian):
    //   arg0_ptr  -> "python\0"
    //   arg1_ptr  -> "-c\0"
    //   arg2_ptr  -> PYTHON_CODE
    //   argv_ptr  -> [arg0_ptr, arg1_ptr, arg2_ptr, 0] (NULL terminator)
    let arg0_ptr = match alloc_cstr(store, b"python\0") {
        Ok(p) => p,
        Err(e) => return format!("{ctors_summary}\n--- phase 5 ---\nARGV ALLOC FAILED: {e}"),
    };
    let arg1_ptr = match alloc_cstr(store, b"-c\0") {
        Ok(p) => p,
        Err(e) => return format!("{ctors_summary}\n--- phase 5 ---\nARGV ALLOC FAILED: {e}"),
    };
    let arg2_ptr = match alloc_cstr(store, PYTHON_CODE) {
        Ok(p) => p,
        Err(e) => return format!("{ctors_summary}\n--- phase 5 ---\nARGV ALLOC FAILED: {e}"),
    };
    // argv[] array: 4 entries x 4 bytes = 16 bytes; use one more page.
    let argv_ptr = {
        let mem = store
            .data()
            .pyodide_memory
            .expect("pyodide_memory set by wire_env_memory_and_table_in_store");
        let prev = mem.grow(&mut *store, 1).map_err(|e| format!("{e}"));
        let prev = match prev {
            Ok(p) => p,
            Err(e) => {
                return format!("{ctors_summary}\n--- phase 5 ---\nARGV TABLE ALLOC FAILED: {e}");
            }
        };
        let base = (prev as usize) * 65536;
        let data = mem.data_mut(&mut *store);
        data[base..base + 4].copy_from_slice(&arg0_ptr.to_le_bytes());
        data[base + 4..base + 8].copy_from_slice(&arg1_ptr.to_le_bytes());
        data[base + 8..base + 12].copy_from_slice(&arg2_ptr.to_le_bytes());
        data[base + 12..base + 16].copy_from_slice(&0u32.to_le_bytes());
        base as i32
    };
    eprintln!(
        "[probe P5] argv: arg0={arg0_ptr:#x}('python') arg1={arg1_ptr:#x}('-c') \
         arg2={arg2_ptr:#x}(CODE) argv_table={argv_ptr:#x}"
    );

    // Step 1: __main_argc_argv(argc=3, argv=argv_ptr).
    // This calls PyImport_AppendInittab + initialize_python (= Py_Initialize).
    // MUST be called EXACTLY ONCE; a second call is a fatal "after Py_Initialize".
    store.data_mut().wasi_stdout.clear();
    eprintln!("[probe P5] calling __main_argc_argv(3, {argv_ptr:#x})...");
    let mut main_ret = [wasmtime::Val::I32(-99)];
    let main_result = main_fn.call(
        &mut *store,
        &[wasmtime::Val::I32(3), wasmtime::Val::I32(argv_ptr)],
        &mut main_ret,
    );

    {
        let wasi_mid = store.data().wasi_stdout.clone();
        if !wasi_mid.is_empty() {
            eprintln!(
                "[probe P5] wasi_stdout after __main_argc_argv ({} bytes): {:?}",
                wasi_mid.len(),
                String::from_utf8_lossy(&wasi_mid)
            );
        }
    }

    let main_exitcode = match main_result {
        Ok(()) => match main_ret[0] {
            wasmtime::Val::I32(v) => v,
            _ => -99,
        },
        Err(ref e) => {
            let wasi_out = store.data().wasi_stdout.clone();
            let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
            let fuel_remaining = store.get_fuel().unwrap_or(0);
            let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
            let noop_calls = noop_log.snapshot();
            let mech_tail = mech_log.tail(MECH_TRACE_TAIL);
            let mech_trace = format_mech_tail(&mech_tail);
            let throw_count = store.data().cxa_throw_count;
            let fs_paths: Vec<String> = store.data().fs_path_log.iter().cloned().collect();
            let finding = classify_python_error(&format!("{e}"), log.total_calls());
            return format!(
                "{ctors_summary}\n\
                 --- phase 5: __main_argc_argv(3, argv) ---\n\
                 exports: __main_argc_argv={has_main} run_main={has_run_main}\n\
                 TRAPPED in __main_argc_argv: {e}\n\
                 Fuel consumed: {total_fuel}\n\
                 JS-FFI calls: {}\n\
                 C++ throws: {throw_count}\n\
                 Last 12 FS paths: {fs_paths:?}\n\
                 Noop stubs called ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 WASI stdout ({} bytes):\n{wasi_text}\n\
                 Finding: {finding}",
                log.total_calls(),
                noop_calls.len(),
                wasi_out.len()
            );
        }
    };
    eprintln!("[probe P5] __main_argc_argv returned {main_exitcode}");

    if main_exitcode != 0 {
        let wasi_out = store.data().wasi_stdout.clone();
        let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
        return format!(
            "{ctors_summary}\n\
             --- phase 5: __main_argc_argv(3, argv) ---\n\
             exports: __main_argc_argv={has_main} run_main={has_run_main}\n\
             __main_argc_argv returned {main_exitcode} (non-zero = init failure)\n\
             Fuel consumed: {total_fuel}\n\
             JS-FFI calls: {}\n\
             WASI stdout ({} bytes):\n{wasi_text}\n\
             Finding: CPython initialization returned non-zero exit",
            log.total_calls(),
            wasi_out.len()
        );
    }

    // Step 2: run_main() calls pymain_run_python which executes the -c code.
    // Prefer run_main (EMSCRIPTEN_KEEPALIVE); fall back to pymain_run_python
    // if run_main is absent in this binary variant.
    let (run_entry_name, run_fn) = if let Some(f) = instance.get_func(&mut *store, "run_main") {
        ("run_main", f)
    } else if let Some(f) = instance.get_func(&mut *store, "pymain_run_python") {
        ("pymain_run_python", f)
    } else {
        let wasi_out = store.data().wasi_stdout.clone();
        let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
        return format!(
            "{ctors_summary}\n\
             --- phase 5: run_main ---\n\
             exports: __main_argc_argv={has_main} run_main={has_run_main}\n\
             BLOCKED: neither run_main nor pymain_run_python exported.\n\
             WASI stdout ({} bytes):\n{wasi_text}",
            wasi_out.len()
        );
    };
    eprintln!("[probe P5] calling {run_entry_name}()...");

    store.data_mut().wasi_stdout.clear();
    let mut run_ret = [wasmtime::Val::I32(-99)];
    let run_result = run_fn.call(&mut *store, &[], &mut run_ret);

    let wasi_out = store.data().wasi_stdout.clone();
    let wasi_text = String::from_utf8_lossy(&wasi_out).into_owned();
    let fuel_remaining = store.get_fuel().unwrap_or(0);
    let total_fuel = PROBE_FUEL.saturating_sub(fuel_remaining);
    let noop_calls = noop_log.snapshot();
    let mech_tail = mech_log.tail(MECH_TRACE_TAIL);
    let mech_trace = format_mech_tail(&mech_tail);

    match run_result {
        Ok(()) => {
            let exitcode = match run_ret[0] {
                wasmtime::Val::I32(v) => v,
                _ => -99,
            };
            eprintln!("[probe P5] {run_entry_name} exitcode={exitcode}");
            eprintln!(
                "[probe P5] wasi_stdout ({} bytes):\n{wasi_text}",
                wasi_out.len()
            );
            let milestone = if wasi_text.contains("hello from cpython on afterburner")
                && wasi_text.contains("pyver")
                && wasi_text.contains("4950")
            {
                "MILESTONE MET: Python executed and produced expected output"
            } else if !wasi_text.is_empty() {
                "PARTIAL: some output captured but expected strings missing"
            } else {
                "NO OUTPUT: run_main returned but wasi_stdout is empty"
            };
            format!(
                "{ctors_summary}\n\
                 --- phase 5: __main_argc_argv + {run_entry_name} ---\n\
                 exports: __main_argc_argv={has_main} run_main={has_run_main} \
                 pymain_run_python={has_pymain}\n\
                 __main_argc_argv exitcode: {main_exitcode}\n\
                 {run_entry_name} exitcode: {exitcode}\n\
                 Fuel consumed: {total_fuel}\n\
                 JS-FFI calls: {}\n\
                 Noop stubs called ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 WASI stdout ({} bytes):\n{wasi_text}\n\
                 {milestone}",
                log.total_calls(),
                noop_calls.len(),
                wasi_out.len()
            )
        }
        Err(e) => {
            let finding = classify_python_error(&format!("{e}"), log.total_calls());
            let throw_count = store.data().cxa_throw_count;
            let fs_paths: Vec<String> = store.data().fs_path_log.iter().cloned().collect();
            format!(
                "{ctors_summary}\n\
                 --- phase 5: __main_argc_argv + {run_entry_name} ---\n\
                 exports: __main_argc_argv={has_main} run_main={has_run_main} \
                 pymain_run_python={has_pymain}\n\
                 __main_argc_argv exitcode: {main_exitcode}\n\
                 TRAPPED in {run_entry_name}: {e}\n\
                 Fuel consumed: {total_fuel}\n\
                 JS-FFI calls: {}\n\
                 C++ throws: {throw_count}\n\
                 Last 12 FS paths: {fs_paths:?}\n\
                 Noop stubs called ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 WASI stdout ({} bytes):\n{wasi_text}\n\
                 Finding: {finding}",
                log.total_calls(),
                noop_calls.len(),
                wasi_out.len()
            )
        }
    }
}

fn format_mech_tail(tail: &[afterburner_wasi::emscripten_runtime::MechCallEntry]) -> String {
    tail.iter()
        .enumerate()
        .map(|(i, entry)| {
            if entry.arg0 != 0 || entry.arg1 != 0 {
                format!(
                    "  [{:>3}] {} (arg0={}, arg1={})\n",
                    i + 1,
                    entry.name,
                    entry.arg0,
                    entry.arg1
                )
            } else {
                format!("  [{:>3}] {}\n", i + 1, entry.name)
            }
        })
        .collect()
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
