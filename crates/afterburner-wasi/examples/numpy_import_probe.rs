// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Bring-up probe for `import numpy as np` via Emscripten SIDE_MODULE linking.
//!
//! ## Prerequisites (same as pyodide028_probe)
//!
//! - `/tmp/pyodide-exnref.wasm` - Pyodide 0.28.3 translated to exnref EH.
//! - `/tmp/python_stdlib.zip` - Python 3.13 stdlib zip.
//! - `/tmp/numpy_check.whl` - numpy Pyodide wheel (contains .so WASM files).
//!
//! ## Usage
//!
//!   cargo run -p afterburner-wasi --example numpy_import_probe

use std::fs;
use std::num::NonZeroUsize;

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
use afterburner_wasi::emscripten_sidemodule::{pre_load_side_module, wire_dlopen_dlsym};
use afterburner_wasi::emscripten_syscall::wire_fs_env_funcs;
use wasmtime::{
    Config, Engine, FuncType, Global, GlobalType, Linker, Module, Mutability, OptLevel, Store, Tag,
    TagType, Trap, Val, ValType, WasmBacktrace, WasmBacktraceDetails,
};

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";
const NUMPY_WHEEL_PATH: &str = "/tmp/numpy_check.whl";

/// The .so that CPython dlopen()s to run `import numpy._core._multiarray_umath`.
const NUMPY_CORE_SO: &str = "numpy/_core/_multiarray_umath.cpython-313-wasm32-emscripten.so";

/// Guest site-packages prefix where numpy .py and .so files are mounted.
const SITE_PACKAGES: &str = "/lib/python3.13/site-packages";

/// stdlib prefix inside python_stdlib.zip
const STDLIB_MOUNT_PREFIX: &str = "/lib/python3.13";
const STDLIB_ZIP_MOUNT_PATH: &str = "/lib/python313.zip";

/// Instruction budget - numpy init is heavier than bare CPython.
/// 2T was exhausted during module discovery before dlopen; 10T gives margin
/// to reach and exercise the dlopen/dlsym path.
const PROBE_FUEL: u64 = 10_000_000_000_000;

const MECH_TRACE_TAIL: usize = 40;

fn main() {
    let outcome = run_probe();
    println!("\n=== NUMPY PROBE OUTCOME ===");
    println!("{outcome}");
}

fn exnref_engine_cfg() -> Config {
    let mut cfg = Config::new();
    cfg.cranelift_opt_level(OptLevel::Speed)
        .cranelift_nan_canonicalization(true)
        .wasm_relaxed_simd(true)
        .relaxed_simd_deterministic(true)
        .wasm_threads(false)
        .consume_fuel(true)
        .wasm_function_references(true)
        .wasm_gc(true)
        .wasm_exceptions(true)
        .wasm_backtrace_details(WasmBacktraceDetails::Enable)
        // Raise the frame cap so the full chain is not truncated at the default 20.
        .wasm_backtrace_max_frames(NonZeroUsize::new(500));
    cfg
}

/// Extract a named file from a zip archive (stored or deflate compressed).
fn extract_from_zip(zip_bytes: &[u8], target_name: &str) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut pos = 0usize;
    while pos + 30 <= zip_bytes.len() {
        let sig = u32::from_le_bytes(zip_bytes[pos..pos + 4].try_into().unwrap());
        if sig == 0x02014b50 || sig == 0x06054b50 {
            break;
        }
        if sig != 0x04034b50 {
            pos += 1;
            continue;
        }
        let compression = u16::from_le_bytes(zip_bytes[pos + 8..pos + 10].try_into().unwrap());
        let compressed_size =
            u32::from_le_bytes(zip_bytes[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let fname_len =
            u16::from_le_bytes(zip_bytes[pos + 26..pos + 28].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(zip_bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;

        let fname_start = pos + 30;
        let fname_end = fname_start + fname_len;
        if fname_end > zip_bytes.len() {
            break;
        }
        let fname = match std::str::from_utf8(&zip_bytes[fname_start..fname_end]) {
            Ok(s) => s,
            Err(_) => {
                pos = fname_end + extra_len + compressed_size;
                continue;
            }
        };
        let data_start = fname_end + extra_len;
        let data_end = data_start + compressed_size;
        if data_end > zip_bytes.len() {
            break;
        }
        if fname == target_name {
            let raw = &zip_bytes[data_start..data_end];
            return match compression {
                0 => Some(raw.to_vec()),
                8 => {
                    let mut dec = DeflateDecoder::new(raw);
                    let mut out = Vec::new();
                    dec.read_to_end(&mut out).ok()?;
                    Some(out)
                }
                _ => None,
            };
        }
        pos = data_end;
    }
    None
}

/// Mount all entries from a wheel (zip) into MEMFS under `guest_prefix`.
/// Skips the .dist-info directory entries. Returns the count of files mounted.
fn mount_wheel_into_fs(
    fs: &mut afterburner_wasi::emscripten_fs::InMemFs,
    wheel_bytes: &[u8],
    guest_prefix: &str,
) -> usize {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut count = 0usize;
    let mut pos = 0usize;
    while pos + 30 <= wheel_bytes.len() {
        let sig = u32::from_le_bytes(wheel_bytes[pos..pos + 4].try_into().unwrap());
        if sig == 0x02014b50 || sig == 0x06054b50 {
            break;
        }
        if sig != 0x04034b50 {
            pos += 1;
            continue;
        }
        let compression = u16::from_le_bytes(wheel_bytes[pos + 8..pos + 10].try_into().unwrap());
        let compressed_size =
            u32::from_le_bytes(wheel_bytes[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let fname_len =
            u16::from_le_bytes(wheel_bytes[pos + 26..pos + 28].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(wheel_bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let fname_start = pos + 30;
        let fname_end = fname_start + fname_len;
        if fname_end > wheel_bytes.len() {
            break;
        }
        let fname = match std::str::from_utf8(&wheel_bytes[fname_start..fname_end]) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                pos = fname_end + extra_len + compressed_size;
                continue;
            }
        };
        let data_start = fname_end + extra_len;
        let data_end = data_start + compressed_size;
        if data_end > wheel_bytes.len() {
            break;
        }
        // Skip dist-info and directories.
        if fname.contains(".dist-info") || fname.ends_with('/') {
            pos = data_end;
            continue;
        }
        let raw = &wheel_bytes[data_start..data_end];
        let contents = match compression {
            0 => raw.to_vec(),
            8 => {
                let mut dec = DeflateDecoder::new(raw);
                let mut out = Vec::new();
                if dec.read_to_end(&mut out).is_err() {
                    pos = data_end;
                    continue;
                }
                out
            }
            _ => {
                pos = data_end;
                continue;
            }
        };
        let guest_path = format!("{guest_prefix}/{fname}");
        fs.insert_file(&guest_path, contents);
        count += 1;
        pos = data_end;
    }
    count
}

fn run_probe() -> String {
    let wasm_bytes = match fs::read(PYODIDE_WASM_PATH) {
        Ok(b) => b,
        Err(e) => {
            return format!(
                "LOAD FAILED: cannot read {PYODIDE_WASM_PATH}: {e}\n\
                 Produce with: wasm-opt --translate-to-exnref ... pyodide-new.asm.wasm -o {PYODIDE_WASM_PATH}"
            );
        }
    };
    eprintln!("[numpy_probe] loaded pyodide ({} bytes)", wasm_bytes.len());

    let wheel_bytes = match fs::read(NUMPY_WHEEL_PATH) {
        Ok(b) => b,
        Err(e) => return format!("LOAD FAILED: cannot read {NUMPY_WHEEL_PATH}: {e}"),
    };
    eprintln!(
        "[numpy_probe] loaded numpy wheel ({} bytes)",
        wheel_bytes.len()
    );

    // Extract the main numpy C extension .so from the wheel.
    let numpy_so_bytes = match extract_from_zip(&wheel_bytes, NUMPY_CORE_SO) {
        Some(b) => b,
        None => {
            return format!("LOAD FAILED: cannot extract {NUMPY_CORE_SO} from {NUMPY_WHEEL_PATH}");
        }
    };
    eprintln!(
        "[numpy_probe] extracted {NUMPY_CORE_SO} ({} bytes)",
        numpy_so_bytes.len()
    );

    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, 1);
    eprintln!("[numpy_probe] parsed {} GOT entries", name_to_slot.len());

    let cfg = exnref_engine_cfg();
    let engine = match Engine::new(&cfg) {
        Ok(e) => e,
        Err(e) => return format!("ENGINE FAILED: {e}"),
    };

    let module = match Module::new(&engine, &wasm_bytes) {
        Ok(m) => m,
        Err(e) => return format!("COMPILE FAILED: {e}"),
    };
    eprintln!(
        "[numpy_probe] compiled pyodide ({} imports)",
        module.imports().count()
    );

    let _log = JsFfiCallLog::new();
    let noop_log = NoopCallLog::new();
    let mut linker: Linker<EmbedderState> = Linker::new(&engine);

    if let Err(e) = wire_wasi_only(&mut linker) {
        return format!("IMPORT SETUP FAILED (wasi): {e}");
    }
    if let Err(e) = wire_invoke_trampolines(&engine, &mut linker) {
        return format!("IMPORT SETUP FAILED (trampolines): {e}");
    }
    let mech_log = MechCallLog::new();
    if let Err(e) = wire_fs_env_funcs(&mut linker, mech_log.clone()) {
        return format!("IMPORT SETUP FAILED (syscalls): {e}");
    }
    if let Err(e) = wire_pyodide028_env_stubs(&engine, &mut linker) {
        return format!("IMPORT SETUP FAILED (pyodide028 stubs): {e}");
    }

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

    let mut store = Store::new(&engine, EmbedderState::for_emscripten());
    store.set_fuel(PROBE_FUEL).expect("set_fuel");

    let got_globals =
        match wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, 1, PYODIDE_STACK_BASE)
        {
            Ok(g) => g,
            Err(e) => return format!("MEMORY/TABLE SETUP FAILED: {e}"),
        };

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

    let got_ty = GlobalType::new(ValType::I32, Mutability::Var);
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
    }

    // Create /tmp and mount stdlib.
    store.data_mut().fs.mkdir_p("/tmp");

    match fs::read(PYTHON_STDLIB_ZIP_PATH) {
        Ok(zip_bytes) => {
            store
                .data_mut()
                .fs
                .insert_file(STDLIB_ZIP_MOUNT_PATH, zip_bytes.clone());
            match mount_zip_into_fs(&mut store.data_mut().fs, STDLIB_MOUNT_PREFIX, &zip_bytes) {
                Ok(n) => eprintln!("[numpy_probe] mounted {n} stdlib files"),
                Err(e) => eprintln!("[numpy_probe] WARN: stdlib mount: {e}"),
            }
        }
        Err(e) => eprintln!("[numpy_probe] WARN: stdlib not available: {e}"),
    }

    // Mount numpy .py and .so from the wheel into MEMFS site-packages.
    let np_files = mount_wheel_into_fs(&mut store.data_mut().fs, &wheel_bytes, SITE_PACKAGES);
    eprintln!("[numpy_probe] mounted {np_files} numpy files at {SITE_PACKAGES}");

    match wire_got_func_stubs_from_module(&mut store, &mut linker, &module) {
        Ok(n) => eprintln!("[numpy_probe] wired {n} GOT.func stubs"),
        Err(e) => return format!("GOT STUB WIRING FAILED: {e}"),
    }

    // Wire _dlopen_js / _dlsym_js before auto-filling noops so that Python's
    // dlopen dispatch reaches the SideModuleRegistry rather than returning 0.
    if let Err(e) = wire_dlopen_dlsym(&mut linker) {
        return format!("DLOPEN WIRING FAILED: {e}");
    }

    let auto_filled =
        fill_unknown_imports_as_noops(&mut store, &mut linker, &module, noop_log.clone());
    eprintln!("[numpy_probe] {} imports auto-filled", auto_filled.len());

    eprintln!("[numpy_probe] instantiating...");
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            return format!("INSTANTIATION FAILED: {e}");
        }
    };
    eprintln!("[numpy_probe] instantiated");

    match fill_got_table_slots(
        &mut store,
        &linker,
        &instance,
        &got_globals,
        &name_to_slot,
        &module,
    ) {
        Ok(r) => eprintln!(
            "[numpy_probe] GOT: {} elem, {} export, {} stub, {} mem",
            r.funcs_from_elem, r.funcs_from_export, r.funcs_stubbed, r.mem_resolved
        ),
        Err(e) => return format!("GOT RESOLUTION FAILED: {e}"),
    }

    if let Some(func) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("RELOC FAILED: {e}");
        }
        eprintln!("[numpy_probe] __wasm_apply_data_relocs OK");
    }

    // Pre-load the numpy SIDE_MODULE now that the main instance exists.
    // This must happen BEFORE __wasm_call_ctors so the dlopen shim can find it.
    //
    // memory_base is derived from the module's dylink.0 mem_size via malloc on
    // the main instance. table_base is the current table size before growing.
    let (handle, _next_mem, _next_tbl) = match pre_load_side_module(
        &engine,
        &mut store,
        &instance,
        &numpy_so_bytes,
        NUMPY_CORE_SO,
    ) {
        Ok(r) => r,
        Err(e) => return format!("SIDE_MODULE LOAD FAILED for {NUMPY_CORE_SO}: {e}"),
    };

    let idx = store
        .data_mut()
        .side_modules
        .insert(NUMPY_CORE_SO.to_owned(), handle);
    eprintln!("[numpy_probe] numpy SIDE_MODULE pre-loaded, idx={idx} (dso_ptr mapped by _dlopen_js at runtime)");

    // Boot CPython.
    if let Some(func) = instance.get_func(&mut store, "__wasm_call_ctors") {
        eprintln!("[numpy_probe] calling __wasm_call_ctors...");
        match func.call(&mut store, &[], &mut []) {
            Ok(_) => eprintln!("[numpy_probe] __wasm_call_ctors OK"),
            Err(e) => {
                return format!("CTORS FAILED: {e}");
            }
        }
    }

    run_numpy_phase(&instance, &mut store, &mech_log, &noop_log)
}

/// Python code to run. Writes output to /tmp/pyout.txt via file I/O.
///
/// Uses a try/except so any ImportError or other exception gets written to the
/// file instead of trapping silently.
const NUMPY_CODE: &[u8] = b"import traceback\ntry:\n    import numpy as np\n    ver=np.__version__\n    arange_sum=int(np.arange(10).sum())\n    mean=float(np.array([1.,2.,3.]).mean())\n    f=open('/tmp/pyout.txt','w')\n    f.write('numpy_version '+ver+'\\n')\n    f.write('arange_sum '+str(arange_sum)+'\\n')\n    f.write('mean '+str(mean)+'\\n')\n    f.close()\nexcept Exception:\n    f=open('/tmp/pyout.txt','w')\n    f.write(traceback.format_exc())\n    f.close()\n\0";

const PYOUT_PATH: &str = "/tmp/pyout.txt";

fn alloc_cstr(store: &mut Store<EmbedderState>, s: &[u8]) -> std::result::Result<u32, String> {
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
            "alloc_cstr: [{base:#x}..{:#x}) exceeds {mem_len:#x}",
            base + s.len()
        ));
    }
    mem.data_mut(&mut *store)[base..base + s.len()].copy_from_slice(s);
    Ok(base as u32)
}

fn run_numpy_phase(
    instance: &wasmtime::Instance,
    store: &mut Store<EmbedderState>,
    mech_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::MechCallLog>,
    noop_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::NoopCallLog>,
) -> String {
    store.data_mut().wasi_stdout.clear();

    let main_fn = match instance.get_func(&mut *store, "__main_argc_argv") {
        Some(f) => f,
        None => return "BLOCKED: __main_argc_argv not exported".to_owned(),
    };

    let arg0_ptr = match alloc_cstr(store, b"python\0") {
        Ok(p) => p,
        Err(e) => return format!("ARGV ALLOC FAILED: {e}"),
    };
    let arg1_ptr = match alloc_cstr(store, b"-c\0") {
        Ok(p) => p,
        Err(e) => return format!("ARGV ALLOC FAILED: {e}"),
    };
    let arg2_ptr = match alloc_cstr(store, NUMPY_CODE) {
        Ok(p) => p,
        Err(e) => return format!("ARGV ALLOC FAILED: {e}"),
    };
    let argv_ptr = {
        let mem = store.data().pyodide_memory.expect("pyodide_memory set");
        let prev = mem.grow(&mut *store, 1).unwrap();
        let base = (prev as usize) * 65536;
        let data = mem.data_mut(&mut *store);
        data[base..base + 4].copy_from_slice(&arg0_ptr.to_le_bytes());
        data[base + 4..base + 8].copy_from_slice(&arg1_ptr.to_le_bytes());
        data[base + 8..base + 12].copy_from_slice(&arg2_ptr.to_le_bytes());
        data[base + 12..base + 16].copy_from_slice(&0u32.to_le_bytes());
        base as i32
    };

    eprintln!("[numpy_probe P5] calling __main_argc_argv(3, {argv_ptr:#x})...");
    let mut main_ret = [wasmtime::Val::I32(-99)];
    match main_fn.call(
        &mut *store,
        &[wasmtime::Val::I32(3), wasmtime::Val::I32(argv_ptr)],
        &mut main_ret,
    ) {
        Ok(_) => {}
        Err(e) => {
            let pyout = read_pyout(store);
            let fuel = PROBE_FUEL.saturating_sub(store.get_fuel().unwrap_or(0));
            let noop_calls = noop_log.snapshot();
            let mech_tail = mech_log.tail(MECH_TRACE_TAIL);
            let mech_trace = format_mech_tail(&mech_tail);
            return format!(
                "TRAPPED in __main_argc_argv: {e}\n\
                 Fuel consumed: {fuel}\n\
                 C++ throws: {}\n\
                 Noop stubs ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 {PYOUT_PATH}:\n{pyout}",
                store.data().cxa_throw_count,
                noop_calls.len()
            );
        }
    }
    let main_exit = match main_ret[0] {
        wasmtime::Val::I32(v) => v,
        _ => -99,
    };
    eprintln!("[numpy_probe P5] __main_argc_argv returned {main_exit}");
    if main_exit != 0 {
        let pyout = read_pyout(store);
        return format!(
            "__main_argc_argv returned {main_exit} (non-zero = CPython init failure)\n\
             {PYOUT_PATH}:\n{pyout}"
        );
    }

    let run_fn = match instance
        .get_func(&mut *store, "run_main")
        .or_else(|| instance.get_func(&mut *store, "pymain_run_python"))
    {
        Some(f) => f,
        None => return "BLOCKED: neither run_main nor pymain_run_python exported".to_owned(),
    };

    store.data_mut().wasi_stdout.clear();
    eprintln!("[numpy_probe P5] calling run_main()...");
    let mut run_ret = [wasmtime::Val::I32(-99)];
    match run_fn.call(&mut *store, &[], &mut run_ret) {
        Ok(_) => {}
        Err(e) => {
            let pyout = read_pyout(store);
            let fuel = PROBE_FUEL.saturating_sub(store.get_fuel().unwrap_or(0));
            let noop_calls = noop_log.snapshot();
            let mech_tail = mech_log.tail(MECH_TRACE_TAIL);
            let mech_trace = format_mech_tail(&mech_tail);

            // Trap kind (unreachable, OOB, indirect-call-type-mismatch, ...).
            let trap_kind = e
                .downcast_ref::<Trap>()
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| "(no Trap root cause)".to_owned());

            // Full Debug chain (includes WasmBacktrace as context).
            let debug_chain = format!("{e:?}");

            // Frame-by-frame WasmBacktrace: func_index + module_offset + name.
            let frame_lines = e
                .downcast_ref::<WasmBacktrace>()
                .map(|bt| {
                    let frames = bt.frames();
                    let mut s = format!("WasmBacktrace ({} frames):\n", frames.len());
                    for (i, fr) in frames.iter().enumerate() {
                        let offset = fr
                            .module_offset()
                            .map(|o| format!("{o:#x}"))
                            .unwrap_or_else(|| "?".to_owned());
                        let name = fr.func_name().unwrap_or("<unnamed>");
                        s.push_str(&format!(
                            "  [{i:>4}] func_index={} module_offset={offset} {name}\n",
                            fr.func_index()
                        ));
                    }
                    s
                })
                .unwrap_or_else(|| "WasmBacktrace: not attached to error\n".to_owned());

            return format!(
                "TRAPPED in run_main: {e}\n\
                 Trap kind: {trap_kind}\n\
                 Fuel consumed: {fuel}\n\
                 C++ throws: {}\n\
                 Last FS paths: {:?}\n\
                 Noop stubs ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 {frame_lines}\
                 Full debug chain:\n{debug_chain}\n\
                 {PYOUT_PATH}:\n{pyout}",
                store.data().cxa_throw_count,
                store.data().fs_path_log.iter().cloned().collect::<Vec<_>>(),
                noop_calls.len()
            );
        }
    }

    let fuel_consumed = PROBE_FUEL.saturating_sub(store.get_fuel().unwrap_or(0));
    let pyout = read_pyout(store);
    let wasi_out = String::from_utf8_lossy(&store.data().wasi_stdout).into_owned();

    eprintln!("[numpy_probe P5] pyout:\n{pyout}");

    format!(
        "Fuel consumed: {fuel_consumed}\n\
         WASI stdout ({} bytes):\n{wasi_out}\n\
         {PYOUT_PATH} ({} bytes):\n{pyout}",
        store.data().wasi_stdout.len(),
        pyout.len()
    )
}

fn read_pyout(store: &Store<EmbedderState>) -> String {
    let bytes = store
        .data()
        .fs
        .read_file(PYOUT_PATH)
        .map(|b| b.to_vec())
        .unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
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
