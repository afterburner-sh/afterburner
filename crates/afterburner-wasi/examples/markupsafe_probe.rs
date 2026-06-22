// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Bring-up probe for `import markupsafe` via Emscripten SIDE_MODULE linking.
//!
//! Validates the general side-module loader against a minimal C extension
//! (~2.5 KB .so) before testing larger packages. MarkupSafe's
//! `_speedups.cpython-313-wasm32-emscripten.so` is the smallest available
//! Pyodide compiled extension and isolates loader correctness from package
//! size or feature complexity.
//!
//! ## Prerequisites (same as pyodide028_probe)
//!
//! - `/tmp/pyodide-exnref.wasm` - Pyodide 0.28.3 translated to exnref EH.
//! - `/tmp/python_stdlib.zip` - Python 3.13 stdlib zip.
//! - `/tmp/markupsafe_check.whl` - MarkupSafe Pyodide wheel.
//!
//! ## Expected output in /tmp/pyout.txt on success
//!
//!   markupsafe_version 3.0.2
//!   escape_result &lt;b&gt;
//!
//! ## Usage
//!
//!   cargo run -p afterburner-wasi --example markupsafe_probe

use std::fs;
use std::num::NonZeroUsize;

use afterburner_wasi::embedder_vm::EmbedderState;
use afterburner_wasi::emscripten_dylink::{
    GotGlobalMap, fill_got_table_slots, parse_got_name_to_slot, wire_got_func_stubs_from_module,
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
const MARKUPSAFE_WHEEL_PATH: &str = "/tmp/markupsafe_check.whl";

/// The .so that CPython dlopen()s to run `import markupsafe._speedups`.
const MARKUPSAFE_SO: &str = "markupsafe/_speedups.cpython-313-wasm32-emscripten.so";

/// Guest site-packages prefix where .py and .so files are mounted.
const SITE_PACKAGES: &str = "/lib/python3.13/site-packages";

/// stdlib prefix inside python_stdlib.zip
const STDLIB_MOUNT_PREFIX: &str = "/lib/python3.13";
const STDLIB_ZIP_MOUNT_PATH: &str = "/lib/python313.zip";

/// Instruction budget. MarkupSafe is tiny; 2T is well above what it needs.
/// Keep the same ceiling as the numpy probe for comparability.
const PROBE_FUEL: u64 = 10_000_000_000_000;

const MECH_TRACE_TAIL: usize = 40;

fn main() {
    let outcome = run_probe();
    println!("\n=== MARKUPSAFE PROBE OUTCOME ===");
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
/// Skips .dist-info directory entries. Returns the count of files mounted.
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
    eprintln!(
        "[markupsafe_probe] loaded pyodide ({} bytes)",
        wasm_bytes.len()
    );

    let wheel_bytes = match fs::read(MARKUPSAFE_WHEEL_PATH) {
        Ok(b) => b,
        Err(e) => return format!("LOAD FAILED: cannot read {MARKUPSAFE_WHEEL_PATH}: {e}"),
    };
    eprintln!(
        "[markupsafe_probe] loaded markupsafe wheel ({} bytes)",
        wheel_bytes.len()
    );

    // Extract the C extension .so from the wheel.
    let so_bytes = match extract_from_zip(&wheel_bytes, MARKUPSAFE_SO) {
        Some(b) => b,
        None => {
            return format!(
                "LOAD FAILED: cannot extract {MARKUPSAFE_SO} from {MARKUPSAFE_WHEEL_PATH}"
            );
        }
    };
    eprintln!(
        "[markupsafe_probe] extracted {MARKUPSAFE_SO} ({} bytes)",
        so_bytes.len()
    );

    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, 1);
    eprintln!(
        "[markupsafe_probe] parsed {} GOT entries",
        name_to_slot.len()
    );

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
        "[markupsafe_probe] compiled pyodide ({} imports)",
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
                Ok(n) => eprintln!("[markupsafe_probe] mounted {n} stdlib files"),
                Err(e) => eprintln!("[markupsafe_probe] WARN: stdlib mount: {e}"),
            }
        }
        Err(e) => eprintln!("[markupsafe_probe] WARN: stdlib not available: {e}"),
    }

    // Mount markupsafe .py and .so from the wheel into MEMFS site-packages.
    let ms_files = mount_wheel_into_fs(&mut store.data_mut().fs, &wheel_bytes, SITE_PACKAGES);
    eprintln!("[markupsafe_probe] mounted {ms_files} markupsafe files at {SITE_PACKAGES}");

    match wire_got_func_stubs_from_module(&mut store, &mut linker, &module) {
        Ok(n) => eprintln!("[markupsafe_probe] wired {n} GOT.func stubs"),
        Err(e) => return format!("GOT STUB WIRING FAILED: {e}"),
    }

    // Wire _dlopen_js / _dlsym_js before auto-filling noops so that Python's
    // dlopen dispatch reaches the SideModuleRegistry rather than returning 0.
    if let Err(e) = wire_dlopen_dlsym(&mut linker) {
        return format!("DLOPEN WIRING FAILED: {e}");
    }

    let auto_filled =
        fill_unknown_imports_as_noops(&mut store, &mut linker, &module, noop_log.clone());
    eprintln!(
        "[markupsafe_probe] {} imports auto-filled",
        auto_filled.len()
    );

    eprintln!("[markupsafe_probe] instantiating...");
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            return format!("INSTANTIATION FAILED: {e}");
        }
    };
    eprintln!("[markupsafe_probe] instantiated");

    match fill_got_table_slots(
        &mut store,
        &linker,
        &instance,
        &got_globals,
        &name_to_slot,
        &module,
    ) {
        Ok(r) => eprintln!(
            "[markupsafe_probe] GOT: {} elem, {} export, {} stub, {} mem",
            r.funcs_from_elem, r.funcs_from_export, r.funcs_stubbed, r.mem_resolved
        ),
        Err(e) => return format!("GOT RESOLUTION FAILED: {e}"),
    }

    if let Some(func) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("RELOC FAILED: {e}");
        }
        eprintln!("[markupsafe_probe] __wasm_apply_data_relocs OK");
    }

    // Pre-load the markupsafe SIDE_MODULE before __wasm_call_ctors so the
    // dlopen shim can find it when CPython imports the extension.
    let (handle, _next_mem, _next_tbl) =
        match pre_load_side_module(&engine, &mut store, &instance, &so_bytes, MARKUPSAFE_SO) {
            Ok(r) => r,
            Err(e) => return format!("SIDE_MODULE LOAD FAILED for {MARKUPSAFE_SO}: {e}"),
        };

    let handle_int = store
        .data_mut()
        .side_modules
        .insert(MARKUPSAFE_SO.to_owned(), handle);
    eprintln!("[markupsafe_probe] markupsafe SIDE_MODULE pre-loaded, handle={handle_int}");

    // Boot CPython.
    if let Some(func) = instance.get_func(&mut store, "__wasm_call_ctors") {
        eprintln!("[markupsafe_probe] calling __wasm_call_ctors...");
        match func.call(&mut store, &[], &mut []) {
            Ok(_) => eprintln!("[markupsafe_probe] __wasm_call_ctors OK"),
            Err(e) => {
                let diag = memory_diag(&mut store, Some(&got_globals));
                return format!("CTORS FAILED: {e}\n{diag}");
            }
        }
    }

    run_python_phase(&instance, &mut store, &mech_log, &noop_log, &got_globals)
}

/// Python code that exercises markupsafe and writes output to /tmp/pyout.txt.
///
/// Uses try/except so any ImportError or exception is captured in the file
/// rather than trapping silently.
const PYTHON_CODE: &[u8] = b"import traceback\ntry:\n    import markupsafe\n    ver=markupsafe.__version__\n    escaped=str(markupsafe.escape('<b>'))\n    f=open('/tmp/pyout.txt','w')\n    f.write('markupsafe_version '+ver+'\\n')\n    f.write('escape_result '+escaped+'\\n')\n    f.close()\nexcept Exception:\n    f=open('/tmp/pyout.txt','w')\n    f.write(traceback.format_exc())\n    f.close()\n\0";

const PYOUT_PATH: &str = "/tmp/pyout.txt";

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
            "alloc_cstr: [{base:#x}..{:#x}) exceeds {mem_len:#x}",
            base + s.len()
        ));
    }
    mem.data_mut(&mut *store)[base..base + s.len()].copy_from_slice(s);
    Ok(base as u32)
}

fn run_python_phase(
    instance: &wasmtime::Instance,
    store: &mut Store<EmbedderState>,
    mech_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::MechCallLog>,
    noop_log: &std::sync::Arc<afterburner_wasi::emscripten_runtime::NoopCallLog>,
    got_globals: &GotGlobalMap,
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
    let arg2_ptr = match alloc_cstr(store, PYTHON_CODE) {
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

    eprintln!("[markupsafe_probe] calling __main_argc_argv(3, {argv_ptr:#x})...");
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
            let diag = memory_diag(store, Some(got_globals));
            return format!(
                "TRAPPED in __main_argc_argv: {e}\n\
                 Fuel consumed: {fuel}\n\
                 C++ throws: {}\n\
                 Noop stubs ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 {diag}\
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
    eprintln!("[markupsafe_probe] __main_argc_argv returned {main_exit}");
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
    eprintln!("[markupsafe_probe] calling run_main()...");
    let mut run_ret = [wasmtime::Val::I32(-99)];
    match run_fn.call(&mut *store, &[], &mut run_ret) {
        Ok(_) => {}
        Err(e) => {
            let pyout = read_pyout(store);
            let fuel = PROBE_FUEL.saturating_sub(store.get_fuel().unwrap_or(0));
            let noop_calls = noop_log.snapshot();
            let mech_tail = mech_log.tail(MECH_TRACE_TAIL);
            let mech_trace = format_mech_tail(&mech_tail);

            let trap_kind = e
                .downcast_ref::<Trap>()
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| "(no Trap root cause)".to_owned());

            let debug_chain = format!("{e:?}");

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

            let diag = memory_diag(store, Some(got_globals));

            return format!(
                "TRAPPED in run_main: {e}\n\
                 Trap kind: {trap_kind}\n\
                 Fuel consumed: {fuel}\n\
                 C++ throws: {}\n\
                 Last FS paths: {:?}\n\
                 Noop stubs ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 {diag}\
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

    eprintln!("[markupsafe_probe] pyout:\n{pyout}");

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

// --- memory diagnostic helpers ---

/// Side-module data region: malloc'd by pre_load_side_module for markupsafe.
/// memory_base=0x46aeb0, size=0x7e544.
const MEMORY_BASE: u32 = 0x0046_aeb0;
const MEMORY_BASE_END: u32 = MEMORY_BASE + 0x7e544;

/// Classify a linear-memory address into a human-readable region.
fn classify_addr(addr: u32) -> &'static str {
    if addr < MEMORY_BASE {
        "main-module static/heap"
    } else if addr < MEMORY_BASE_END {
        "side-module data region"
    } else {
        "CPython heap"
    }
}

/// Hex + printable-ASCII dump of `data[start..end]`, 16 bytes per row.
fn hexdump(data: &[u8], base_addr: usize) -> String {
    let mut out = String::new();
    for (row_off, chunk) in data.chunks(16).enumerate() {
        let row_addr = base_addr + row_off * 16;
        let hex: String = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("  {row_addr:#010x}  {hex:<47}  {ascii}\n"));
    }
    out
}

/// Scan ALL of linear memory for every 4-byte aligned occurrence of `needle`
/// (little-endian). Returns `(address, region)` for every hit.
/// Also returns a 64-byte hexdump centred on the first hit.
fn scan_u32_all(store: &Store<EmbedderState>, needle: u32) -> (Vec<(u32, &'static str)>, String) {
    let Some(mem) = store.data().pyodide_memory else {
        return (vec![], "pyodide_memory not set\n".to_owned());
    };
    let data = mem.data(store);
    let target = needle.to_le_bytes();
    let mut hits: Vec<(u32, &'static str)> = Vec::new();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        if data[i..i + 4] == target {
            hits.push((i as u32, classify_addr(i as u32)));
        }
        i += 4;
    }
    let first_dump = if let Some(&(first_addr, _)) = hits.first() {
        let a = first_addr as usize;
        let dump_start = a.saturating_sub(32);
        let dump_end = (a + 32).min(data.len());
        format!(
            "  first hit {first_addr:#010x}: 64-byte window [{dump_start:#010x}..{dump_end:#010x}):\n{}",
            hexdump(&data[dump_start..dump_end], dump_start)
        )
    } else {
        String::new()
    };
    (hits, first_dump)
}

/// Read 4 bytes at `addr` from linear memory and return them as hex.
fn read_u32_at(store: &Store<EmbedderState>, addr: u32) -> String {
    let Some(mem) = store.data().pyodide_memory else {
        return "pyodide_memory not set".to_owned();
    };
    let data = mem.data(store);
    let a = addr as usize;
    if a + 4 > data.len() {
        return format!("addr {addr:#010x} out of range (mem len={:#x})", data.len());
    }
    let val = u32::from_le_bytes(data[a..a + 4].try_into().unwrap());
    format!("{val:#010x}")
}

/// Scan ALL of linear memory for byte-exact occurrences of `needle` (any alignment).
fn scan_bytes(store: &Store<EmbedderState>, needle: &[u8]) -> Vec<u32> {
    let Some(mem) = store.data().pyodide_memory else {
        return vec![];
    };
    let data = mem.data(store);
    let mut hits = Vec::new();
    for i in 0..data.len().saturating_sub(needle.len() - 1) {
        if data[i..i + needle.len()] == *needle {
            hits.push(i as u32);
        }
    }
    hits
}

/// CPython 3.13 wasm32 PyTypeObject field name for a given byte offset within
/// the object (ob_refcnt at +0, ob_type at +4).
///
/// Offsets are for wasm32 (4-byte pointers/Py_ssize_t). Source: cpython/Include/cpython/object.h.
fn py_typeobject_slot_name(offset: u32) -> &'static str {
    match offset {
        0 => "ob_refcnt",
        4 => "ob_type",
        8 => "ob_size",
        12 => "tp_name",
        16 => "tp_basicsize",
        20 => "tp_itemsize",
        24 => "tp_dealloc",
        28 => "tp_vectorcall_offset",
        32 => "tp_getattr",
        36 => "tp_setattr",
        40 => "tp_as_async",
        44 => "tp_repr",
        48 => "tp_as_number",
        52 => "tp_as_sequence",
        56 => "tp_as_mapping",
        60 => "tp_hash",
        64 => "tp_call",
        68 => "tp_str",
        72 => "tp_getattro",
        76 => "tp_setattro",
        80 => "tp_as_buffer",
        84 => "tp_flags",
        88 => "tp_doc",
        92 => "tp_traverse",
        96 => "tp_clear",
        100 => "tp_richcompare",
        104 => "tp_weaklistoffset",
        108 => "tp_iter",
        112 => "tp_iternext",
        116 => "tp_methods",
        120 => "tp_members",
        124 => "tp_getset",
        128 => "tp_base",
        132 => "tp_dict",
        136 => "tp_descr_get",
        140 => "tp_descr_set",
        144 => "tp_dictoffset",
        148 => "tp_init",
        152 => "tp_alloc",
        156 => "tp_new",
        160 => "tp_free",
        164 => "tp_is_gc",
        168 => "tp_bases",
        172 => "tp_mro",
        176 => "tp_cache",
        180 => "tp_subclasses",
        184 => "tp_weaklist",
        188 => "tp_del",
        192 => "tp_version_tag",
        196 => "tp_finalize",
        200 => "tp_vectorcall",
        _ => "<unknown>",
    }
}

/// For a hit address holding the bad value, snap backward in 4-byte steps to
/// find the nearest CPython object boundary (where ob_refcnt looks plausible
/// and ob_type resolves to a readable tp_name). Returns a formatted string.
///
/// Heuristic: scan up to 512 bytes back in 4-byte steps looking for a slot
/// where the u32 at +0 is 1..=10000 (plausible refcnt) and the u32 at +4
/// points somewhere in linear memory that itself has a printable C string at
/// +12 (tp_name of the ob_type). Reports the best match found.
fn identify_object_at_hit(store: &Store<EmbedderState>, hit_addr: u32) -> String {
    let Some(mem) = store.data().pyodide_memory else {
        return "  pyodide_memory not set\n".to_owned();
    };
    let data = mem.data(store);
    let mem_len = data.len();

    // Snap hit_addr down to 4-byte alignment.
    let hit_aligned = hit_addr & !3;

    // Scan backward up to 512 bytes for a plausible ob_type.
    let scan_start = hit_aligned.saturating_sub(512);
    let mut best_obj: Option<(u32, u32, String, u32)> = None; // (obj_addr, ob_type, tp_name, offset)

    let mut candidate = scan_start;
    while candidate <= hit_aligned {
        let c = candidate as usize;
        if c + 8 > mem_len {
            candidate += 4;
            continue;
        }
        let refcnt = u32::from_le_bytes(data[c..c + 4].try_into().unwrap());
        // Plausible refcnt: 1..=1_000_000
        if refcnt == 0 || refcnt > 1_000_000 {
            candidate += 4;
            continue;
        }
        let ob_type = u32::from_le_bytes(data[c + 4..c + 8].try_into().unwrap());
        if ob_type == 0 || (ob_type as usize) + 16 > mem_len {
            candidate += 4;
            continue;
        }
        // Read tp_name pointer at ob_type+12.
        let tp = ob_type as usize;
        if tp + 16 > mem_len {
            candidate += 4;
            continue;
        }
        let tp_name_ptr = u32::from_le_bytes(data[tp + 12..tp + 16].try_into().unwrap()) as usize;
        if tp_name_ptr == 0 || tp_name_ptr + 1 > mem_len {
            candidate += 4;
            continue;
        }
        // Read the C string at tp_name_ptr (up to 64 bytes).
        let name_end = (tp_name_ptr + 64).min(mem_len);
        let name_bytes = &data[tp_name_ptr..name_end];
        let nul = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name_slice = &name_bytes[..nul];
        if name_slice.is_empty()
            || !name_slice
                .iter()
                .all(|&b| b.is_ascii_graphic() || b == b' ')
        {
            candidate += 4;
            continue;
        }
        let tp_name = String::from_utf8_lossy(name_slice).into_owned();
        let offset = hit_aligned.saturating_sub(candidate);
        // Prefer the candidate closest to the hit (largest offset that still
        // makes the hit fall within the first 256 bytes of a PyTypeObject).
        if offset <= 256 {
            best_obj = Some((candidate, ob_type, tp_name, offset));
        }
        candidate += 4;
    }

    match best_obj {
        None => format!(
            "  hit {hit_addr:#010x}: no plausible CPython object boundary found in [{scan_start:#010x}..{hit_aligned:#010x}]\n"
        ),
        Some((obj_addr, ob_type, ref tp_name, offset)) => {
            let slot = py_typeobject_slot_name(offset);
            let dump_end = ((obj_addr as usize) + 96).min(mem_len);
            let dump = hexdump(&data[obj_addr as usize..dump_end], obj_addr as usize);
            format!(
                "  hit {hit_addr:#010x}: object at {obj_addr:#010x} ob_type={ob_type:#010x} tp_name=\"{tp_name}\"\n\
                     field offset +{offset} ({offset:#04x}) = {slot}\n\
                     object dump (96 bytes from {obj_addr:#010x}):\n{dump}"
            )
        }
    }
}

/// Scan all GOT globals in `got_globals` for the value `needle` (as i32).
/// Returns a formatted report.
fn scan_got_globals_for_needle(
    store: &mut Store<EmbedderState>,
    got_globals: &GotGlobalMap,
    needle: u32,
) -> String {
    let needle_i32 = needle as i32;
    let mut hits: Vec<(String, i32)> = Vec::new();
    for (key, &g) in got_globals {
        if let Val::I32(v) = g.get(&mut *store)
            && v == needle_i32
        {
            hits.push((key.clone(), v));
        }
    }
    if hits.is_empty() {
        format!(
            "GOT global scan for {needle:#010x}: no GOT.func or GOT.mem global holds this value\n"
        )
    } else {
        let mut s = format!(
            "GOT global scan for {needle:#010x} ({} hits - SMOKING GUN candidates):\n",
            hits.len()
        );
        for (key, v) in &hits {
            s.push_str(&format!("  {key} = {v:#010x}\n"));
        }
        s
    }
}

/// Dump `window` bytes centred on `addr` from linear memory. Returns hex+ASCII.
fn dump_bytes_around(store: &Store<EmbedderState>, addr: u32, window: usize) -> String {
    let Some(mem) = store.data().pyodide_memory else {
        return "  pyodide_memory not set\n".to_owned();
    };
    let data = mem.data(store);
    let mem_len = data.len();
    let half = window / 2;
    let start = (addr as usize).saturating_sub(half);
    let end = ((addr as usize) + half).min(mem_len);
    if start >= mem_len {
        return format!("  addr {addr:#010x} out of range (mem len={mem_len:#x})\n");
    }
    format!(
        "  [{start:#010x}..{end:#010x}) around {addr:#010x}:\n{}",
        hexdump(&data[start..end], start)
    )
}

/// Run all diagnostics and format a single report block.
///
/// `got_globals` is `Some` when available (at trap sites that have the map in scope).
/// When `None`, the GOT global scan is skipped with a note.
fn memory_diag(store: &mut Store<EmbedderState>, got_globals: Option<&GotGlobalMap>) -> String {
    const NEEDLE: u32 = 0x7472_6176;

    // --- Section 1: raw scan for all occurrences of the needle ---
    let (hits, first_dump) = scan_u32_all(&*store, NEEDLE);
    let scan_report = if hits.is_empty() {
        format!("scan for {NEEDLE:#010x}: no occurrences in linear memory\n")
    } else {
        let mut s = format!("scan for {NEEDLE:#010x} ({} hits):\n", hits.len());
        for (addr, region) in &hits {
            s.push_str(&format!("  [{addr:#010x}] {region}\n"));
        }
        s.push_str(&first_dump);
        s
    };

    // --- Section 2: identify the object at each hit (up to 5 unique objects) ---
    // Deduplicate by snapping each hit back to its inferred object boundary so
    // that 22 hits on the same type do not produce 22 identical dumps.
    let obj_report = if hits.is_empty() {
        String::new()
    } else {
        let mut s = "object identification (first 5 unique CPython heap hits):\n".to_owned();
        let mut seen_objs: Vec<u32> = Vec::new();
        let heap_hits: Vec<u32> = hits
            .iter()
            .filter(|(_, r)| *r == "CPython heap")
            .map(|(a, _)| *a)
            .collect();
        for hit_addr in &heap_hits {
            if seen_objs.len() >= 5 {
                break;
            }
            // Snap to infer object start (heuristic: back up to 512 bytes).
            let aligned = hit_addr & !3;
            let start = aligned.saturating_sub(512);
            // Try to find the object start by the same heuristic as
            // identify_object_at_hit uses internally; we just check if this
            // hit already belongs to an already-reported object.
            if seen_objs
                .iter()
                .any(|&o| o <= *hit_addr && *hit_addr < o.saturating_add(512))
            {
                continue;
            }
            seen_objs.push(start);
            s.push_str(&identify_object_at_hit(&*store, *hit_addr));
        }
        s
    };

    // --- Section 3: reloc slot spot-check (pre-existing) ---
    let slot70 = read_u32_at(&*store, MEMORY_BASE + 0x70);
    let slot74 = read_u32_at(&*store, MEMORY_BASE + 0x74);
    let slot_report = format!(
        "memory_base+0x70 ({:#010x}): {slot70}  (expected: {:#010x})\n\
         memory_base+0x74 ({:#010x}): {slot74}  (expected: 0x00001aa8 = table_base 6824)\n",
        MEMORY_BASE + 0x70,
        MEMORY_BASE + 21,
        MEMORY_BASE + 0x74,
    );

    // --- Section 4: GOT global scan ---
    let got_report = match got_globals {
        Some(g) => scan_got_globals_for_needle(store, g, NEEDLE),
        None => format!(
            "GOT global scan for {NEEDLE:#010x}: got_globals not available at this trap site\n"
        ),
    };

    // --- Section 5: "traverse" string occurrences + 48-byte dump around 0x4b8411 ---
    // First 4 bytes of "traverse" are 74 72 61 76 = 0x74726176 = NEEDLE.
    // A pointer to this string equals NEEDLE, explaining the 22 bad slots.
    let trav_hits = scan_bytes(&*store, b"traverse");
    let trav_report = if trav_hits.is_empty() {
        "scan for \"traverse\": no occurrences in linear memory\n".to_owned()
    } else {
        let mut s = format!("scan for \"traverse\" ({} hits):\n", trav_hits.len());
        for addr in &trav_hits {
            s.push_str(&format!("  [{addr:#010x}] {}\n", classify_addr(*addr)));
        }
        s
    };

    // Dump 48 bytes around the known side-module "traverse" string at 0x4b8411.
    // This address was identified in the previous scan as the side-module data
    // region occurrence of "traverse". Dump clarifies what structure it belongs to.
    const TRAV_ADDR: u32 = 0x004b_8411;
    let trav_dump_report = format!(
        "48-byte dump around side-module \"traverse\" string at {TRAV_ADDR:#010x}:\n{}",
        dump_bytes_around(&*store, TRAV_ADDR, 48)
    );

    format!("{scan_report}{obj_report}{slot_report}{got_report}{trav_report}{trav_dump_report}")
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
