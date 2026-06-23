// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Bring-up probe for `import markupsafe` via Emscripten SIDE_MODULE linking.
//!
//! Boot sequence is byte-for-byte identical to `pyodide028_probe` (which boots
//! pure Python correctly), differing only by:
//!
//!   - Mounting markupsafe's 6 files + python313.zip stdlib.
//!   - Pre-loading markupsafe's .so via the side-module loader.
//!   - The `-c` code exercising `markupsafe.escape('<b>')`.
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

use afterburner_wasi::embedder_vm::EmbedderState;
use afterburner_wasi::emscripten_dylink::{
    fill_got_table_slots, parse_got_name_to_slot, wire_got_func_stubs_from_module,
};
use afterburner_wasi::emscripten_fs::mount_zip_into_fs;
use afterburner_wasi::emscripten_invoke::wire_invoke_trampolines;
use afterburner_wasi::emscripten_mechanical::wire_pyodide028_env_stubs;
use afterburner_wasi::emscripten_runtime::{
    JsFfiCallLog, MainModuleLayout, MechCallLog, NoopCallLog, fill_unknown_imports_as_noops,
    wire_env_memory_and_table_in_store, wire_wasi_only,
};
use afterburner_wasi::emscripten_sidemodule::{pre_load_side_module, wire_dlopen_dlsym};
use afterburner_wasi::emscripten_syscall::wire_fs_env_funcs;
use wasmtime::{
    Config, Engine, FuncType, Global, GlobalType, Linker, Module, Mutability, OptLevel, Store, Tag,
    TagType, Val, ValType, WasmBacktraceDetails,
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

/// Raw zip mount path (zipimport bootstrap entry).
const STDLIB_ZIP_MOUNT_PATH: &str = "/lib/python313.zip";

/// Instruction budget. MarkupSafe is tiny; 10T is well above what it needs.
const PROBE_FUEL: u64 = 10_000_000_000_000;

const MECH_TRACE_TAIL: usize = 40;

fn main() {
    let outcome = run_probe();
    println!("\n=== MARKUPSAFE PROBE OUTCOME ===");
    println!("{outcome}");
}

/// Engine config: identical to pyodide028_probe.
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
        .wasm_backtrace_details(WasmBacktraceDetails::Enable);
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

    eprintln!("[markupsafe_probe] parsing GOT symbol map...");
    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, /* table_base */ 1);
    eprintln!(
        "[markupsafe_probe] parsed {} GOT entries",
        name_to_slot.len()
    );
    let layout = MainModuleLayout::from_main_wasm(&wasm_bytes);

    let cfg = exnref_engine_cfg();
    eprintln!("[markupsafe_probe] Engine::new...");
    let engine = match Engine::new(&cfg) {
        Ok(e) => {
            eprintln!("[markupsafe_probe] Engine::new SUCCEEDED");
            e
        }
        Err(e) => return format!("ENGINE FAILED: {e}"),
    };

    eprintln!("[markupsafe_probe] Module::new...");
    let module = match Module::new(&engine, &wasm_bytes) {
        Ok(m) => m,
        Err(e) => return format!("COMPILE FAILED: {e}"),
    };
    let import_count = module.imports().count();
    eprintln!("[markupsafe_probe] COMPILE SUCCEEDED ({import_count} imports)");

    let log = JsFfiCallLog::new();
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

    // sentinel::is_sentinel: (externref) -> i32
    // sentinel::create_sentinel: () -> externref
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
    eprintln!("[markupsafe_probe] wired sentinel stubs (externref types)");

    let mut store = Store::new(&engine, EmbedderState::for_emscripten());
    store
        .set_fuel(PROBE_FUEL)
        .expect("set_fuel on consume_fuel engine");

    let got_globals = match wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, &layout)
    {
        Ok(g) => g,
        Err(e) => return format!("MEMORY/TABLE SETUP FAILED: {e}"),
    };

    // Wire the 2 native-EH exception tags: (i32) -> ().
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
    eprintln!("[markupsafe_probe] wired env.__c_longjmp and env.__cpp_exception as host tags");

    // Auto-fill GOT.func/GOT.mem globals not yet in the linker.
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
    eprintln!("[markupsafe_probe] auto-filled {extra_got_filled} extra GOT globals");

    // Pre-create /tmp so Python's open('/tmp/pyout.txt', 'w') can O_CREAT there.
    store.data_mut().fs.mkdir_p("/tmp");

    match fs::read(PYTHON_STDLIB_ZIP_PATH) {
        Ok(zip_bytes) => {
            store
                .data_mut()
                .fs
                .insert_file(STDLIB_ZIP_MOUNT_PATH, zip_bytes.clone());
            match mount_zip_into_fs(&mut store.data_mut().fs, STDLIB_MOUNT_PREFIX, &zip_bytes) {
                Ok(n) => eprintln!(
                    "[markupsafe_probe] mounted {n} stdlib files at {STDLIB_MOUNT_PREFIX}"
                ),
                Err(e) => eprintln!("[markupsafe_probe] WARN: stdlib mount error: {e}"),
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

    // Use no-ops (not traps) for remaining unknown imports.
    let auto_filled =
        fill_unknown_imports_as_noops(&mut store, &mut linker, &module, noop_log.clone());
    eprintln!(
        "[markupsafe_probe] {} imports auto-filled as no-op stubs",
        auto_filled.len()
    );

    eprintln!("[markupsafe_probe] instantiating...");
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
    eprintln!("[markupsafe_probe] instantiation succeeded");

    // Store main instance for on-demand _dlopen_js side module loading.
    store.data_mut().main_instance = Some(instance);

    let fuel_after_inst = store.get_fuel().unwrap_or(0);
    eprintln!(
        "[markupsafe_probe] fuel consumed by instantiation: {}",
        PROBE_FUEL.saturating_sub(fuel_after_inst)
    );

    eprintln!("[markupsafe_probe] resolving GOT entries...");
    match fill_got_table_slots(
        &mut store,
        &linker,
        &instance,
        &got_globals,
        &name_to_slot,
        &module,
        layout.host_got_base(),
    ) {
        Ok(r) => eprintln!(
            "[markupsafe_probe] GOT: {} elem, {} export, {} stub, {} mem",
            r.funcs_from_elem, r.funcs_from_export, r.funcs_stubbed, r.mem_resolved
        ),
        Err(e) => return format!("GOT RESOLUTION FAILED: {e}"),
    }

    if let Some(func) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        eprintln!("[markupsafe_probe] calling __wasm_apply_data_relocs...");
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("RELOC FAILED: {e}");
        }
        eprintln!("[markupsafe_probe] __wasm_apply_data_relocs OK");
    }

    // Pre-load the markupsafe SIDE_MODULE before __wasm_call_ctors so the
    // dlopen shim can find it when CPython imports the extension.
    let (handle, _next_mem, _next_tbl) = match pre_load_side_module(
        &engine,
        &mut store,
        &instance,
        &[],
        &so_bytes,
        MARKUPSAFE_SO,
    ) {
        Ok(r) => r,
        Err(e) => return format!("SIDE_MODULE LOAD FAILED for {MARKUPSAFE_SO}: {e}"),
    };

    let idx = store
        .data_mut()
        .side_modules
        .insert(MARKUPSAFE_SO.to_owned(), handle);
    eprintln!("[markupsafe_probe] markupsafe SIDE_MODULE pre-loaded, idx={idx}");

    let ctors_summary: String;
    if let Some(func) = instance.get_func(&mut store, "__wasm_call_ctors") {
        eprintln!("[markupsafe_probe] calling __wasm_call_ctors (CPython 3.13 static init)...");
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
                eprintln!("[markupsafe_probe] {ctors_summary}");
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
                let mech_trace = format_mech_tail(&mech_tail);

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
                     FS path log ({} entries):\n{}\n\
                     WASI stdout ({} bytes): {wasi_text:?}\n\
                     Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                     Noop stubs called ({} unique): {noop_calls:?}\n\
                     Finding: {finding}",
                    log.total_calls(),
                    fs_paths.len(),
                    fs_paths
                        .iter()
                        .enumerate()
                        .map(|(i, p)| format!("  [{i}] {p}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
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
/// Runs the full markupsafe test: import markupsafe, write escape result to
/// `/tmp/pyout.txt`. NUL-terminated.
const PYTHON_CODE: &[u8] =
    b"import markupsafe\nopen('/tmp/pyout.txt','w').write('escape '+str(markupsafe.escape('<b>'))+'\\n')\n\0";

/// Guest path where Python writes its output.
const PYOUT_PATH: &str = "/tmp/pyout.txt";

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

/// Boot sequence identical to pyodide028_probe::run_python_phase.
///
/// 1. `probe_direct_write` (diagnostic, clears wasi_stdout).
/// 2. `__main_argc_argv(3, argv_ptr)` - Py_Initialize with `-c CODE`.
/// 3. `run_main()` or `pymain_run_python()` - execute the -c code.
/// 4. Read `/tmp/pyout.txt` from MEMFS.
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
        "[markupsafe_probe P5] exports: __main_argc_argv={has_main} run_main={has_run_main} \
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
        "[markupsafe_probe P5] argv: arg0={arg0_ptr:#x}('python') arg1={arg1_ptr:#x}('-c') \
         arg2={arg2_ptr:#x}(CODE) argv_table={argv_ptr:#x}"
    );

    // Step 1: __main_argc_argv(argc=3, argv=argv_ptr).
    store.data_mut().wasi_stdout.clear();
    eprintln!("[markupsafe_probe P5] calling __main_argc_argv(3, {argv_ptr:#x})...");
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
                "[markupsafe_probe P5] wasi_stdout after __main_argc_argv ({} bytes): {:?}",
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
    eprintln!("[markupsafe_probe P5] __main_argc_argv returned {main_exitcode}");

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
    eprintln!("[markupsafe_probe P5] calling {run_entry_name}()...");

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
            eprintln!("[markupsafe_probe P5] {run_entry_name} exitcode={exitcode}");
            eprintln!(
                "[markupsafe_probe P5] wasi_stdout ({} bytes):\n{wasi_text}",
                wasi_out.len()
            );
            let pyout_bytes = store
                .data()
                .fs
                .read_file(PYOUT_PATH)
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let pyout_text = String::from_utf8_lossy(&pyout_bytes).into_owned();
            eprintln!(
                "[markupsafe_probe P5] {PYOUT_PATH} ({} bytes):\n{pyout_text}",
                pyout_bytes.len()
            );
            let milestone = if pyout_text.contains("escape") && pyout_text.contains("&lt;b&gt;") {
                "MILESTONE MET: markupsafe imported and escape('<b>') -> '&lt;b&gt;'"
            } else if !pyout_bytes.is_empty() {
                "PARTIAL: /tmp/pyout.txt has content but escape result missing"
            } else if !wasi_text.is_empty() {
                "PARTIAL: output in wasi_stdout but not in /tmp/pyout.txt"
            } else {
                "NO OUTPUT: run_main returned but /tmp/pyout.txt is absent or empty"
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
                 {PYOUT_PATH} ({} bytes):\n{pyout_text}\n\
                 {milestone}",
                log.total_calls(),
                noop_calls.len(),
                wasi_out.len(),
                pyout_bytes.len()
            )
        }
        Err(e) => {
            let finding = classify_python_error(&format!("{e}"), log.total_calls());
            let throw_count = store.data().cxa_throw_count;
            let fs_paths: Vec<String> = store.data().fs_path_log.iter().cloned().collect();
            let pyout_bytes = store
                .data()
                .fs
                .read_file(PYOUT_PATH)
                .map(|b| b.to_vec())
                .unwrap_or_default();
            let pyout_text = String::from_utf8_lossy(&pyout_bytes).into_owned();
            let trap_kind = e
                .downcast_ref::<wasmtime::Trap>()
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| "(not a Trap)".to_owned());
            format!(
                "{ctors_summary}\n\
                 --- phase 5: __main_argc_argv + {run_entry_name} ---\n\
                 exports: __main_argc_argv={has_main} run_main={has_run_main} \
                 pymain_run_python={has_pymain}\n\
                 __main_argc_argv exitcode: {main_exitcode}\n\
                 TRAPPED in {run_entry_name}: {e}\n\
                 Trap kind: {trap_kind}\n\
                 Fuel consumed: {total_fuel}\n\
                 JS-FFI calls: {}\n\
                 C++ throws: {throw_count}\n\
                 FS path log ({} entries):\n{}\n\
                 Noop stubs called ({} unique): {noop_calls:?}\n\
                 Last {MECH_TRACE_TAIL} mech calls:\n{mech_trace}\
                 WASI stdout ({} bytes):\n{wasi_text}\n\
                 {PYOUT_PATH} ({} bytes):\n{pyout_text}\n\
                 Finding: {finding}",
                log.total_calls(),
                fs_paths.len(),
                fs_paths
                    .iter()
                    .enumerate()
                    .map(|(i, p)| format!("  [{i}] {p}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                noop_calls.len(),
                wasi_out.len(),
                pyout_bytes.len()
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
