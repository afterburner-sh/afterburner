// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Bring-up probe for `import pandas` via Emscripten SIDE_MODULE linking.
//!
//! Boot sequence is identical to `numpy_import_probe` (which imports numpy
//! correctly). The differences:
//!
//!   - Mounts numpy + pandas + python-dateutil + pytz + six wheels into
//!     site-packages (pandas' hard dependencies).
//!   - Pre-loads numpy's core `.so` (CPython expects it from the first dlopen);
//!     every other `.so` (numpy's and pandas' 44 `pandas/_libs/*.so`) loads
//!     on-demand through the FS dlopen path in `emscripten_sidemodule`.
//!   - The `-c` code exercises `pandas.DataFrame({'a':[1,2,3]}).sum()`.
//!
//! ## Prerequisites
//!
//! - `/tmp/pyodide-exnref.wasm` - Pyodide 0.28.3 translated to exnref EH.
//! - `/tmp/python_stdlib.zip` - Python 3.13 stdlib zip.
//! - `/tmp/numpy_check.whl`, `/tmp/pandas_check.whl`, `/tmp/dateutil_check.whl`,
//!   `/tmp/pytz_check.whl`, `/tmp/six_check.whl` - Pyodide 0.28.3 wheels.
//!
//! ## Usage
//!
//!   BURN_PROBE_WASM=/tmp/pyodide-exnref.wasm \
//!     cargo run -q -p afterburner-wasi --example pandas_import_probe

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
    JsFfiCallLog, MainModuleLayout, MechCallLog, NoopCallLog, adopt_self_provided_exports,
    fill_unknown_imports_as_noops, module_self_provides_env, wire_env_memory_and_table_in_store,
    wire_wasi_only,
};
use afterburner_wasi::emscripten_sidemodule::{pre_load_side_module, wire_dlopen_dlsym};
use afterburner_wasi::emscripten_syscall::wire_fs_env_funcs;
use wasmtime::{
    Config, Engine, FuncType, Global, GlobalType, Linker, Module, Mutability, OptLevel, Store, Tag,
    TagType, Trap, Val, ValType, WasmBacktrace, WasmBacktraceDetails,
};

const PYODIDE_WASM_PATH: &str = "/tmp/pyodide-exnref.wasm";
const PYTHON_STDLIB_ZIP_PATH: &str = "/tmp/python_stdlib.zip";

/// The wheels mounted into guest site-packages, in dependency order. Each is a
/// `.whl` (a zip of `.py` and `.so` files). All `.so` files land in the in-memory
/// FS and are dlopen'd on demand; only numpy's core `.so` is pre-loaded.
const WHEELS: &[&str] = &[
    "/tmp/numpy_check.whl",
    "/tmp/pandas_check.whl",
    "/tmp/dateutil_check.whl",
    "/tmp/pytz_check.whl",
    "/tmp/six_check.whl",
];

/// Interpreter `X.Y` version (e.g. `3.14`), from `BURN_PYTHON_STDLIB_VER`
/// (default `3.13`, the Pyodide 0.28.x interpreter). All guest mount paths and
/// the side-module soabi tag derive from this, so the probe serves any Pyodide
/// release without a rebuild: CPython 3.14 searches `/lib/python3.14` and loads
/// `.so` files tagged `cpython-314`, where 3.13 used `/lib/python3.13` and
/// `cpython-313`.
fn py_ver() -> String {
    std::env::var("BURN_PYTHON_STDLIB_VER").unwrap_or_else(|_| "3.13".to_owned())
}

/// soabi tag for wheel `.so` files: `cpython-314-wasm32-emscripten` for 3.14.
fn soabi_tag() -> String {
    format!("cpython-{}-wasm32-emscripten", py_ver().replace('.', ""))
}

/// The .so that CPython dlopen()s first to run `import numpy._core._multiarray_umath`.
/// numpy is a pandas hard dependency, so this is pre-loaded exactly as in the
/// numpy probe. Everything else loads on demand.
fn numpy_core_so() -> String {
    format!("numpy/_core/_multiarray_umath.{}.so", soabi_tag())
}

/// Guest site-packages prefix where wheels' `.py` and `.so` files are mounted.
fn site_packages() -> String {
    format!("/lib/python{}/site-packages", py_ver())
}

/// stdlib mount prefix and zip path inside the guest FS.
fn stdlib_mount_prefix() -> String {
    format!("/lib/python{}", py_ver())
}
fn stdlib_zip_mount_path() -> String {
    format!("/lib/python{}.zip", py_ver().replace('.', ""))
}

/// Instruction budget. pandas import is far heavier than numpy (44 `.so` side
/// modules plus a large pure-Python import graph), so the budget is raised.
const PROBE_FUEL: u64 = 100_000_000_000_000;

const MECH_TRACE_TAIL: usize = 40;

fn main() {
    let outcome = run_probe();
    println!("\n=== PANDAS PROBE OUTCOME ===");
    println!("{outcome}");
}

fn exnref_engine_cfg() -> Config {
    let mut cfg = Config::new();
    // BURN_OPT_LEVEL lets a diagnostic run pick the Cranelift optimization level
    // (none / speed / speed_and_size) so a possible optimizer miscompile of the
    // exnref/GC lowering can be bisected. Defaults to Speed (the production level).
    let opt = match std::env::var("BURN_OPT_LEVEL").as_deref() {
        Ok("none") => OptLevel::None,
        Ok("speed_and_size") => OptLevel::SpeedAndSize,
        _ => OptLevel::Speed,
    };
    cfg.cranelift_opt_level(opt)
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
    let wasm_path =
        std::env::var("BURN_PROBE_WASM").unwrap_or_else(|_| PYODIDE_WASM_PATH.to_owned());
    let wasm_bytes = match fs::read(&wasm_path) {
        Ok(b) => b,
        Err(e) => {
            return format!(
                "LOAD FAILED: cannot read {wasm_path}: {e}\n\
                 Produce with: wasm-opt --translate-to-exnref ... pyodide-new.asm.wasm -o {wasm_path}"
            );
        }
    };
    eprintln!(
        "[pandas_probe] loaded pyodide ({} bytes) from {wasm_path}",
        wasm_bytes.len()
    );

    // Version-derived guest paths (BURN_PYTHON_STDLIB_VER; default 3.13).
    let numpy_core = numpy_core_so();
    let site_pkgs = site_packages();
    eprintln!(
        "[pandas_probe] python {} (soabi {}, site-packages {site_pkgs})",
        py_ver(),
        soabi_tag()
    );

    // Wheel set: BURN_WHEELS (comma-separated paths) overrides the default
    // pandas closure, so any package can be probed without a rebuild.
    let wheels_owned: Vec<String> = std::env::var("BURN_WHEELS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_else(|| WHEELS.iter().map(|s| s.to_string()).collect());

    // Read every wheel up front; extract numpy's core .so for pre-load (if any
    // wheel contains it - pure-Python sets won't).
    let mut wheel_blobs: Vec<(String, Vec<u8>)> = Vec::with_capacity(wheels_owned.len());
    let mut numpy_so_bytes: Option<Vec<u8>> = None;
    for wheel in &wheels_owned {
        let bytes = match fs::read(wheel) {
            Ok(b) => b,
            Err(e) => return format!("LOAD FAILED: cannot read {wheel}: {e}"),
        };
        eprintln!(
            "[pandas_probe] loaded wheel {wheel} ({} bytes)",
            bytes.len()
        );
        if numpy_so_bytes.is_none()
            && let Some(so) = extract_from_zip(&bytes, &numpy_core)
        {
            eprintln!("[pandas_probe] extracted {numpy_core} ({} bytes)", so.len());
            numpy_so_bytes = Some(so);
        }
        wheel_blobs.push((wheel.clone(), bytes));
    }

    // Diagnostic: BURN_NUMPYCORE_OVERRIDE=hostfile replaces the pre-loaded numpy
    // core .so bytes with an instrumented build (the core is pre-loaded from the
    // extracted wheel bytes, not the FS, so BURN_FS_OVERRIDE does not reach it).
    if let Ok(path) = std::env::var("BURN_NUMPYCORE_OVERRIDE") {
        match fs::read(path.trim()) {
            Ok(b) => {
                eprintln!(
                    "[pandas_probe] NUMPYCORE OVERRIDE <- {} ({} bytes)",
                    path.trim(),
                    b.len()
                );
                numpy_so_bytes = Some(b);
            }
            Err(e) => eprintln!("[pandas_probe] NUMPYCORE OVERRIDE failed: {e}"),
        }
    }

    let name_to_slot = parse_got_name_to_slot(&wasm_bytes, 1);
    eprintln!("[pandas_probe] parsed {} GOT entries", name_to_slot.len());
    let layout = MainModuleLayout::from_main_wasm(&wasm_bytes);

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
        "[pandas_probe] compiled pyodide ({} imports)",
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

    // Emscripten 5.0.3 (Pyodide 314+) defines and exports its own memory, table,
    // stack pointer, and EH tags. Detect purely by import shape.
    let self_provided = module_self_provides_env(&module);

    let got_globals =
        match wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, &layout, &module) {
            Ok(g) => g,
            Err(e) => return format!("MEMORY/TABLE SETUP FAILED: {e}"),
        };

    // On the 0.28.x host-provided path the host creates the EH tags; on the 314
    // self-providing path the module exports them and they are adopted after
    // instantiation (adopt_self_provided_exports), so skip host tag creation.
    if !self_provided {
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
        // Retain the tags in the store so every side module loaded on-demand by
        // _dlopen_js can share them (mirrors pyodide_runner.rs boot_pyodide_instance).
        store.data_mut().pyodide_cpp_exception_tag = Some(cpp_exception_tag);
        store.data_mut().pyodide_c_longjmp_tag = Some(c_longjmp_tag);
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

    // Create /tmp and mount stdlib. BURN_PYTHON_STDLIB_ZIP overrides the path so
    // a version-specific stdlib (3.14) can be mounted without a rebuild.
    store.data_mut().fs.mkdir_p("/tmp");

    let stdlib_zip_path = std::env::var("BURN_PYTHON_STDLIB_ZIP")
        .unwrap_or_else(|_| PYTHON_STDLIB_ZIP_PATH.to_owned());
    match fs::read(&stdlib_zip_path) {
        Ok(zip_bytes) => {
            store
                .data_mut()
                .fs
                .insert_file(&stdlib_zip_mount_path(), zip_bytes.clone());
            match mount_zip_into_fs(&mut store.data_mut().fs, &stdlib_mount_prefix(), &zip_bytes) {
                Ok(n) => eprintln!("[pandas_probe] mounted {n} stdlib files"),
                Err(e) => eprintln!("[pandas_probe] WARN: stdlib mount: {e}"),
            }
        }
        Err(e) => eprintln!("[pandas_probe] WARN: stdlib not available: {e}"),
    }

    // Mount every wheel's .py and .so into MEMFS site-packages.
    let mut total_mounted = 0usize;
    for (wheel, bytes) in &wheel_blobs {
        let n = mount_wheel_into_fs(&mut store.data_mut().fs, bytes, &site_pkgs);
        eprintln!("[pandas_probe] mounted {n} files from {wheel}");
        total_mounted += n;
    }
    eprintln!("[pandas_probe] mounted {total_mounted} site-packages files at {site_pkgs}");

    // Diagnostic override: BURN_FS_OVERRIDE=guestpath=hostfile[,guestpath=hostfile]
    // replaces an already-mounted guest file with bytes from a host file. Used to
    // swap in an instrumented side-module .so without rebuilding the wheel.
    if let Ok(spec) = std::env::var("BURN_FS_OVERRIDE") {
        for pair in spec.split(',') {
            let Some((guest, host)) = pair.split_once('=') else {
                continue;
            };
            match fs::read(host.trim()) {
                Ok(bytes) => {
                    let n = bytes.len();
                    store.data_mut().fs.insert_file(guest.trim(), bytes);
                    eprintln!(
                        "[pandas_probe] FS OVERRIDE {} <- {} ({n} bytes)",
                        guest.trim(),
                        host.trim()
                    );
                }
                Err(e) => eprintln!("[pandas_probe] FS OVERRIDE failed for {host}: {e}"),
            }
        }
    }

    match wire_got_func_stubs_from_module(&mut store, &mut linker, &module) {
        Ok(n) => eprintln!("[pandas_probe] wired {n} GOT.func stubs"),
        Err(e) => return format!("GOT STUB WIRING FAILED: {e}"),
    }

    // Wire _dlopen_js / _dlsym_js before auto-filling noops so that Python's
    // dlopen dispatch reaches the SideModuleRegistry rather than returning 0.
    if let Err(e) = wire_dlopen_dlsym(&mut linker) {
        return format!("DLOPEN WIRING FAILED: {e}");
    }

    let auto_filled =
        fill_unknown_imports_as_noops(&mut store, &mut linker, &module, noop_log.clone());
    eprintln!("[pandas_probe] {} imports auto-filled", auto_filled.len());

    eprintln!("[pandas_probe] instantiating...");
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            return format!("INSTANTIATION FAILED: {e}");
        }
    };
    eprintln!("[pandas_probe] instantiated");

    // On the 314 self-providing path, adopt the module's exported memory, table,
    // stack pointer, and EH tags into the store BEFORE GOT resolution (which
    // reads the adopted table) and the ctors.
    if self_provided {
        if let Err(e) = adopt_self_provided_exports(&mut store, &instance) {
            return format!("SELF-PROVIDED ADOPT FAILED: {e}");
        }
        eprintln!("[pandas_probe] adopted self-provided memory/table/sp/tags");
    }

    // Store the main instance so _dlopen_js can wire env.* imports for
    // on-demand side modules.
    store.data_mut().main_instance = Some(instance);

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
            "[pandas_probe] GOT: {} elem, {} export, {} stub, {} mem",
            r.funcs_from_elem, r.funcs_from_export, r.funcs_stubbed, r.mem_resolved
        ),
        Err(e) => return format!("GOT RESOLUTION FAILED: {e}"),
    }

    // On the 314 self-providing path the GOT.func globals could not be pre-filled
    // (the table is the module's own, adopted only after instantiation). Resolve
    // every GOT.func import the module declares into a real table slot now, or it
    // calls through slot 0 (null) and traps with IndirectCallToNull.
    if self_provided {
        match afterburner_wasi::emscripten_dylink::resolve_self_provided_got_func(
            &mut store,
            &linker,
            &module,
            &got_globals,
        ) {
            Ok((resolved, skipped)) => {
                eprintln!(
                    "[pandas_probe] self-provided GOT.func: {resolved} resolved, {skipped} skipped"
                )
            }
            Err(e) => return format!("SELF-PROVIDED GOT.func FAILED: {e}"),
        }
    }

    // Initialize the C-stack bookkeeping BEFORE relocs/ctors (see numpy probe).
    if let Some(func) = instance.get_func(&mut store, "emscripten_stack_init") {
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("emscripten_stack_init FAILED: {e}");
        }
        eprintln!("[pandas_probe] emscripten_stack_init OK");
    }

    if let Some(func) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("RELOC FAILED: {e}");
        }
        eprintln!("[pandas_probe] __wasm_apply_data_relocs OK");
    }

    // Pre-load the numpy core SIDE_MODULE before ctors (CPython's import machinery
    // expects it from the first dlopen). All other .so files (numpy's linalg/fft/
    // random and pandas' 44 pandas/_libs/*.so) load on-demand via _dlopen_js.
    // Skipped for pure-Python wheel sets that ship no numpy core .so.
    if let Some(numpy_so_bytes) = numpy_so_bytes.as_ref() {
        let (handle, _next_mem, _next_tbl) = match pre_load_side_module(
            &engine,
            &mut store,
            &instance,
            &[],
            numpy_so_bytes,
            &numpy_core,
        ) {
            Ok(r) => r,
            Err(e) => return format!("SIDE_MODULE LOAD FAILED for {numpy_core}: {e}"),
        };
        let idx = store
            .data_mut()
            .side_modules
            .insert(numpy_core.clone(), handle);
        eprintln!("[pandas_probe] numpy core SIDE_MODULE pre-loaded, idx={idx}");
    } else {
        eprintln!("[pandas_probe] no numpy core .so in wheel set; skipping numpy pre-load");
    }

    // EXPERIMENT (BURN_PRELOAD_RANDOM): pre-load the numpy.random .so chain
    // before ctors, the same way numpy core is pre-loaded, to test whether the
    // numpy.random failure is specific to the on-demand dlopen path.
    if std::env::var("BURN_PRELOAD_RANDOM").is_ok() {
        let tag = soabi_tag();
        let random_sos = [
            format!("numpy/random/bit_generator.{tag}.so"),
            format!("numpy/random/_common.{tag}.so"),
            format!("numpy/random/_mt19937.{tag}.so"),
            format!("numpy/random/_bounded_integers.{tag}.so"),
            format!("numpy/random/mtrand.{tag}.so"),
        ];
        for rel in &random_sos {
            let path = format!("{site_pkgs}/{rel}");
            let so_bytes = match store.data().fs.read_file(&path).map(|b| b.to_vec()) {
                Some(b) => b,
                None => {
                    eprintln!("[preload-random] FS miss for {path}");
                    continue;
                }
            };
            let side_insts = store.data().side_modules.all_instances();
            match pre_load_side_module(&engine, &mut store, &instance, &side_insts, &so_bytes, rel)
            {
                Ok((h, _, _)) => {
                    let i = store.data_mut().side_modules.insert(rel.clone(), h);
                    eprintln!("[preload-random] pre-loaded {rel} idx={i}");
                }
                Err(e) => eprintln!("[preload-random] FAILED {rel}: {e}"),
            }
        }
    }

    // Boot CPython.
    if let Some(func) = instance.get_func(&mut store, "__wasm_call_ctors") {
        eprintln!("[pandas_probe] calling __wasm_call_ctors...");
        match func.call(&mut store, &[], &mut []) {
            Ok(_) => eprintln!("[pandas_probe] __wasm_call_ctors OK"),
            Err(e) => {
                return format!("CTORS FAILED: {e}");
            }
        }
    }

    let outcome = run_pandas_phase(&instance, &mut store, &mech_log, &noop_log);

    // Optional post-mortem guest-memory dump for diagnosis. BURN_DUMP_ADDR is a
    // comma-separated list of hex addresses; dump 64 bytes around each as both
    // raw bytes and the u32 words (so a candidate object header / type ptr can
    // be inspected). No-op when unset.
    if let Ok(addrs) = std::env::var("BURN_DUMP_ADDR")
        && let Some(mem) = store.data().pyodide_memory
    {
        let d = mem.data(&store);
        for tok in addrs.split(',') {
            let tok = tok.trim().trim_start_matches("0x");
            let Ok(addr) = usize::from_str_radix(tok, 16) else {
                continue;
            };
            let lo = addr.saturating_sub(16);
            eprintln!("[DUMP] around {addr:#x}:");
            for row in 0..6usize {
                let base = lo + row * 16;
                if base + 16 > d.len() {
                    break;
                }
                let w0 = u32::from_le_bytes([d[base], d[base + 1], d[base + 2], d[base + 3]]);
                let w1 = u32::from_le_bytes([d[base + 4], d[base + 5], d[base + 6], d[base + 7]]);
                let w2 = u32::from_le_bytes([d[base + 8], d[base + 9], d[base + 10], d[base + 11]]);
                let w3 =
                    u32::from_le_bytes([d[base + 12], d[base + 13], d[base + 14], d[base + 15]]);
                let mark = if base <= addr && addr < base + 16 {
                    " <-- target"
                } else {
                    ""
                };
                eprintln!("  {base:#010x}: {w0:#010x} {w1:#010x} {w2:#010x} {w3:#010x}{mark}");
            }
        }
    }

    // Optional: scan all of guest memory for word-aligned occurrences of given
    // u32 values (BURN_SCAN_VAL, comma-separated hex). Reports the first 40 hit
    // addresses per value, so the storage location of a corrupt pointer can be
    // located. No-op when unset.
    if let Ok(vals) = std::env::var("BURN_SCAN_VAL")
        && let Some(mem) = store.data().pyodide_memory
    {
        let d = mem.data(&store);
        for tok in vals.split(',') {
            let tok = tok.trim().trim_start_matches("0x");
            let Ok(needle) = u32::from_str_radix(tok, 16) else {
                continue;
            };
            let nb = needle.to_le_bytes();
            let mut hits: Vec<usize> = Vec::new();
            let mut a = 0usize;
            while a + 4 <= d.len() {
                if d[a] == nb[0] && d[a + 1] == nb[1] && d[a + 2] == nb[2] && d[a + 3] == nb[3] {
                    hits.push(a);
                    if hits.len() >= 40 {
                        break;
                    }
                }
                a += 4;
            }
            eprintln!(
                "[SCAN] value {needle:#x}: {} aligned hit(s){}: {:#x?}",
                hits.len(),
                if hits.len() >= 40 { " (capped)" } else { "" },
                hits
            );
        }
    }

    outcome
}

/// Python code to run. Writes output to /tmp/pyout.txt via file I/O.
///
/// Uses a try/except so any ImportError or other exception gets written to the
/// file (with a full traceback) instead of trapping silently.
const PANDAS_CODE: &[u8] = b"import traceback\ntry:\n    import pandas as pd\n    ver=pd.__version__\n    df=pd.DataFrame({'a':[1,2,3]})\n    s=int(df['a'].sum())\n    s2=df.sum()\n    f=open('/tmp/pyout.txt','a')\n    f.write('pandas_version '+ver+'\\n')\n    f.write('col_sum '+str(s)+'\\n')\n    f.write('frame_sum_a '+str(int(s2['a']))+'\\n')\n    f.close()\nexcept BaseException as e:\n    f=open('/tmp/pyout.txt','a')\n    f.write('ERR '+type(e).__name__+': '+str(e)+'\\n')\n    f.flush()\n    tb=e.__traceback__\n    while tb is not None:\n        co=tb.tb_frame.f_code\n        f.write('  '+co.co_filename+':'+str(tb.tb_lineno)+' '+co.co_name+'\\n')\n        f.flush()\n        tb=tb.tb_next\n    f.close()\n\0";

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

fn run_pandas_phase(
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
    // Allow overriding the Python snippet from a file (BURN_PY_CODE) so the
    // import path can be probed without a rebuild.
    //
    // In pyodide's native (non-JS) build, Python's sys.stdout goes through a
    // JS-backed IO layer that produces no output. Prepend a redirect so that
    // print() and traceback output land in /tmp/pyout.txt (captured by the
    // probe via the in-memory FS) rather than being silently dropped.
    // Use line-buffered mode (buffering=1) so each print() flushes immediately.
    // Also redirect stderr so tracebacks land in the same file.
    const STDOUT_REDIRECT: &[u8] =
        b"import sys; _f=open('/tmp/pyout.txt','w',buffering=1); sys.stdout=_f; sys.stderr=_f\n";
    let code_owned: Option<Vec<u8>> = std::env::var("BURN_PY_CODE").ok().and_then(|p| {
        std::fs::read(&p)
            .map(|b| {
                let mut out = STDOUT_REDIRECT.to_vec();
                out.extend_from_slice(&b);
                out.push(0);
                eprintln!(
                    "[pandas_probe] using BURN_PY_CODE from {p} ({} bytes)",
                    out.len()
                );
                out
            })
            .ok()
    });
    let code_slice: &[u8] = code_owned.as_deref().unwrap_or(PANDAS_CODE);
    let arg2_ptr = match alloc_cstr(store, code_slice) {
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

    eprintln!("[pandas_probe P5] calling __main_argc_argv(3, {argv_ptr:#x})...");
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
    eprintln!("[pandas_probe P5] __main_argc_argv returned {main_exit}");
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

    // Do NOT clear wasi_stdout here: the -c code runs inside __main_argc_argv,
    // so any print() output is already in wasi_stdout. run_main() only does
    // Emscripten keepalive cleanup with no user-visible output.
    eprintln!("[pandas_probe P5] calling run_main()...");
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

            // Read the shared C stack pointer and the layout bounds so a C-stack
            // overflow (SP descended below stack_low) can be distinguished from a
            // genuine bad table index.
            let sp_now = store
                .data()
                .pyodide_stack_pointer
                .map(|g| match g.get(&mut *store) {
                    wasmtime::Val::I32(v) => v as u32,
                    _ => 0,
                })
                .unwrap_or(0);
            eprintln!("[pandas_probe P5] shared __stack_pointer at trap = {sp_now:#x}");

            // Dump the OOB-instrumenter scratch region (instrument_callind_oob
            // records the offending call_indirect index + caller here).
            if let Some(mem) = store.data().pyodide_memory {
                let d = mem.data(&*store);
                let rd = |off: usize| -> u32 {
                    if off + 4 <= d.len() {
                        u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
                    } else {
                        0
                    }
                };
                // instrument_callind_314 scratch (magic 0xCA111DCA at 0x1BF0000):
                // the first call_indirect with a null (slot-0) index records the
                // caller function and call-site ordinal here, then traps.
                // instrument_addr_watch_314 ring (head at 0x1B00000, entries
                // {func,val,addr} at +8): the write history of the watched object
                // header. Shows who last wrote (and zeroed) the corrupt PyObject.
                {
                    let ring = 0x1B0_0000usize;
                    let head = rd(ring);
                    if head > 0 {
                        let cap = 256u32;
                        let shown = head.min(cap);
                        eprintln!(
                            "[addrwatch] {head} stores to watched window; last {shown} (func, val, addr):"
                        );
                        let start = head.saturating_sub(shown);
                        for i in start..head {
                            let slot = (i % cap) as usize;
                            let e = ring + 8 + slot * 12;
                            eprintln!(
                                "  [{i}] func={} val={:#x} addr={:#x}",
                                rd(e),
                                rd(e + 4),
                                rd(e + 8)
                            );
                        }
                    }
                }
                // instrument_minsp_314 scratch (magic 0x51595159 at 0x1BE0000):
                // the lowest C stack-pointer value reached. Below __stack_low
                // (0x3e0110) means a stack overflow corrupted memory.
                let ms = 0x1BE_0000usize;
                if rd(ms) == 0x5159_5159 {
                    let min_sp = rd(ms + 4);
                    eprintln!(
                        "[minsp314] min C stack-pointer reached = {min_sp:#x} (__stack_low=0x3e0110); \
                         {} stack region",
                        if min_sp < 0x3e0110 {
                            "OVERFLOWED below"
                        } else {
                            "within"
                        }
                    );
                }
                let cs = 0x1BF_0000usize;
                if rd(cs) == 0xCA11_1DCA {
                    eprintln!(
                        "[callind314] magic set: index={} caller_func={} callsite_ordinal={}",
                        rd(cs + 4),
                        rd(cs + 8),
                        rd(cs + 12),
                    );
                    let obj = rd(cs + 16);
                    let ob_type = rd(cs + 20);
                    let tp_dealloc = rd(cs + 24);
                    let tp_flags = rd(cs + 28);
                    let tp_name_ptr = rd(cs + 32);
                    eprintln!(
                        "[callind314] obj={obj:#x} ob_type={ob_type:#x} tp_dealloc={tp_dealloc:#x} \
                         tp_flags={tp_flags:#x} tp_name_ptr={tp_name_ptr:#x}"
                    );
                    // Read the tp_name C-string if the pointer looks sane.
                    let read_cstr = |p: usize| -> String {
                        if p == 0 || p >= d.len() {
                            return "<null/oob>".to_owned();
                        }
                        let mut s = Vec::new();
                        let mut q = p;
                        while q < d.len() && d[q] != 0 && s.len() < 64 {
                            s.push(d[q]);
                            q += 1;
                        }
                        String::from_utf8_lossy(&s).into_owned()
                    };
                    eprintln!(
                        "[callind314] tp_name = {:?}",
                        read_cstr(tp_name_ptr as usize)
                    );
                    // Dump the type object header (first 32 words) so tp_dealloc
                    // (offset 24) and neighbours are visible.
                    if ob_type != 0 && (ob_type as usize) < d.len() {
                        let ot = ob_type as usize;
                        let mut w = String::new();
                        for k in 0..32usize {
                            let off = ot + k * 4;
                            if off + 4 > d.len() {
                                break;
                            }
                            w.push_str(&format!("+{}={:#x} ", k * 4, rd(off)));
                        }
                        eprintln!("[callind314] ob_type @ {ot:#x}: {w}");
                    }
                }
                let s = 0x1BD_0000usize;
                if rd(s) == 0x00B_00B {
                    let obj = rd(s + 16);
                    eprintln!(
                        "[oob] magic set: index={:#x} caller_func={} callsite={} captured_obj={:#x}",
                        rd(s + 4),
                        rd(s + 8),
                        rd(s + 12),
                        obj
                    );
                    // Dump the captured obj header + the obj+488 chain.
                    if obj != 0 {
                        let o = obj as usize;
                        let dump = |base: usize, label: &str| {
                            let mut w = String::new();
                            for k in 0..8usize {
                                let off = base + k * 4;
                                w.push_str(&format!("{:#x} ", rd(off)));
                            }
                            eprintln!("[oob]   {label} @ {base:#x}: {w}");
                        };
                        dump(o, "obj");
                        let p488 = rd(o + 488) as usize;
                        eprintln!("[oob]   obj+488 = {p488:#x}");
                        if p488 != 0 {
                            dump(p488, "obj+488 target");
                        }
                    }
                }
            }

            let debug_chain = format!("{e:?}");

            let frame_lines = e
                .downcast_ref::<WasmBacktrace>()
                .map(|bt| {
                    let frames = bt.frames();
                    let mut s = format!("WasmBacktrace ({} frames):\n", frames.len());
                    for (i, fr) in frames.iter().enumerate().take(60) {
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

            let last_idx = store.data().last_invoke_idx;
            let table_scan = if let Some(tbl) = store.data().pyodide_table {
                let size = tbl.size(&mut *store);
                let mut nulls: Vec<u64> = Vec::new();
                for i in 0..size {
                    if !matches!(tbl.get(&mut *store, i), Some(wasmtime::Ref::Func(Some(_)))) {
                        nulls.push(i);
                    }
                }
                let first: Vec<u64> = nulls.iter().take(60).copied().collect();
                format!(
                    "table size={size}, null funcref slots={} (first 60: {first:?})",
                    nulls.len()
                )
            } else {
                "no pyodide_table".to_owned()
            };

            return format!(
                "TRAPPED in run_main: {e}\n\
                 Trap kind: {trap_kind}\n\
                 Table scan: {table_scan} last_invoke_idx={last_idx}\n\
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

    eprintln!("[pandas_probe P5] pyout:\n{pyout}");

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
