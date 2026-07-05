// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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
    JsFfiCallLog, MainModuleLayout, MechCallLog, NoopCallLog, fill_unknown_imports_as_noops,
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

/// Ring buffer base address in guest linear memory (28 MiB), must match
/// `instrument_sp.rs` RING_BASE exactly.
const RING_BASE: usize = 0x1C0_0000;
/// Number of ring entries (power of two), must match `instrument_sp.rs` RING_CAP.
const RING_CAP: usize = 1024;
/// Byte size of each ring entry: { addr:i32, val:i32 } = 8 bytes.
const RING_ENTRY_BYTES: usize = 8;
/// Byte offset of entries from RING_BASE (skip 8-byte header).
const RING_ENTRIES_OFFSET: usize = 8;

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
        "[numpy_probe] loaded pyodide ({} bytes) from {wasm_path}",
        wasm_bytes.len()
    );

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
        match wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, &layout, &module) {
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
            match mount_zip_into_fs(
                &mut store.data_mut().fs,
                STDLIB_MOUNT_PREFIX,
                ::std::sync::Arc::from(zip_bytes.clone()),
            ) {
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
    eprintln!("[numpy_probe] {} imports auto-filled:", auto_filled.len());
    for name in &auto_filled {
        eprintln!("  [noop-stub] {name}");
    }

    eprintln!("[numpy_probe] instantiating...");
    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            return format!("INSTANTIATION FAILED: {e}");
        }
    };
    eprintln!("[numpy_probe] instantiated");

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
            "[numpy_probe] GOT: {} elem, {} export, {} stub, {} mem",
            r.funcs_from_elem, r.funcs_from_export, r.funcs_stubbed, r.mem_resolved
        ),
        Err(e) => return format!("GOT RESOLUTION FAILED: {e}"),
    }

    // Initialize the C-stack bookkeeping (base/end/limit) BEFORE relocs/ctors.
    // Emscripten's runtime startup calls this; without it CPython's C recursion
    // limit and the stack-overflow guard operate on zeroed limits, so deep
    // activity (numpy's import) runs past the guard and clobbers live C-stack
    // frames such as `_PyEval_EvalFrameDefault`'s `entry_frame` (ceval.c) - whose
    // dangling `previous` link then crashes frame teardown (`take_ownership`).
    if let Some(func) = instance.get_func(&mut store, "emscripten_stack_init") {
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("emscripten_stack_init FAILED: {e}");
        }
        eprintln!("[numpy_probe] emscripten_stack_init OK");
    }

    if let Some(func) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        if let Err(e) = func.call(&mut store, &[], &mut []) {
            return format!("RELOC FAILED: {e}");
        }
        eprintln!("[numpy_probe] __wasm_apply_data_relocs OK");
    }

    // DIAGNOSTIC (BURN_GAP_SCAN): scan guest static-data memory for aligned u32
    // values in the null table gap [6074..6643). NOTE: this gap is a RED HERRING.
    // Investigation proved every R_WASM_TABLE_INDEX data relocation in the main
    // module targets a slot <= 6073 (inside the element segment [1..6074)); the
    // [6074..6643) slots are null only because afterburner sizes the table to the
    // OLD build's WASM_TABLE_INITIAL_SIZE=6643 (new build dylink table_size=6073),
    // and they are never the call target. The actual trap is a call_indirect to
    // table slot 0 (NULL) from _PyEval_EvalFrameDefault reading a NULL function
    // pointer out of a static C struct, i.e. an upstream eval-state corruption.
    // The byte-coincidence hits this scan reports are non-pointer data, not fnptrs.
    if std::env::var("BURN_GAP_SCAN").is_ok()
        && let Some(mem) = store.data().pyodide_memory
    {
        let d = mem.data(&store);
        let (lo, hi) = (6074u32, 6643u32);
        // Scan the whole static data image (first ~5 MiB) for aligned u32 in range.
        let scan_end = d.len().min(6 * 1024 * 1024);
        let mut by_slot: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
        let mut addrs_for_slot: std::collections::BTreeMap<u32, Vec<usize>> =
            std::collections::BTreeMap::new();
        let mut a = 0usize;
        while a + 4 <= scan_end {
            let v = u32::from_le_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]]);
            if v >= lo && v < hi {
                *by_slot.entry(v).or_default() += 1;
                let e = addrs_for_slot.entry(v).or_default();
                if e.len() < 4 {
                    e.push(a);
                }
            }
            a += 4;
        }
        eprintln!(
            "[GAP-SCAN] {} distinct gap-slot values referenced in static data (aligned u32)",
            by_slot.len()
        );
        for (slot, cnt) in by_slot.iter() {
            let addrs = addrs_for_slot
                .get(slot)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            eprintln!("  slot={slot} refs={cnt} at_addrs={addrs:x?}");
        }
        // Dump the dispatch table that func 3530 reads (global 568 = 0x2BB770).
        let base = 0x2BB770usize;
        eprintln!("[GAP-SCAN] dispatch table @ {base:#x} (8-byte stride, first 32 entries):");
        for i in 0..32usize {
            let a = base + i * 8;
            if a + 8 <= d.len() {
                let sel = u32::from_le_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]]);
                let fp = u32::from_le_bytes([d[a + 4], d[a + 5], d[a + 6], d[a + 7]]);
                let mark = if fp >= lo && fp < hi { "  <-- GAP" } else { "" };
                eprintln!("  [{i:>2}] @{a:#x} word0={sel:#x} word1(fp)={fp}{mark}");
            }
        }
    }

    // Pre-load the numpy core SIDE_MODULE before ctors - CPython's import
    // machinery expects it available from the first dlopen() call.
    // All other .so files (linalg, fft, random, ...) are loaded on-demand
    // when Python calls _dlopen_js; the wheel is already mounted in FS.
    let (handle, _next_mem, _next_tbl) = match pre_load_side_module(
        &engine,
        &mut store,
        &instance,
        &[],
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
    eprintln!("[numpy_probe] numpy core SIDE_MODULE pre-loaded, idx={idx}");

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

    // SMART DEBUG (BURN_MALLOC_TEST): malloc stress-test, no numpy import needed.
    // Detects overlapping / OOB allocations - the kind of allocator bug that
    // would let numpy's small float buffers corrupt each other.
    if std::env::var("BURN_MALLOC_TEST").is_ok() {
        if let Some(malloc) = instance.get_func(&mut store, "malloc") {
            let sizes = [
                2u32, 4, 8, 16, 2, 4, 2, 2, 4, 8, 32, 2, 16, 64, 2, 4, 1, 3, 5,
            ];
            let memsz = store
                .data()
                .pyodide_memory
                .map(|m| m.data_size(&store))
                .unwrap_or(0);
            let mut allocs: Vec<(u32, u32)> = Vec::new();
            let mut overlaps = 0usize;
            for i in 0..4000usize {
                let size = sizes[i % sizes.len()];
                let mut r = [wasmtime::Val::I32(0)];
                if malloc
                    .call(&mut store, &[wasmtime::Val::I32(size as i32)], &mut r)
                    .is_err()
                {
                    eprintln!("[MALLOC] call failed at i={i}");
                    break;
                }
                let p = if let wasmtime::Val::I32(v) = r[0] {
                    v as u32
                } else {
                    0
                };
                if p == 0 {
                    eprintln!("[MALLOC] NULL at i={i} size={size}");
                    break;
                }
                if (p as usize) + (size as usize) > memsz {
                    eprintln!("[MALLOC OOB] ({p:#x}+{size}) past mem {memsz:#x} i={i}");
                }
                for (pp, ss) in &allocs {
                    if p < pp + ss && *pp < p + size {
                        overlaps += 1;
                        if overlaps <= 8 {
                            eprintln!("[MALLOC OVERLAP] new ({p:#x},{size}) vs ({pp:#x},{ss})");
                        }
                    }
                }
                allocs.push((p, size));
            }
            // Free-path stress: numpy creates+frees many temp float buffers.
            // A buggy free (double-free / bad coalescing) corrupts live blocks -
            // exactly the "wrote into a live object" signature we're chasing.
            let mut free_corrupt = 0usize;
            if let (Some(free), Some(mem)) = (
                instance.get_func(&mut store, "free"),
                store.data().pyodide_memory,
            ) {
                let mut live: Vec<(u32, u32, u8)> = Vec::new();
                let mut canary: u8 = 1;
                for _round in 0..400usize {
                    for &size in &[8u32, 16, 32, 16, 8, 24] {
                        let mut r = [wasmtime::Val::I32(0)];
                        if malloc
                            .call(&mut store, &[wasmtime::Val::I32(size as i32)], &mut r)
                            .is_err()
                        {
                            break;
                        }
                        let p = if let wasmtime::Val::I32(v) = r[0] {
                            v as u32
                        } else {
                            0
                        };
                        if p == 0 {
                            continue;
                        }
                        canary = canary.wrapping_add(1);
                        if canary == 0 {
                            canary = 1;
                        }
                        let d = mem.data_mut(&mut store);
                        for b in 0..size as usize {
                            if (p as usize) + b < d.len() {
                                d[p as usize + b] = canary;
                            }
                        }
                        live.push((p, size, canary));
                    }
                    {
                        let d = mem.data(&store);
                        for (p, size, c) in &live {
                            for b in 0..*size as usize {
                                if d[*p as usize + b] != *c {
                                    free_corrupt += 1;
                                    if free_corrupt <= 8 {
                                        eprintln!(
                                            "[FREE-TEST CORRUPT] ({p:#x},{size}) b{b} {}!={c}",
                                            d[*p as usize + b]
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    let n = live.len() / 2;
                    for _ in 0..n {
                        let (p, _, _) = live.remove(0);
                        let _ = free.call(&mut store, &[wasmtime::Val::I32(p as i32)], &mut []);
                    }
                }
                eprintln!(
                    "[FREE-TEST] {free_corrupt} corruptions, {} still live",
                    live.len()
                );
            }
            return format!(
                "MALLOC TEST: {} allocs, {overlaps} overlaps, {free_corrupt} free-corruptions",
                allocs.len()
            );
        }
        return "MALLOC TEST: no malloc export".to_owned();
    }

    let outcome = run_numpy_phase(&instance, &mut store, &mech_log, &noop_log);
    dump_frame_capture(&store);
    outcome
}

/// Dump the frame (param0) captured by the func-3871 instrument at 0x1C00000,
/// to find why its stacktop/localsplus is corrupt. Only meaningful with the
/// instrumented wasm (BURN_PROBE_WASM); no-op otherwise (param0 stays 0).
fn dump_frame_capture(store: &Store<EmbedderState>) {
    let Some(mem) = store.data().pyodide_memory else {
        return;
    };
    let d = mem.data(store);
    let rd = |a: usize| -> u32 {
        if a + 4 <= d.len() {
            u32::from_le_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]])
        } else {
            0
        }
    };
    let param0 = rd(0x1C0_0000) as usize;
    let eff = rd(0x1C0_0004);
    let local1 = rd(0x1C0_0008);
    let local3 = rd(0x1C0_000C);
    let frame_obj = rd(0x1C0_0010) as usize;
    let local4 = rd(0x1C0_0014);
    if param0 == 0 {
        return;
    }
    eprintln!(
        "[FRAME-DUMP] frame(param0)={param0:#x} eff={eff:#x} local1={local1:#x} local3(garbage)={local3:#x} frame_obj={frame_obj:#x} local4={local4:#x}"
    );
    eprintln!("  -- frame (param0) header --");
    for off in (0..48usize).step_by(4) {
        eprintln!(
            "  [frame+{off:>2}] = {:#010x} ({})",
            rd(param0 + off),
            rd(param0 + off) as i32
        );
    }
    // Walk the chain func 3871 walks ([frame_obj+40], follow +4) and print each
    // node's +24 cache; the node whose +24 < 1024 is the corrupt one.
    if frame_obj != 0 && frame_obj < d.len() {
        eprintln!("  -- frame_obj header --");
        for off in (0..48usize).step_by(4) {
            eprintln!("  [fo+{off:>2}] = {:#010x}", rd(frame_obj + off));
        }
        let mut node = rd(frame_obj + 40) as usize;
        eprintln!("  -- chain from [frame_obj+40]={node:#x} (follow +4) --");
        let mut steps = 0;
        while node != 0 && node + 40 < d.len() && steps < 40 {
            let cache = rd(node + 24);
            let owner = d.get(node + 38).copied().unwrap_or(0);
            let exe = rd(node);
            let flag = if cache != 0 && cache < 1024 {
                "  <-- BAD: [node+24] cache < 1024"
            } else {
                ""
            };
            eprintln!(
                "  node[{steps:>2}]={node:#x} exe={exe:#x} owner={owner} [+24]cache={cache:#x}{flag}"
            );
            node = rd(node + 4) as usize;
            steps += 1;
        }
    }
    // Walk param0's `previous` chain (follow +4) - take_ownership walks this via
    // _PyFrame_GetFirstComplete. Find the frame whose previous IS the corrupt
    // string (0x18be8c0) or a near-null; that frame's +4 is the real slot.
    eprintln!("  -- param0 previous chain (follow +4) --");
    {
        let mut fr = param0;
        let mut steps = 0;
        while fr != 0 && fr + 40 < d.len() && steps < 60 {
            let prev = rd(fr + 4);
            let owner = d.get(fr + 38).copied().unwrap_or(0);
            let exe = rd(fr);
            let corrupt = prev == 0x18be8c0 || (prev != 0 && prev < 1024);
            let flag = if corrupt {
                "  <<< previous is CORRUPT"
            } else {
                ""
            };
            eprintln!(
                "  fr[{steps:>2}]={fr:#x} exe={exe:#x} owner={owner} previous={prev:#x}{flag}"
            );
            if corrupt {
                eprintln!(
                    "    (this frame @ {:#x}+4 = {:#x} is the corrupt slot)",
                    fr,
                    fr + 4
                );
                break;
            }
            fr = prev as usize;
            steps += 1;
        }
    }
    // local1 history (newest->oldest): the chain node survives reuse here. The
    // node whose +24 cache is the garbage pointer (< 1024) is the culprit.
    eprintln!("  -- local1 history (newest->oldest) --");
    for (i, slot) in [0x1C0_0018usize, 0x1C0_001C, 0x1C0_0020, 0x1C0_0024]
        .iter()
        .enumerate()
    {
        let p = rd(*slot) as usize;
        let c24 = if p + 28 < d.len() { rd(p + 24) } else { 0 };
        let exe = if p + 4 < d.len() { rd(p) } else { 0 };
        let owner = if p + 38 < d.len() { d[p + 38] } else { 0 };
        let flag = if c24 != 0 && c24 < 1024 {
            "  <<< NODE (its +24 is the garbage)"
        } else {
            ""
        };
        eprintln!("  hist[{i}]={p:#x} exe={exe:#x} owner={owner} [+24]={c24:#x}{flag}");
        if c24 != 0 && c24 < 1024 && p + 48 < d.len() {
            for off in (0..48usize).step_by(4) {
                eprintln!("    [node+{off:>2}] = {:#010x}", rd(p + off));
            }
        }
    }
    // f_executable (code object) at frame+0: dump its head for co_* sizes.
    let code = rd(param0) as usize;
    eprintln!("  -- f_executable(code)={code:#x} --");
    if code != 0 {
        for off in (0..72usize).step_by(4) {
            eprintln!(
                "  [code+{off:>2}] = {:#010x} ({})",
                rd(code + off),
                rd(code + off) as i32
            );
        }
    }
}

/// Python code to run. Writes output to /tmp/pyout.txt via file I/O.
///
/// Uses a try/except so any ImportError or other exception gets written to the
/// file instead of trapping silently.
const NUMPY_CODE: &[u8] = b"import traceback\ntry:\n    import numpy as np\n    ver=np.__version__\n    arange_sum=int(np.arange(10).sum())\n    mean=float(np.array([1.,2.,3.]).mean())\n    f=open('/tmp/pyout.txt','a')\n    f.write('numpy_version '+ver+'\\n')\n    f.write('arange_sum '+str(arange_sum)+'\\n')\n    f.write('mean '+str(mean)+'\\n')\n    f.close()\nexcept BaseException as e:\n    f=open('/tmp/pyout.txt','a')\n    f.write('ERR '+type(e).__name__+': '+str(e)+'\\n')\n    f.flush()\n    tb=e.__traceback__\n    while tb is not None:\n        co=tb.tb_frame.f_code\n        f.write('  '+co.co_filename+':'+str(tb.tb_lineno)+' '+co.co_name+'\\n')\n        f.flush()\n        tb=tb.tb_next\n    f.close()\n\0";

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
            dump_store_ring(store);
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
            dump_store_ring(store);
            dump_callind_scratch(store);
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

            // Table-null scan: which table slots are null funcrefs (the
            // "uninitialized element" candidates the trapping call_indirect hit).
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

    dump_store_ring(store);
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

/// Read the call_indirect-instrumenter scratch region at 0x1BF0000 and report
/// the captured trapping index, caller func, and call-site ordinal. No-op (magic
/// absent) unless running against the instrument_callind output wasm.
fn dump_callind_scratch(store: &Store<EmbedderState>) {
    let Some(mem) = store.data().pyodide_memory else {
        return;
    };
    let d = mem.data(store);
    let base = 0x1BF_0000usize;
    let rd = |a: usize| -> u32 {
        if a + 4 <= d.len() {
            u32::from_le_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]])
        } else {
            0
        }
    };
    let magic = rd(base);
    if magic != 0xCA11_1DCA {
        return;
    }
    eprintln!(
        "[CALLIND] trapping call_indirect index={} caller_func={} callsite_ordinal={} global568={:#x}",
        rd(base + 4),
        rd(base + 8),
        rd(base + 12),
        rd(base + 16),
    );
    eprintln!(
        "[CALLIND] func3530 ctx: local3(index)={} local5(bc_ptr)={:#x} local7(sp)={:#x}  load_addr=global568+local3*8={:#x}",
        rd(base + 20),
        rd(base + 24),
        rd(base + 28),
        rd(base + 16).wrapping_add(rd(base + 20).wrapping_mul(8)),
    );
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

/// Read the `0xC200????`-store ring buffer from guest linear memory and print
/// every recorded entry as `STORE-REC addr=0x.. val=0x..` to stderr.
///
/// Call this immediately after a trap (or at run end) to get the full sequence
/// of addresses that received a corruption-pattern store. The outlier address
/// (not a freshly-malloc'd float buffer) is the target of the actual corruption.
fn dump_store_ring(store: &Store<EmbedderState>) {
    let mem = match store.data().pyodide_memory {
        Some(m) => m,
        None => {
            eprintln!("[STORE-RING] pyodide_memory not available");
            return;
        }
    };
    let data = mem.data(store);
    let total_bytes = RING_BASE + RING_ENTRIES_OFFSET + RING_CAP * RING_ENTRY_BYTES;
    if data.len() < total_bytes {
        eprintln!(
            "[STORE-RING] memory too small: {} < {total_bytes:#x}",
            data.len()
        );
        return;
    }
    // Read head (i32 little-endian at RING_BASE+0).
    let head =
        u32::from_le_bytes(data[RING_BASE..RING_BASE + 4].try_into().expect("4 bytes")) as usize;
    eprintln!("[STORE-RING] head={head} (total stores recorded with 0xC2000000 pattern)");
    if head == 0 {
        eprintln!("[STORE-RING] no matching stores recorded");
        return;
    }
    // Determine the range of valid entries (up to RING_CAP, oldest first).
    let count = head.min(RING_CAP);
    let oldest = head.saturating_sub(RING_CAP);
    for i in oldest..head {
        let slot = i % RING_CAP;
        let entry_base = RING_BASE + RING_ENTRIES_OFFSET + slot * RING_ENTRY_BYTES;
        let addr = u32::from_le_bytes(
            data[entry_base..entry_base + 4]
                .try_into()
                .expect("4 bytes"),
        );
        let val = u32::from_le_bytes(
            data[entry_base + 4..entry_base + 8]
                .try_into()
                .expect("4 bytes"),
        );
        // seq is the monotonic store sequence number (1-based).
        let seq = i + 1;
        eprintln!("STORE-REC [{seq:>5}] addr={addr:#010x} val={val:#010x}");
    }
    eprintln!("[STORE-RING] dumped {count} entries");
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
