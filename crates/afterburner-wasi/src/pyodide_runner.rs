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

use std::path::{Path, PathBuf};

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{
    FuncType, Global, GlobalType, Instance, Linker, Module, Mutability, Store, Tag, TagType, Val,
    ValType,
};

use crate::{
    embedder_vm::{EmbedderState, deterministic_engine},
    emscripten_dylink::{
        fill_got_table_slots, parse_got_name_to_slot, resolve_self_provided_got_func,
        wire_got_func_stubs_from_module,
    },
    emscripten_fs::{InMemFs, mount_zip_into_fs},
    emscripten_invoke::wire_invoke_trampolines,
    emscripten_mechanical::wire_pyodide028_env_stubs,
    emscripten_runtime::{
        MainModuleLayout, MechCallLog, NoopCallLog, adopt_self_provided_exports,
        fill_unknown_imports_as_noops, module_self_provides_env,
        wire_env_memory_and_table_in_store, wire_wasi_only,
    },
    emscripten_sidemodule::{pre_load_side_module, wire_dlopen_dlsym},
    emscripten_syscall::wire_fs_env_funcs,
};

/// Instruction budget - CPython 3.13 static init is heavy.
///
/// vertexia: global fuel budget; per-phase sub-budgets would let us measure
/// which init phase consumes the most instructions.
const PYODIDE_FUEL: u64 = 500_000_000_000;

/// Guest mount paths for the Python stdlib, derived from the interpreter's
/// `X.Y` version (e.g. `"3.14"` -> `/lib/python314.zip` + `/lib/python3.14`).
///
/// The version comes from `BURN_PYTHON_STDLIB_VER` (default `3.13`, the Pyodide
/// 0.28.x interpreter) so a single boot path serves any Pyodide release: CPython
/// searches `sys.prefix/lib/pythonXY.zip` and `sys.prefix/lib/pythonX.Y/`, so the
/// stdlib must be mounted under the exact version directory the binary was built
/// for. The version is external knowledge (which Pyodide release), not derivable
/// from the flat stdlib zip, so it is a parameter rather than a hardcoded
/// constant.
fn python_stdlib_mount_paths() -> (String, String) {
    let ver = std::env::var("BURN_PYTHON_STDLIB_VER").unwrap_or_else(|_| "3.13".to_owned());
    let flat = ver.replace('.', "");
    (
        format!("/lib/python{flat}.zip"),
        format!("/lib/python{ver}"),
    )
}

// ---- runtime resolution (bundle by default; env overrides) -----------------

/// A fully-resolved Python runtime: the exnref main wasm, the stdlib zip, the
/// wheel set to mount (in dependency order), and the interpreter `X.Y` version.
///
/// Resolved by [`resolve_runtime`], which prefers the explicit `BURN_*` env
/// overrides and otherwise loads the self-contained bundle the build script
/// assembled (see [`crate::pyodide_bundle`]). So `burn run x.py` runs numpy +
/// pandas with no configuration, while a developer can still point at a custom
/// runtime via `BURN_PYTHON_RUNTIME` / `BURN_WHEELS`.
pub struct PyRuntime {
    /// exnref-translated `pyodide.asm.wasm`.
    pub wasm_path: PathBuf,
    /// `python_stdlib.zip`.
    pub stdlib_path: PathBuf,
    /// Wheels to mount, in dependency (load) order. Empty = stdlib only.
    pub wheels: Vec<PathBuf>,
    /// Interpreter `X.Y`, e.g. `"3.13"`, for the stdlib mount + soabi tag.
    pub python_xy: String,
}

/// Resolve the Python runtime to run, honoring (in order):
///
/// 1. `BURN_PYTHON_RUNTIME=<dir>` - a directory with `pyodide-exnref.wasm` and
///    `python_stdlib.zip`. Wheels come from `BURN_WHEELS` (comma-separated
///    paths) if set, else none. `BURN_PYTHON_STDLIB_VER` overrides the version.
/// 2. The bundled runtime the build script assembled (numpy + pandas included).
///
/// Returns `Err` (honest, actionable) when neither is available.
pub fn resolve_runtime() -> Result<PyRuntime> {
    if let Ok(dir) = std::env::var("BURN_PYTHON_RUNTIME") {
        let wasm_path = Path::new(&dir).join("pyodide-exnref.wasm");
        let stdlib_path = std::env::var("BURN_PYTHON_STDLIB_ZIP")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Path::new(&dir).join("python_stdlib.zip"));
        if !wasm_path.exists() {
            return Err(AfterburnerError::Engine(format!(
                "python runtime not found; {} does not exist. BURN_PYTHON_RUNTIME must point at \
                 a directory containing pyodide-exnref.wasm and python_stdlib.zip",
                wasm_path.display()
            )));
        }
        let wheels = std::env::var("BURN_WHEELS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|p| PathBuf::from(p.trim()))
                    .filter(|p| !p.as_os_str().is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let python_xy =
            std::env::var("BURN_PYTHON_STDLIB_VER").unwrap_or_else(|_| "3.13".to_owned());
        return Ok(PyRuntime {
            wasm_path,
            stdlib_path,
            wheels,
            python_xy,
        });
    }

    if let Some(b) = crate::pyodide_bundle::resolve() {
        return Ok(PyRuntime {
            wasm_path: b.wasm_path,
            stdlib_path: b.stdlib_path,
            wheels: b.wheels,
            python_xy: b.python_xy,
        });
    }

    Err(AfterburnerError::Engine(
        "python runtime not found. The bundled Pyodide runtime was not assembled at build time \
         (wasm-opt or network unavailable); set BURN_PYTHON_RUNTIME=<dir> with pyodide-exnref.wasm \
         and python_stdlib.zip, or rebuild with wasm-opt on PATH."
            .to_owned(),
    ))
}

// ---- wheel + side-module mounting ------------------------------------------

/// soabi tag for a wheel's `.so` files, e.g. `cpython-313-wasm32-emscripten`.
fn soabi_tag(python_xy: &str) -> String {
    format!("cpython-{}-wasm32-emscripten", python_xy.replace('.', ""))
}

/// Guest path of numpy's core `.so` (the one CPython dlopen()s first, so it is
/// pre-loaded before ctors). Everything else loads on demand via `_dlopen_js`.
fn numpy_core_so(python_xy: &str) -> String {
    format!("numpy/_core/_multiarray_umath.{}.so", soabi_tag(python_xy))
}

/// Guest site-packages prefix the wheels are mounted under.
fn site_packages(python_xy: &str) -> String {
    format!("/lib/python{python_xy}/site-packages")
}

/// Mount every file in a wheel (a zip of `.py` + `.so`) into `fs` under
/// `guest_prefix`, skipping `.dist-info` and directory entries. Returns the
/// count mounted. Supports the two zip methods Pyodide wheels use: 0 (stored)
/// and 8 (deflate).
fn mount_wheel(fs: &mut InMemFs, wheel_bytes: &[u8], guest_prefix: &str) -> usize {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut count = 0usize;
    let mut pos = 0usize;
    while pos + 30 <= wheel_bytes.len() {
        let sig = u32::from_le_bytes(wheel_bytes[pos..pos + 4].try_into().unwrap());
        if sig == 0x0201_4b50 || sig == 0x0605_4b50 {
            break;
        }
        if sig != 0x0403_4b50 {
            pos += 1;
            continue;
        }
        let method = u16::from_le_bytes(wheel_bytes[pos + 8..pos + 10].try_into().unwrap());
        let comp_size =
            u32::from_le_bytes(wheel_bytes[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let name_len =
            u16::from_le_bytes(wheel_bytes[pos + 26..pos + 28].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(wheel_bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let name_start = pos + 30;
        let name_end = name_start + name_len;
        if name_end > wheel_bytes.len() {
            break;
        }
        let name = match std::str::from_utf8(&wheel_bytes[name_start..name_end]) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                pos = name_end + extra_len + comp_size;
                continue;
            }
        };
        let data_start = name_end + extra_len;
        let data_end = data_start + comp_size;
        if data_end > wheel_bytes.len() {
            break;
        }
        if name.contains(".dist-info") || name.ends_with('/') {
            pos = data_end;
            continue;
        }
        let raw = &wheel_bytes[data_start..data_end];
        let contents = match method {
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
        fs.insert_file(&format!("{guest_prefix}/{name}"), contents);
        count += 1;
        pos = data_end;
    }
    count
}

/// Extract one named entry from a zip (stored or deflate). Used to pull numpy's
/// core `.so` out of its wheel for pre-load before ctors.
fn extract_from_zip(zip_bytes: &[u8], target: &str) -> Option<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    let mut pos = 0usize;
    while pos + 30 <= zip_bytes.len() {
        let sig = u32::from_le_bytes(zip_bytes[pos..pos + 4].try_into().unwrap());
        if sig == 0x0201_4b50 || sig == 0x0605_4b50 {
            break;
        }
        if sig != 0x0403_4b50 {
            pos += 1;
            continue;
        }
        let method = u16::from_le_bytes(zip_bytes[pos + 8..pos + 10].try_into().unwrap());
        let comp_size =
            u32::from_le_bytes(zip_bytes[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let name_len =
            u16::from_le_bytes(zip_bytes[pos + 26..pos + 28].try_into().unwrap()) as usize;
        let extra_len =
            u16::from_le_bytes(zip_bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let name_start = pos + 30;
        let name_end = name_start + name_len;
        if name_end > zip_bytes.len() {
            break;
        }
        let name = match std::str::from_utf8(&zip_bytes[name_start..name_end]) {
            Ok(s) => s,
            Err(_) => {
                pos = name_end + extra_len + comp_size;
                continue;
            }
        };
        let data_start = name_end + extra_len;
        let data_end = data_start + comp_size;
        if data_end > zip_bytes.len() {
            break;
        }
        if name == target {
            let raw = &zip_bytes[data_start..data_end];
            return match method {
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
///
/// When `rt.wheels` is non-empty, the wheels are mounted into guest
/// site-packages, on-demand `dlopen` is wired, numpy's core `.so` is pre-loaded
/// before ctors, and the main instance is published so side modules can resolve
/// `env.*` - exactly the machinery that lets numpy + pandas import. With no
/// wheels this is the plain stdlib-only boot (byte-identical to the original
/// basic-Python path).
fn boot_pyodide_instance(
    rt: &PyRuntime,
) -> Result<(
    Store<EmbedderState>,
    Instance,
    std::collections::HashMap<String, wasmtime::Global>,
)> {
    let wasm_path = rt.wasm_path.display().to_string();
    let wasm_bytes = std::fs::read(&rt.wasm_path)
        .map_err(|e| AfterburnerError::Engine(format!("read {wasm_path}: {e}")))?;

    // Read every wheel up front and extract numpy's core `.so` for pre-load (a
    // pure-Python wheel set has none, which is fine - it is then skipped).
    let mut wheel_blobs: Vec<Vec<u8>> = Vec::with_capacity(rt.wheels.len());
    let numpy_core = numpy_core_so(&rt.python_xy);
    let mut numpy_so_bytes: Option<Vec<u8>> = None;
    for wheel in &rt.wheels {
        let bytes = std::fs::read(wheel).map_err(|e| {
            AfterburnerError::Engine(format!("read wheel {}: {e}", wheel.display()))
        })?;
        if numpy_so_bytes.is_none()
            && let Some(so) = extract_from_zip(&bytes, &numpy_core)
        {
            numpy_so_bytes = Some(so);
        }
        wheel_blobs.push(bytes);
    }
    let has_wheels = !wheel_blobs.is_empty();

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

    // True for Emscripten 5.0.3 (Pyodide 314+): the module defines and exports
    // its own memory, table, stack pointer, and EH tags, so the host must not
    // create the env counterparts. Detected purely by import shape.
    let self_provided = module_self_provides_env(&module);

    let got_globals =
        wire_env_memory_and_table_in_store(&mut store, &mut linker, 0, &layout, &module)?;

    // Native-EH tags. On the 0.28.x host-provided path the host creates and
    // defines env.__c_longjmp / env.__cpp_exception. On the 314 self-providing
    // path the module exports them; they are adopted after instantiation by
    // adopt_self_provided_exports, so we skip host tag creation here.
    if !self_provided {
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
        // Retain the tags in the store so every side module can share them.
        // Tags are Copy; storing here and having the linker hold a ref both work.
        store.data_mut().pyodide_cpp_exception_tag = Some(cpp_exc);
        store.data_mut().pyodide_c_longjmp_tag = Some(c_longjmp);
    }

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

    // Mount stdlib zip under the interpreter's version-specific guest paths.
    if let Ok(zip_bytes) = std::fs::read(&rt.stdlib_path) {
        let (zip_mount, dir_mount) = python_stdlib_mount_paths();
        store
            .data_mut()
            .fs
            .insert_file(&zip_mount, zip_bytes.clone());
        let _ = mount_zip_into_fs(&mut store.data_mut().fs, &dir_mount, &zip_bytes);
    }
    store.data_mut().fs.mkdir_p("/tmp");

    // Mount every wheel's `.py` + `.so` into guest site-packages. Each `.so`
    // lands in MEMFS and is dlopen'd on demand; numpy's core `.so` is pre-loaded
    // below (CPython expects it from the first dlopen).
    if has_wheels {
        let site_pkgs = site_packages(&rt.python_xy);
        for bytes in &wheel_blobs {
            mount_wheel(&mut store.data_mut().fs, bytes, &site_pkgs);
        }
    }

    wire_got_func_stubs_from_module(&mut store, &mut linker, &module)?;

    // Wire `_dlopen_js` / `_dlsym_js` before the noop fill so Python's dlopen
    // dispatch reaches the side-module registry rather than a noop returning 0.
    // Only needed when wheels ship `.so`; the stdlib-only path leaves it out so
    // its import set stays exactly as before.
    if has_wheels {
        wire_dlopen_dlsym(&mut linker)?;
    }

    let noop_log = NoopCallLog::new();
    fill_unknown_imports_as_noops(&mut store, &mut linker, &module, noop_log);

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| AfterburnerError::Engine(format!("instantiate: {e}")))?;

    // On the 314 self-providing path, adopt the module's exported memory, table,
    // stack pointer, and EH tags into the store BEFORE GOT resolution (which
    // reads the adopted table) and the ctors.
    if self_provided {
        adopt_self_provided_exports(&mut store, &instance)?;
    }

    // Publish the main instance so `_dlopen_js` can wire each side module's
    // `env.*` imports against it when a `.so` is loaded on demand.
    if has_wheels {
        store.data_mut().main_instance = Some(instance);
    }

    fill_got_table_slots(
        &mut store,
        &linker,
        &instance,
        &got_globals,
        &name_to_slot,
        &module,
        layout.host_got_base(),
    )?;

    // On the 314 self-providing path, resolve every GOT.func import into a real
    // table slot (the globals could not be pre-filled before instantiation).
    if self_provided {
        resolve_self_provided_got_func(&mut store, &linker, &module, &got_globals)?;
    }

    // Initialize the C-stack bookkeeping BEFORE relocs/ctors when side modules
    // are in play (they malloc into the heap, which needs the stack set up).
    // Left out of the stdlib-only path to keep it byte-identical to before.
    if has_wheels && let Some(f) = instance.get_func(&mut store, "emscripten_stack_init") {
        f.call(&mut store, &[], &mut [])
            .map_err(|e| AfterburnerError::Engine(format!("emscripten_stack_init: {e}")))?;
    }

    if let Some(f) = instance.get_func(&mut store, "__wasm_apply_data_relocs") {
        f.call(&mut store, &[], &mut [])
            .map_err(|e| AfterburnerError::Engine(format!("__wasm_apply_data_relocs: {e}")))?;
    }

    // Pre-load numpy's core SIDE_MODULE before ctors (CPython's import machinery
    // expects it from the first dlopen). Every other `.so` (numpy's linalg/fft/
    // random and pandas' `pandas/_libs/*.so`) loads on demand via `_dlopen_js`.
    // Skipped for pure-Python wheel sets that ship no numpy core `.so`.
    if let Some(so) = numpy_so_bytes.as_ref() {
        let (handle, _next_mem, _next_tbl) =
            pre_load_side_module(&engine, &mut store, &instance, &[], so, &numpy_core)?;
        store
            .data_mut()
            .side_modules
            .insert(numpy_core.clone(), handle);
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
    let rt = PyRuntime {
        wasm_path: PathBuf::from(wasm_path),
        stdlib_path: PathBuf::from(stdlib_zip_path),
        wheels: Vec::new(),
        python_xy: std::env::var("BURN_PYTHON_STDLIB_VER").unwrap_or_else(|_| "3.13".to_owned()),
    };
    let (store, _instance, _got_globals) = boot_pyodide_instance(&rt)?;
    let stdout = store.data().wasi_stdout.clone();
    Ok(PyodideBootOutput { stdout })
}

/// Run a `.py` program on the self-contained, zero-config runtime: the bundled
/// Pyodide 0.28.3 with numpy + pandas, or a `BURN_PYTHON_RUNTIME` override.
///
/// This is the entry point behind `burn run x.py`. It resolves the runtime via
/// [`resolve_runtime`] (so no env vars are needed on a normal build) and mounts
/// the bundled wheels, so `import numpy` / `import pandas` work out of the box.
///
/// # Errors
///
/// Returns `Err` when no runtime is available (neither bundled nor via
/// `BURN_PYTHON_RUNTIME`), or when boot / run traps. The message is actionable.
pub fn run_python(python_source: &str) -> Result<PyodideRunOutput> {
    let rt = resolve_runtime()?;
    run_pyodide_with(&rt, python_source)
}

/// Run a Python *package* on the self-contained, zero-config runtime (or a
/// `BURN_PYTHON_RUNTIME` override): mount the package's sibling modules into
/// the guest filesystem, prepend `pkg.sys_path_dir` to `sys.path`, and run
/// `entry_source` via `-c` - so a package whose entry does `import helper`
/// resolves the sibling.
///
/// This is the entry point behind `burn run <pkg.afb>` for a Python package.
/// It resolves the runtime via [`resolve_runtime`] (so no env vars are needed
/// on a normal build) and reuses the one canonical run core
/// ([`run_pyodide_package_with`]).
///
/// # Errors
///
/// Returns `Err` when no runtime is available (neither bundled nor via
/// `BURN_PYTHON_RUNTIME`), or when boot / run traps. The message is actionable.
pub fn run_python_package(entry_source: &str, pkg: &PyPackage) -> Result<PyodideRunOutput> {
    let rt = resolve_runtime()?;
    run_pyodide_package_with(&rt, entry_source, pkg)
}

/// Boot Pyodide, run `python -c <python_source>`, and return stdout + exit code.
///
/// The source string is passed verbatim as the `-c` argument to CPython.
/// Output from `print()` is captured via `EmbedderState::wasi_stdout` and
/// returned in [`PyodideRunOutput::stdout`].
///
/// This path mounts NO wheels (stdlib only) - it is the basic-Python entry the
/// REPL uses. For the zero-config numpy + pandas runtime behind `burn run`, use
/// [`run_python`].
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
    let rt = PyRuntime {
        wasm_path: PathBuf::from(wasm_path),
        stdlib_path: PathBuf::from(stdlib_zip_path),
        wheels: Vec::new(),
        python_xy: std::env::var("BURN_PYTHON_STDLIB_VER").unwrap_or_else(|_| "3.13".to_owned()),
    };
    run_pyodide_with(&rt, python_source)
}

/// A Python *package* to run: sibling `.py` modules to mount into the guest
/// in-memory filesystem, and the guest directory to add to `sys.path` so
/// `import sibling` resolves.
///
/// Built by `burn run <pkg.afb>` for a Python package: the unpacked `source/`
/// tree (entry + helpers) is mounted under [`Self::sys_path_dir`] and that dir
/// is prepended to `sys.path`.
pub struct PyPackage {
    /// Guest-absolute path -> file contents for every `.py` module in the
    /// package (the entry is run via `-c`, so it need not be listed here, but
    /// listing it is harmless). Mounted into the boot-time [`InMemFs`].
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
    /// Guest directory prepended to `sys.path` (e.g. `/pkg`). The package's
    /// modules in [`Self::files`] live under this directory.
    pub sys_path_dir: String,
}

/// Boot a resolved [`PyRuntime`], run `python -c <source>`, return stdout + exit
/// code. The one canonical run path; the public entry points are thin shims.
pub fn run_pyodide_with(rt: &PyRuntime, python_source: &str) -> Result<PyodideRunOutput> {
    run_pyodide_core(rt, python_source, None)
}

/// Run a Python *package* on a resolved [`PyRuntime`]: mount the package's
/// sibling modules into the guest filesystem, prepend its directory to
/// `sys.path`, and run `entry_source` via `-c` so `import helper` resolves a
/// sibling module.
///
/// Reuses the same boot + run-argv machinery as [`run_pyodide_with`] (one
/// canonical core); the only difference is the mounted package files and the
/// `sys.path` entry. This mirrors how the wheel path already injects `.py`
/// files into the boot-time [`InMemFs`] and lets CPython import them.
pub fn run_pyodide_package_with(
    rt: &PyRuntime,
    entry_source: &str,
    pkg: &PyPackage,
) -> Result<PyodideRunOutput> {
    run_pyodide_core(rt, entry_source, Some(pkg))
}

/// Shared boot + run core for [`run_pyodide_with`] and
/// [`run_pyodide_package_with`]. Boots the interpreter, optionally mounts a
/// package's sibling modules into the guest filesystem and prepends its
/// directory to `sys.path`, then runs `python_source` via `-c`.
fn run_pyodide_core(
    rt: &PyRuntime,
    python_source: &str,
    pkg: Option<&PyPackage>,
) -> Result<PyodideRunOutput> {
    let (mut store, instance, _got_globals) = boot_pyodide_instance(rt)?;
    // Clear any stdout emitted during boot before running user code.
    store.data_mut().wasi_stdout.clear();

    // Mount the package's sibling modules into the guest in-memory FS so
    // CPython's import machinery (which reads from this same FS the stdlib and
    // wheels are mounted into) can load them once the dir is on `sys.path`.
    if let Some(pkg) = pkg {
        for (guest_path, contents) in &pkg.files {
            store
                .data_mut()
                .fs
                .insert_file(guest_path, contents.clone());
        }
    }

    // In Pyodide's native (non-JS) build, `sys.stdout`/`sys.stderr` go through a
    // JS-backed IO layer that emits NOTHING to WASI - so `print()` output never
    // reaches `wasi_stdout`. Redirect both to a known guest file (line-buffered
    // so each print flushes) and read it back after the run. This is the only
    // capture that works for this build; it serves the basic path and numpy/
    // pandas alike.
    const STDOUT_REDIRECT: &[u8] =
        b"import sys as _sys; _f=open('/tmp/pyout.txt','w',buffering=1); _sys.stdout=_f; _sys.stderr=_f\n";

    // Build argv in wasm memory: ["python\0", "-c\0", <source>\0] + pointer table.
    // Layout (wasm32 = 4-byte pointers, little-endian):
    //   arg0_ptr -> "python\0"
    //   arg1_ptr -> "-c\0"
    //   arg2_ptr -> python_source with NUL terminator
    //   argv_ptr -> [arg0_ptr, arg1_ptr, arg2_ptr, 0]
    let arg0_ptr = alloc_cstr(&mut store, b"python\0")?;
    let arg1_ptr = alloc_cstr(&mut store, b"-c\0")?;

    // Prepend the redirect (and, for a package, a `sys.path` insert of its
    // directory so `import sibling` resolves), then NUL-terminate the combined
    // source string. `sys.path.insert(0, ...)` is prepended via the redirect
    // block, before any user import runs.
    let mut source_bytes = STDOUT_REDIRECT.to_vec();
    if let Some(pkg) = pkg {
        // The dir is a guest path with no embedded quote/newline (it is built
        // by the caller from the package mount constant + relative subdirs), so
        // a single-quoted Python literal is safe here.
        let sys_path_line = format!("_sys.path.insert(0, '{}')\n", pkg.sys_path_dir);
        source_bytes.extend_from_slice(sys_path_line.as_bytes());
    }
    source_bytes.extend_from_slice(python_source.as_bytes());
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
        return Ok(PyodideRunOutput {
            stdout: captured_stdout(&store),
            exit_code: main_exitcode,
        });
    }

    // run_main() in the Emscripten Pyodide build is a keepalive-marked cleanup
    // call; the actual -c code runs inside __main_argc_argv (which calls
    // Py_Main). Do NOT clear wasi_stdout here: the output from print() is
    // already captured from the __main_argc_argv call above.
    //
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

    Ok(PyodideRunOutput {
        stdout: captured_stdout(&store),
        exit_code,
    })
}

/// The program's captured output. Prefers the guest `/tmp/pyout.txt` (where the
/// injected redirect sends `sys.stdout`/`sys.stderr`); falls back to
/// `wasi_stdout` if the redirect file is empty (e.g. a future build that writes
/// straight to WASI).
fn captured_stdout(store: &Store<EmbedderState>) -> Vec<u8> {
    let from_file = store
        .data()
        .fs
        .read_file("/tmp/pyout.txt")
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    if from_file.is_empty() {
        store.data().wasi_stdout.clone()
    } else {
        from_file
    }
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

    /// End-to-end multi-file: a package whose entry imports a sibling module
    /// runs on the bundled (zero-config) runtime and prints the value computed
    /// via the sibling. Proves the package's `.py` files are mounted into the
    /// guest FS and its directory is on `sys.path`. LOUD-SKIPs (never fails)
    /// when no runtime was assembled in this build, so the suite stays green
    /// offline.
    #[test]
    fn run_python_package_resolves_sibling_import() {
        let rt = match resolve_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!("skip: no python runtime assembled in this build");
                return;
            }
        };

        // Mount a sibling module `helper.py` under the package's sys.path dir
        // and import it from the entry.
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "/pkg/source/helper.py".to_owned(),
            b"def square(n):\n    return n * n\n".to_vec(),
        );
        let pkg = PyPackage {
            files,
            sys_path_dir: "/pkg/source".to_owned(),
        };
        let entry = "from helper import square\nprint(f\"sq={square(9)}\")\n";

        let out = run_pyodide_package_with(&rt, entry, &pkg).expect("run_pyodide_package_with");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(out.exit_code, 0, "clean exit; stdout={text:?}");
        assert!(
            text.contains("sq=81"),
            "sibling import must resolve (9*9=81), got stdout={text:?}"
        );
    }
}
