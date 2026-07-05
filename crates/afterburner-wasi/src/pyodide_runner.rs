// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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

use afterburner_core::{
    AfterburnerError, Language, OutputTag, OutputValue, Result, RunResult, Session,
    decode_output_value, encode_frame,
};
use wasmtime::{
    Engine, FuncType, Global, GlobalType, Instance, Linker, Module, Mutability, Store, Tag,
    TagType, Val, ValType,
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
/// The version comes from the runtime descriptor (`PyRuntime::python_xy`), so a
/// 3.14 runtime mounts the 3.14 stdlib automatically with no configuration:
/// CPython searches `sys.prefix/lib/pythonXY.zip` and `sys.prefix/lib/pythonX.Y/`,
/// so the stdlib must be mounted under the exact version directory the binary was
/// built for. `BURN_PYTHON_STDLIB_VER` stays as an explicit override for a custom
/// runtime whose stdlib version differs from the descriptor.
fn python_stdlib_mount_paths(python_xy: &str) -> (String, String) {
    let ver = std::env::var("BURN_PYTHON_STDLIB_VER").unwrap_or_else(|_| python_xy.to_owned());
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
/// 2. The self-contained runtime under `~/.burn` (numpy + pandas included),
///    fetched lazily on first use ([`crate::pyodide_bundle::resolve`]). This is
///    the default path; it fires on the CLI AND on a programmatic embed that
///    calls `resolve_runtime` directly.
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
        "python runtime not found. The runtime could not be fetched into ~/.burn on first use \
         (no network, or `wasm-opt` (Binaryen) is not installed for the local translate step); \
         set BURN_PYTHON_RUNTIME=<dir> with pyodide-exnref.wasm and python_stdlib.zip, or install \
         Binaryen and re-run with network access."
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

/// Whether a `.dist-info/` entry is one `importlib.metadata` reads at runtime.
///
/// `importlib.metadata.version("pkg")` / `metadata("pkg")` / `entry_points()`
/// open `METADATA` and `entry_points.txt` inside the package's `.dist-info`. A
/// package that checks its own version at import (duckdb, bokeh, h3, imageio,
/// xarray, ...) raises `PackageNotFoundError` if these are missing. We mount
/// exactly these two and skip the bulky rest of `.dist-info` (`RECORD`, `WHEEL`,
/// `licenses/`, the signature files), which nothing imports.
fn is_metadata_entry(name: &str) -> bool {
    name.ends_with(".dist-info/METADATA") || name.ends_with(".dist-info/entry_points.txt")
}

/// Mount every file in a wheel (a zip of `.py` + `.so`) into `fs` under
/// `guest_prefix`. Skips directory entries and the bulk of `.dist-info`, but
/// keeps the two metadata files `importlib.metadata` reads (see
/// [`is_metadata_entry`]). Returns the count mounted. Supports the two zip
/// methods Pyodide wheels use: 0 (stored) and 8 (deflate).
fn mount_wheel(fs: &mut InMemFs, wheel: std::sync::Arc<[u8]>, guest_prefix: &str) -> usize {
    // #23: index each wheel entry lazily against the shared `wheel` blob; the
    // bytes decompress on first read, so an unimported numpy/pandas never pays.
    let wheel_bytes: &[u8] = &wheel;
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
        let uncomp_size =
            u32::from_le_bytes(wheel_bytes[pos + 22..pos + 26].try_into().unwrap()) as usize;
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
        if name.ends_with('/') || (name.contains(".dist-info") && !is_metadata_entry(&name)) {
            pos = data_end;
            continue;
        }
        match method {
            0 | 8 => {
                fs.insert_lazy_file(
                    &format!("{guest_prefix}/{name}"),
                    wheel.clone(),
                    data_start,
                    comp_size,
                    method,
                    uncomp_size,
                );
                count += 1;
            }
            _ => {
                pos = data_end;
                continue;
            }
        }
        pos = data_end;
    }
    count
}

/// Load the compiled CPython module from its on-disk cwasm cache, compiling and
/// persisting it on a miss (#56/#62).
///
/// Cranelift-compiling the ~25-34 MiB runtime is the bulk of Python cold start.
/// The cwasm sits next to the wasm (same version-pinned dir, so the source is
/// immutable per version); it is trusted only when at least as new as the wasm
/// AND accepted by wasmtime's own version/config header check - any mismatch,
/// staleness, or corruption falls back to a fresh compile + atomic rewrite.
fn load_or_compile_pyodide_module(
    engine: &Engine,
    wasm_path: &std::path::Path,
    wasm_bytes: &[u8],
) -> Result<Module> {
    let cwasm_path = wasm_path.with_extension("cwasm");

    // Trust the cache only if it is at least as new as the wasm it was built
    // from (a cheap stat, no re-hash of the 25 MiB source).
    let cwasm_fresh = std::fs::metadata(&cwasm_path)
        .and_then(|m| m.modified())
        .ok()
        .zip(std::fs::metadata(wasm_path).and_then(|m| m.modified()).ok())
        .is_some_and(|(cwasm, wasm)| cwasm >= wasm);

    if cwasm_fresh {
        // SAFETY: the artifact is one we produced via `Module::serialize` with
        // this same engine config; wasmtime validates its version/config header
        // and returns Err on any mismatch (then we recompile), so a foreign or
        // stale artifact can never be executed as code.
        if let Ok(module) = unsafe { Module::deserialize_file(engine, &cwasm_path) } {
            return Ok(module);
        }
    }

    let module = Module::new(engine, wasm_bytes)
        .map_err(|e| AfterburnerError::Engine(format!("compile python runtime: {e}")))?;

    // Best-effort persist: write a per-process temp then atomically rename, so a
    // concurrent boot never observes a half-written cwasm. A failed write just
    // recompiles next time.
    if let Ok(serialized) = module.serialize() {
        let tmp = cwasm_path.with_extension(format!("cwasm.tmp.{}", std::process::id()));
        if std::fs::write(&tmp, &serialized).is_ok() {
            let _ = std::fs::rename(&tmp, &cwasm_path);
        }
    }

    Ok(module)
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
///
/// `stdout` / `stderr` are byte-exact: the Python process writes them to
/// separate binary sinks (`/.afb/stdout.bin`, `/.afb/stderr.bin`) in the guest
/// [`InMemFs`], read back verbatim (a PNG or audio bytes on stdout survive
/// bit-for-bit; no UTF-8-lossy text redirect). `output` is the program's typed
/// return value, carried across the guest/host boundary as an `"AFBF"` frame
/// written to `/.afb/output.frame` (decoded by the crate-private
/// `captured_output`); it is [`OutputValue::Json`]`(Value::Null)` when the
/// program surfaced no value.
pub struct PyodideRunOutput {
    /// Bytes the Python process wrote to stdout, byte-exact.
    pub stdout: Vec<u8>,
    /// Bytes the Python process wrote to stderr, byte-exact. Empty on a run
    /// that wrote nothing to stderr.
    pub stderr: Vec<u8>,
    /// Exit code returned by `run_main()` / `pymain_run_python()`.
    pub exit_code: i32,
    /// The program's typed return value (via `__afb_emit__`), or
    /// `Json(Null)` when none was surfaced.
    pub output: OutputValue,
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
///
/// `extra_wheel_bytes` are vendored wheels from a package's `vendor/pip/`
/// archive members (already loaded into memory by the unpack path). They are
/// appended to the runtime wheel set and mounted into the same
/// `/lib/python<xy>/site-packages` guest directory, so `import <pkg>` resolves
/// them exactly as it does the bundled numpy/pandas set. Callers pass an empty
/// slice when running without a package (the `boot_pyodide` / `run_pyodide_source`
/// paths).
fn boot_pyodide_instance(
    rt: &PyRuntime,
    extra_wheel_bytes: &[Vec<u8>],
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
    // #56/#62: Cranelift-compiling the ~25-34 MiB CPython runtime dominates cold
    // start. Compile it once, persist the artifact as a cwasm next to the wasm,
    // and mmap-deserialize it on every subsequent boot.
    let module = load_or_compile_pyodide_module(&engine, &rt.wasm_path, &wasm_bytes)?;

    let mut linker: Linker<EmbedderState> = Linker::new(&engine);
    linker.allow_shadowing(true);

    wire_wasi_only(&mut linker)?;
    wire_invoke_trampolines(&engine, &mut linker)?;

    let mech_log = MechCallLog::new();
    wire_fs_env_funcs(&mut linker, mech_log)?;
    wire_pyodide028_env_stubs(&engine, &mut linker)?;
    // libffi (ctypes) + file-backed mmap host functions. Wired before the no-op
    // fill so ctypes-linking modules (`_ctypes`, used by polars._cpu_check,
    // numpy._core._internal, pandas) get a working ffi_closure_alloc / ffi_call
    // instead of a NULL-returning no-op stub (which surfaces as MemoryError).
    crate::emscripten_ffi::wire_emscripten_ffi(&engine, &mut linker)?;

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
        let (zip_mount, dir_mount) = python_stdlib_mount_paths(&rt.python_xy);
        // Share one compressed blob between the mounted .zip and every lazy
        // entry extracted from it (#23); nothing decompresses until first read.
        let zip: std::sync::Arc<[u8]> = std::sync::Arc::from(zip_bytes);
        let zip_len = zip.len();
        store
            .data_mut()
            .fs
            .insert_lazy_file(&zip_mount, zip.clone(), 0, zip_len, 0, zip_len);
        let _ = mount_zip_into_fs(&mut store.data_mut().fs, &dir_mount, zip);
    }
    store.data_mut().fs.mkdir_p("/tmp");
    // HOME (exposed via environ_get) must exist so a package that writes its
    // cache/config under ~ at import (parso, jedi) can create directories there.
    store.data_mut().fs.mkdir_p("/home/burn");

    // Mount every wheel's `.py` + `.so` into guest site-packages. Each `.so`
    // lands in MEMFS and is dlopen'd on demand; numpy's core `.so` is pre-loaded
    // below (CPython expects it from the first dlopen). Vendored wheels from the
    // package's `vendor/pip/` archive members are appended after the runtime set
    // so `import <pkg>` resolves them exactly as the built-in numpy/pandas set.
    let has_extra = !extra_wheel_bytes.is_empty();
    if has_wheels || has_extra {
        let site_pkgs = site_packages(&rt.python_xy);
        for bytes in wheel_blobs {
            mount_wheel(&mut store.data_mut().fs, std::sync::Arc::from(bytes), &site_pkgs);
        }
        for bytes in extra_wheel_bytes {
            mount_wheel(
                &mut store.data_mut().fs,
                std::sync::Arc::from(bytes.clone()),
                &site_pkgs,
            );
        }
    }

    wire_got_func_stubs_from_module(&mut store, &mut linker, &module)?;

    // Wire `_dlopen_js` / `_dlsym_js` before the noop fill so Python's dlopen
    // dispatch reaches the side-module registry rather than a noop returning 0.
    // Needed when any wheels are present (runtime set or vendored extras), since
    // they may contain `.so` side modules. The stdlib-only path leaves this out
    // to keep its import set exactly as before.
    let any_wheels = has_wheels || has_extra;
    if any_wheels {
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
    if any_wheels {
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
    if any_wheels && let Some(f) = instance.get_func(&mut store, "emscripten_stack_init") {
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
    let (store, _instance, _got_globals) = boot_pyodide_instance(&rt, &[])?;
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

/// Run a `.py` program on the self-contained runtime with a record/replay host
/// attached (R1 effect capture): the emscripten effect seams record every
/// host-mediated effect (fs/env/...) into `host_context`, retrievable via its
/// `get_effect_log`. The sealed [`run_python`] leaves the seams off (the hot
/// path pays nothing when no host is attached).
///
/// # Errors
///
/// Returns `Err` when no runtime is available, or when boot / run traps.
pub fn run_python_with_host(
    python_source: &str,
    host_context: std::sync::Arc<dyn afterburner_core::HostContext>,
) -> Result<PyodideRunOutput> {
    let rt = resolve_runtime()?;
    run_pyodide_with_host(&rt, python_source, host_context)
}

/// Run a `.py` program on the self-contained runtime with host-filesystem
/// read-write preopens, returning stdout + exit code.
///
/// Each `rw_preopens` entry is a `(host_path, guest_path)` pair. A Python file
/// syscall to a guest path under a declared preopen is routed to the
/// corresponding directory on the real host filesystem rather than the in-memory
/// FS, so state written in one invocation persists for the next. Paths not
/// covered by any preopen remain sealed in the in-memory FS (deny-by-default).
///
/// # Errors
///
/// Returns `Err` when no runtime is available, or when boot / run traps.
pub fn run_python_with_preopens(
    python_source: &str,
    rw_preopens: &[(std::path::PathBuf, String)],
) -> Result<PyodideRunOutput> {
    let rt = resolve_runtime()?;
    run_pyodide_with_preopens(&rt, python_source, rw_preopens)
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

/// Run many Python programs on ONE warmed interpreter (#53 warm-interpreter
/// reuse): resolve the runtime, pay the ~490 ms boot + CPython `site`/stdlib
/// bringup once, then run each source via `PyRun_SimpleString` (~0 ms bringup
/// each). Each source runs in a fresh module namespace, so globals do not leak
/// between them. See [`run_pyodide_batch`].
///
/// # Errors
///
/// Returns `Err` when no runtime is available, or when boot / a run traps.
pub fn run_python_batch(sources: &[&str]) -> Result<Vec<PyodideRunOutput>> {
    let rt = resolve_runtime()?;
    run_pyodide_batch(&rt, sources)
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

// ---- daemon-capable Python run (N1 sockets + N2 threads + N3 durable FS) ----

/// Options for running Python with real OS capabilities (section 15 acceptance
/// surface). Requires the `daemon` feature; sealed runs use `run_python` instead.
///
/// All fields default to `None` / empty (deny-by-default). Callers opt in
/// explicitly to each capability so the security posture stays deny-by-default.
#[cfg(feature = "daemon")]
pub struct PythonNetOpts {
    /// A running tokio runtime handle. `DaemonNet` and the blocking socket
    /// bridge both require an async runtime; callers supply one so they control
    /// its lifecycle (thread count, shutdown). A `Builder::new_multi_thread`
    /// with `enable_all()` is the right choice for a webserver acceptance test.
    pub tokio_handle: tokio::runtime::Handle,
    /// Manifold that grants the capabilities this run needs. Use
    /// `Manifold::open()` for a fully-open test run; narrow it for production.
    /// `Manifold::sealed()` (the default) denies all socket and thread ops.
    pub manifold: afterburner_core::Manifold,
    /// Read-write host-filesystem preopens: `(host_path, guest_path)` pairs.
    /// A Python path under a declared guest prefix is routed to the real
    /// host FS instead of the in-memory FS. Empty = no durable FS access.
    pub rw_preopens: Vec<(std::path::PathBuf, String)>,
    /// Optional record/replay host. When set, the emscripten effect seams
    /// journal every host-mediated effect (R1) into it (retrievable via
    /// `get_effect_log`); on replay it serves recorded results. `None` (the
    /// default) = no capture, seams stay off.
    pub host_context: Option<std::sync::Arc<dyn afterburner_core::HostContext>>,
}

/// Run Python with real OS capabilities: server sockets (N1), real threads via
/// the process-isolation model (N2), and host-backed durable FS (N3).
///
/// This is the daemon-mode entry point behind the section-15 acceptance bar
/// (plan `CONCURRENCY_AND_NETWORK_SURFACE_DESIGN.md` section 15). It wires
/// `DaemonNet`, `DaemonWorkers`, and `DaemonSab` into the store so Python's
/// socket syscalls and pthread shims reach the real OS rather than returning
/// `EPERM`. The `tokio_handle` in `opts` is the async runtime the socket
/// bridge uses for `block_on` calls.
///
/// # Errors
///
/// Returns `Err` when no runtime is available or when boot / run traps.
#[cfg(feature = "daemon")]
pub fn run_python_with_net(python_source: &str, opts: PythonNetOpts) -> Result<PyodideRunOutput> {
    let rt = resolve_runtime()?;
    let daemon_net =
        crate::daemon_net::DaemonNet::new(opts.tokio_handle.clone(), opts.manifold.clone());
    let daemon_workers = crate::daemon_workers::DaemonWorkers::new_parent(
        opts.manifold.clone(),
        crate::daemon_workers::WorkerConfig::default(),
    );
    let daemon_sab = crate::daemon_sab::DaemonSab::new();
    let daemon_dgram_py =
        crate::daemon_dgram::DaemonDgram::new(opts.tokio_handle.clone(), opts.manifold.clone());
    #[cfg(unix)]
    let daemon_unix = crate::daemon_unix::DaemonUnix::new(opts.tokio_handle.clone());
    run_pyodide_with_daemon(
        &rt,
        python_source,
        &opts.rw_preopens,
        opts.host_context,
        opts.manifold,
        daemon_net,
        daemon_workers,
        daemon_sab,
        daemon_dgram_py,
        #[cfg(unix)]
        daemon_unix,
    )
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
    /// Vendored Python wheels from `vendor/pip/` archive members (FORMAT_MINOR >= 3).
    /// Each entry is the raw `.whl` bytes (a zip). During boot they are mounted
    /// into site-packages via `mount_wheel` before CPython's import machinery
    /// activates, so `import <pkg>` resolves them exactly as the bundled numpy/pandas
    /// set. Empty for packages with no `[pip]` dependencies.
    pub vendor_pip_wheels: Vec<Vec<u8>>,
}

/// Boot a resolved [`PyRuntime`], run `python -c <source>`, return stdout + exit
/// code. The one canonical run path; the public entry points are thin shims.
pub fn run_pyodide_with(rt: &PyRuntime, python_source: &str) -> Result<PyodideRunOutput> {
    run_pyodide_core(rt, python_source, None, &[], None)
}

/// Boot a resolved [`PyRuntime`] and run `python -c <source>` with a record/replay
/// host attached so the emscripten effect seams capture host-mediated effects
/// (R1) into `host_context`. The sealed [`run_pyodide_with`] leaves the seams off.
pub fn run_pyodide_with_host(
    rt: &PyRuntime,
    python_source: &str,
    host_context: std::sync::Arc<dyn afterburner_core::HostContext>,
) -> Result<PyodideRunOutput> {
    run_pyodide_core(rt, python_source, None, &[], Some(host_context))
}

/// Boot a resolved [`PyRuntime`], run `python -c <source>` with host-filesystem
/// read-write preopens, return stdout + exit code.
///
/// Each `rw_preopens` entry is a `(host_path, guest_path)` pair: a Python file
/// syscall to `guest_path` (or any path under it) is routed to the corresponding
/// `host_path` on the real host filesystem instead of the in-memory FS. Paths
/// not covered by any preopen remain in the in-memory FS (deny-by-default).
///
/// This is the entry point for durable-FS use cases (e.g. a SQLite database that
/// must persist across Python invocations). The replay journal (D3/D4 from the
/// design doc) is deferred to causarum and is NOT built here.
pub fn run_pyodide_with_preopens(
    rt: &PyRuntime,
    python_source: &str,
    rw_preopens: &[(std::path::PathBuf, String)],
) -> Result<PyodideRunOutput> {
    run_pyodide_core(rt, python_source, None, rw_preopens, None)
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
    run_pyodide_core(rt, entry_source, Some(pkg), &[], None)
}

/// Shared boot + run core for [`run_pyodide_with`], [`run_pyodide_with_preopens`],
/// and [`run_pyodide_package_with`]. Boots the interpreter, optionally mounts a
/// package's sibling modules into the guest filesystem and prepends its directory
/// to `sys.path`, installs any rw-preopens into the store state, then runs
/// `python_source` via `-c`.
fn run_pyodide_core(
    rt: &PyRuntime,
    python_source: &str,
    pkg: Option<&PyPackage>,
    rw_preopens: &[(std::path::PathBuf, String)],
    host_context: Option<std::sync::Arc<dyn afterburner_core::HostContext>>,
) -> Result<PyodideRunOutput> {
    // Collect vendored wheels from the package (if any) so they are mounted into
    // site-packages during boot, before CPython's import machinery is active.
    let vendor_wheels: &[Vec<u8>] = pkg
        .map(|p| p.vendor_pip_wheels.as_slice())
        .unwrap_or_default();
    let (mut store, instance, _got_globals) = boot_pyodide_instance(rt, vendor_wheels)?;
    // Clear any stdout emitted during boot before running user code.
    store.data_mut().wasi_stdout.clear();
    // Install host-FS preopens into the store so the Emscripten FS syscall
    // handlers can route guest paths to the real host filesystem.
    if !rw_preopens.is_empty() {
        crate::pyo_trace!("[run_pyodide_core] setting rw_preopens={rw_preopens:?}");
        store.data_mut().rw_preopens = rw_preopens.to_vec();
    }
    // Thread the record/replay host into the store so the emscripten effect
    // seams (FsSeam) capture/serve host-mediated effects (R1). `None` = a sealed
    // run: the seams stay off and the hot path pays nothing.
    store.data_mut().host_context = host_context;

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

    run_booted_pyodide(python_source, pkg, &mut store, &instance)
}

/// Execute `python_source` on a already-booted (post-ctors) interpreter
/// instance. Both `run_pyodide_core` and the daemon-capable path share this
/// so the argv-build + run-main logic lives in one place (DRY).
///
/// Caller is responsible for having already cleared `wasi_stdout`, installed
/// rw-preopens, and wired any daemon coordinators into `store` before calling.
fn run_booted_pyodide(
    python_source: &str,
    pkg: Option<&PyPackage>,
    store: &mut Store<EmbedderState>,
    instance: &Instance,
) -> Result<PyodideRunOutput> {
    // In Pyodide's native (non-JS) build, `sys.stdout`/`sys.stderr` go through a
    // JS-backed IO layer that emits NOTHING to WASI - so `print()` output never
    // reaches `wasi_stdout`. Redirect each to its OWN BINARY sink in the guest
    // InMemFs (`/.afb/stdout.bin`, `/.afb/stderr.bin`) opened `wb` with
    // `buffering=0` (raw, unbuffered): every write lands byte-exact and
    // immediately in the FS node, so a PNG or audio bytes written to
    // `sys.stdout.buffer` survive bit-for-bit (the old text `/tmp/pyout.txt`
    // redirect mangled binary and merged the two streams). `print()` still works
    // via a `write_through` `TextIOWrapper` that encodes UTF-8 straight into the
    // raw sink. `__afb_emit__(value)` records the program's typed return; the
    // appended `OUTPUT_POSTAMBLE` serializes it to `/.afb/output.frame`.
    const STDOUT_REDIRECT: &[u8] = concat!(
        "import sys as _sys, io as _io, os as _os, builtins as _b\n",
        "_os.makedirs('/.afb', exist_ok=True)\n",
        "_afb_o = open('/.afb/stdout.bin', 'wb', buffering=0)\n",
        "_afb_e = open('/.afb/stderr.bin', 'wb', buffering=0)\n",
        "_sys.stdout = _io.TextIOWrapper(_afb_o, encoding='utf-8', write_through=True)\n",
        "_sys.stderr = _io.TextIOWrapper(_afb_e, encoding='utf-8', errors='backslashreplace', write_through=True)\n",
        "_afb_out = [False, None]\n",
        "def __afb_emit__(v):\n",
        " _afb_out[0]=True; _afb_out[1]=v\n",
        "_b.__afb_emit__ = __afb_emit__\n",
    )
    .as_bytes();

    // Appended AFTER the user program (top level): flush the sinks, and if the
    // program called `__afb_emit__`, serialize its value to
    // `/.afb/output.frame` as `[kind_byte] + payload` (kind 1 = raw bytes,
    // kind 0 = UTF-8 JSON). The host reads this in `captured_output` and lifts
    // it through afterburner-core's `"AFBF"` frame codec into an `OutputValue`.
    // Leading `\n` guards against a user source with no trailing newline. If the
    // program raised, this does not run: the frame is absent (`output = Null`)
    // but stdout/stderr were already captured (the sinks are unbuffered).
    const OUTPUT_POSTAMBLE: &[u8] = concat!(
        "\n",
        "def __afb_finalize__():\n",
        " import sys as _s, os as _o, json as _j\n",
        " try:\n",
        "  _s.stdout.flush()\n",
        " except Exception:\n",
        "  pass\n",
        " try:\n",
        "  _s.stderr.flush()\n",
        " except Exception:\n",
        "  pass\n",
        " if not _afb_out[0]:\n",
        "  return\n",
        " v = _afb_out[1]\n",
        " if isinstance(v, (bytes, bytearray, memoryview)):\n",
        "  payload = bytes(v); kind = 1\n",
        " else:\n",
        "  payload = _j.dumps(v).encode('utf-8'); kind = 0\n",
        " fd = _o.open('/.afb/output.frame', _o.O_WRONLY | _o.O_CREAT | _o.O_TRUNC, 0o644)\n",
        " _o.write(fd, bytes([kind]) + payload)\n",
        " _o.close(fd)\n",
        "__afb_finalize__()\n",
    )
    .as_bytes();

    // Build argv in wasm memory: ["python\0", "-c\0", <source>\0] + pointer table.
    // Layout (wasm32 = 4-byte pointers, little-endian):
    //   arg0_ptr -> "python\0"
    //   arg1_ptr -> "-c\0"
    //   arg2_ptr -> python_source with NUL terminator
    //   argv_ptr -> [arg0_ptr, arg1_ptr, arg2_ptr, 0]
    let arg0_ptr = alloc_cstr(&mut *store, b"python\0")?;
    let arg1_ptr = alloc_cstr(&mut *store, b"-c\0")?;

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
    source_bytes.extend_from_slice(OUTPUT_POSTAMBLE);
    source_bytes.push(0);
    let arg2_ptr = alloc_cstr(&mut *store, &source_bytes)?;

    let argv_ptr = alloc_argv_table(&mut *store, arg0_ptr, arg1_ptr, arg2_ptr)?;

    // __main_argc_argv(argc=3, argv=argv_ptr): calls Py_Initialize with -c argv.
    // MUST be called EXACTLY ONCE; CPython is not initialized after __wasm_call_ctors.
    let main_fn = instance
        .get_func(&mut *store, "__main_argc_argv")
        .ok_or_else(|| {
            AfterburnerError::Engine(
                "__main_argc_argv not exported; cannot initialize CPython".into(),
            )
        })?;

    let mut main_ret = [wasmtime::Val::I32(-99)];
    main_fn
        .call(
            &mut *store,
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
            stdout: captured_stdout(store),
            stderr: captured_stderr(store),
            exit_code: main_exitcode,
            output: captured_output(store)?,
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
        .get_func(&mut *store, "run_main")
        .or_else(|| instance.get_func(&mut *store, "pymain_run_python"))
        .ok_or_else(|| {
            AfterburnerError::Engine(
                "neither run_main nor pymain_run_python exported by the python runtime".into(),
            )
        })?;

    let mut run_ret = [wasmtime::Val::I32(-99)];
    run_fn
        .call(&mut *store, &[], &mut run_ret)
        .map_err(|e| AfterburnerError::Engine(format!("run_main trapped: {e}")))?;

    let exit_code = match run_ret[0] {
        wasmtime::Val::I32(v) => v,
        _ => -99,
    };

    // Determinism probe: print fuel consumed (set budget minus remaining) when
    // BURN_FUEL_REPORT is set. The engine runs with consume_fuel(true), so this
    // is an exact, reproducible instruction count for a deterministic run.
    if std::env::var_os("BURN_FUEL_REPORT").is_some()
        && let Ok(remaining) = store.get_fuel()
    {
        eprintln!("[fuel] consumed={}", PYODIDE_FUEL.saturating_sub(remaining));
    }

    Ok(PyodideRunOutput {
        stdout: captured_stdout(store),
        stderr: captured_stderr(store),
        exit_code,
        output: captured_output(store)?,
    })
}

/// Guest driver run via `PyRun_SimpleString` on an already-warm interpreter: it
/// resets the capture state, runs the user script (written to `/.afb/script.py`
/// by the host) in a FRESH module namespace so globals never leak between
/// thrusts, and finalizes the output frame - all by reusing the
/// `__afb_finalize__` / `_afb_out` / `_afb_o` / `_afb_e` machinery installed
/// once by the warmup's `STDOUT_REDIRECT`. The driver is fixed (reads the source
/// from a file), so its wasm pointer is allocated once and reused per thrust.
const WARM_DRIVER: &[u8] = concat!(
    "_afb_out[0]=False\n",
    "_afb_out[1]=None\n",
    // The InMemFs has no ftruncate, so reset each sink by REOPENING it 'wb'
    // (O_TRUNC clears the node, which is wired); CPython refcounting closes the
    // previous handles at once, so no guest fd leaks per thrust.
    "_afb_o=open('/.afb/stdout.bin','wb',buffering=0)\n",
    "_afb_e=open('/.afb/stderr.bin','wb',buffering=0)\n",
    "_sys.stdout=_io.TextIOWrapper(_afb_o,encoding='utf-8',write_through=True)\n",
    "_sys.stderr=_io.TextIOWrapper(_afb_e,encoding='utf-8',errors='backslashreplace',write_through=True)\n",
    "try:\n",
    " _afb_ns={'__name__':'__main__','__builtins__':__builtins__}\n",
    " exec(compile(open('/.afb/script.py','rb').read(),'/.afb/script.py','exec'),_afb_ns)\n",
    "except BaseException as _exc:\n",
    " _sys.stderr.write(type(_exc).__name__ + ': ' + str(_exc) + '\\n')\n",
    "finally:\n",
    " __afb_finalize__()\n",
    "\0"
)
.as_bytes();

/// Like [`WARM_DRIVER`] but runs the user source in a PERSISTENT namespace
/// (`_afb_repl_ns`, created lazily once) so state carries across calls - the
/// semantics a REPL needs (define a name, use it on the next line). Compiled in
/// `exec` mode; expression echoing is the caller's concern (the REPL wraps a
/// bare expression in `print(repr(...))`).
const WARM_REPL_DRIVER: &[u8] = concat!(
    "_afb_out[0]=False\n",
    "_afb_out[1]=None\n",
    "_afb_o=open('/.afb/stdout.bin','wb',buffering=0)\n",
    "_afb_e=open('/.afb/stderr.bin','wb',buffering=0)\n",
    "_sys.stdout=_io.TextIOWrapper(_afb_o,encoding='utf-8',write_through=True)\n",
    "_sys.stderr=_io.TextIOWrapper(_afb_e,encoding='utf-8',errors='backslashreplace',write_through=True)\n",
    "try:\n _afb_repl_ns\n",
    "except NameError:\n _afb_repl_ns={'__name__':'__main__','__builtins__':__builtins__}\n",
    "try:\n",
    " exec(compile(open('/.afb/script.py','rb').read(),'<repl>','exec'),_afb_repl_ns)\n",
    "except BaseException as _exc:\n",
    " _sys.stderr.write(type(_exc).__name__ + ': ' + str(_exc) + '\\n')\n",
    "finally:\n",
    " __afb_finalize__()\n",
    "\0"
)
.as_bytes();

/// Drop the persistent REPL namespace so the next persistent run rebuilds a
/// fresh one (a REPL `:clear`). Runs directly in `__main__` (not redirected into
/// a namespace) so `del` targets the module global.
const WARM_REPL_RESET: &[u8] = b"try:\n del _afb_repl_ns\nexcept NameError:\n pass\n\0";

/// A booted + warmed CPython interpreter that runs many Python programs without
/// paying the ~490 ms boot + `site`/stdlib bringup again (#53 warm reuse).
///
/// Holds the live wasmtime `Store` + `Instance`, so it is single-threaded: keep
/// and drive it from ONE thread (a REPL session, a batch loop). Each run resets
/// the `/.afb` capture sinks and runs via `PyRun_SimpleString` (~0 ms bringup).
///
/// Two run modes:
/// - [`run_isolated`](Self::run_isolated): each program in a FRESH namespace
///   (no leakage between programs) - for batch execution.
/// - [`run_persistent`](Self::run_persistent): programs share ONE namespace
///   (state carries across calls) - for a REPL.
///
/// Note: a program that raises is caught and its traceback captured to stderr,
/// with `exit_code` 0 and an absent output frame (`output = Null`); the cold
/// path instead surfaces a non-zero exit code.
pub struct WarmPyInterpreter {
    store: Store<EmbedderState>,
    #[allow(dead_code)]
    instance: Instance,
    pyrun: wasmtime::Func,
    driver_isolated: u32,
    driver_persistent: u32,
    driver_reset: u32,
}

impl WarmPyInterpreter {
    /// Boot + warm an interpreter on `rt`. Pays the full boot + bringup once.
    pub fn boot(rt: &PyRuntime) -> Result<Self> {
        let (mut store, instance, _got) = boot_pyodide_instance(rt, &[])?;
        // Warm once: Py_Initialize + site/stdlib import + install the capture
        // machinery (which then persists for every run below). The `pass`
        // program's own (empty) output is discarded.
        let _ = run_booted_pyodide("pass", None, &mut store, &instance)?;

        let pyrun = instance.get_func(&mut store, "PyRun_SimpleString").ok_or_else(|| {
            AfterburnerError::Engine("PyRun_SimpleString not exported by the python runtime".into())
        })?;
        // Allocate the fixed drivers once; reuse their pointers for every run so
        // no wasm page grows per program.
        let driver_isolated = alloc_cstr(&mut store, WARM_DRIVER)?;
        let driver_persistent = alloc_cstr(&mut store, WARM_REPL_DRIVER)?;
        let driver_reset = alloc_cstr(&mut store, WARM_REPL_RESET)?;
        Ok(Self {
            store,
            instance,
            pyrun,
            driver_isolated,
            driver_persistent,
            driver_reset,
        })
    }

    /// Boot + warm an interpreter on the resolved runtime (bundle or
    /// `BURN_PYTHON_RUNTIME`).
    pub fn boot_resolved() -> Result<Self> {
        let rt = resolve_runtime()?;
        Self::boot(&rt)
    }

    /// Run `source` in a FRESH namespace (isolation between calls).
    pub fn run_isolated(&mut self, source: &str) -> Result<PyodideRunOutput> {
        let driver = self.driver_isolated;
        self.run_via(source, driver)
    }

    /// Run `source` in the PERSISTENT namespace (state carries across calls).
    pub fn run_persistent(&mut self, source: &str) -> Result<PyodideRunOutput> {
        let driver = self.driver_persistent;
        self.run_via(source, driver)
    }

    /// Drop the persistent namespace so the next [`run_persistent`](Self::run_persistent)
    /// starts fresh (a REPL `:clear`).
    pub fn reset_persistent(&mut self) -> Result<()> {
        let mut ret = [wasmtime::Val::I32(-1)];
        self.pyrun
            .call(
                &mut self.store,
                &[wasmtime::Val::I32(self.driver_reset as i32)],
                &mut ret,
            )
            .map_err(|e| AfterburnerError::Engine(format!("warm reset trapped: {e}")))?;
        Ok(())
    }

    fn run_via(&mut self, source: &str, driver_ptr: u32) -> Result<PyodideRunOutput> {
        let store = &mut self.store;
        store.data_mut().wasi_stdout.clear();
        // Fresh fuel per run; the warm store accumulates consumption otherwise.
        let _ = store.set_fuel(PYODIDE_FUEL);
        // Hand the user source to the guest via a file so the fixed driver execs
        // it - no per-run wasm allocation, no source escaping.
        store
            .data_mut()
            .fs
            .insert_file("/.afb/script.py", source.as_bytes().to_vec());

        let mut ret = [wasmtime::Val::I32(-1)];
        self.pyrun
            .call(&mut *store, &[wasmtime::Val::I32(driver_ptr as i32)], &mut ret)
            .map_err(|e| {
                AfterburnerError::Engine(format!("warm PyRun_SimpleString trapped: {e}"))
            })?;
        let exit_code = match ret[0] {
            wasmtime::Val::I32(v) => v,
            _ => -99,
        };
        Ok(PyodideRunOutput {
            stdout: captured_stdout(store),
            stderr: captured_stderr(store),
            exit_code,
            output: captured_output(store)?,
        })
    }
}

/// Run many Python sources on ONE interpreter (#53 warm-interpreter reuse): pay
/// the ~490 ms boot + CPython `site`/stdlib bringup ONCE, then run each source
/// via `PyRun_SimpleString` (~0 ms bringup each). Each source runs in a fresh
/// module namespace, so globals do not leak between them.
pub fn run_pyodide_batch(rt: &PyRuntime, sources: &[&str]) -> Result<Vec<PyodideRunOutput>> {
    let mut interp = WarmPyInterpreter::boot(rt)?;
    sources.iter().map(|s| interp.run_isolated(s)).collect()
}

/// Daemon-capable boot + run: boots the interpreter, wires the daemon
/// coordinators for real socket + thread access, installs rw-preopens, then
/// runs `python_source` via `-c`. Called by [`run_python_with_net`].
///
/// Separated from `run_pyodide_core` so the sealed path carries no dependency
/// on daemon types. The two functions share `run_booted_pyodide` for the
/// post-boot execution logic (DRY: argv build, `__main_argc_argv`, `run_main`).
// All args are coordinators wired to the store; grouping into a struct would
// just move the count without reducing it. vertexia: consider DaemonBundle if
// more coordinators are added.
#[cfg(feature = "daemon")]
#[allow(clippy::too_many_arguments)]
fn run_pyodide_with_daemon(
    rt: &PyRuntime,
    python_source: &str,
    rw_preopens: &[(std::path::PathBuf, String)],
    host_context: Option<std::sync::Arc<dyn afterburner_core::HostContext>>,
    manifold: afterburner_core::Manifold,
    daemon_net: std::sync::Arc<crate::daemon_net::DaemonNet>,
    daemon_workers: std::sync::Arc<crate::daemon_workers::DaemonWorkers>,
    daemon_sab: std::sync::Arc<crate::daemon_sab::DaemonSab>,
    daemon_dgram_py: std::sync::Arc<crate::daemon_dgram::DaemonDgram>,
    #[cfg(unix)] daemon_unix: std::sync::Arc<crate::daemon_unix::DaemonUnix>,
) -> Result<PyodideRunOutput> {
    let (mut store, instance, _got_globals) = boot_pyodide_instance(rt, &[])?;
    store.data_mut().wasi_stdout.clear();
    // Wire the daemon coordinators so socket and pthread shims reach the OS.
    store.data_mut().daemon_net = Some(daemon_net);
    store.data_mut().manifold = Some(manifold);
    store.data_mut().daemon_workers = Some(daemon_workers);
    store.data_mut().daemon_sab = Some(daemon_sab);
    store.data_mut().daemon_dgram_py = Some(daemon_dgram_py);
    #[cfg(unix)]
    {
        store.data_mut().daemon_unix = Some(daemon_unix);
    }
    if !rw_preopens.is_empty() {
        store.data_mut().rw_preopens = rw_preopens.to_vec();
    }
    // R1 effect capture on the live-net path: attach the record/replay host so
    // the emscripten seams journal host-mediated effects. `None` = no capture.
    store.data_mut().host_context = host_context;
    // Live-net runs need real OS entropy so TLS handshakes can generate
    // cryptographically random session keys. Sealed runs keep Deterministic
    // (the default), which produces byte-identical output on re-execution.
    store.data_mut().entropy = crate::embedder_vm::EntropySource::RealOs;

    // Prepend the ssl shim + certifi setup as a preamble so both are in place
    // before any user code runs `import ssl` or `import urllib.request`.
    //
    // The ssl shim installs a pure-Python `ssl` module into sys.modules. The
    // Pyodide stdlib zip has no ssl.py (no conflict). It provides the minimal
    // surface urllib.request uses:
    //   - SSLContext.wrap_socket: returns the socket as a plaintext passthrough
    //     (an SSLSocket delegating recv/send/makefile to the raw socket). The
    //     host terminates TLS: the SNI hostname is captured at getaddrinfo
    //     (hostname -> resolved ip/port), and the TCP connect signals DaemonNet
    //     to upgrade that connection, which encrypts/decrypts via rustls.
    //   - create_default_context, SSLError, HAS_SNI, CERT_REQUIRED, etc.
    //
    // The certifi block is a no-op when certifi is absent; it stays for
    // environments where certifi is mounted (harmless since host validates certs).
    const SSL_SHIM: &str = concat!(
        "import sys as _sys,types as _t\n",
        "def _mk_ssl():\n",
        " m=_t.ModuleType('ssl')\n",
        " m.CERT_NONE=0;m.CERT_OPTIONAL=1;m.CERT_REQUIRED=2\n",
        " m.PROTOCOL_TLS=2;m.PROTOCOL_TLS_CLIENT=16;m.HAS_SNI=True\n",
        " class VerifyMode(int):pass\n",
        " m.VerifyMode=VerifyMode\n",
        " class Purpose:\n",
        "  SERVER_AUTH=object();CLIENT_AUTH=object()\n",
        " m.Purpose=Purpose\n",
        " class SSLError(OSError):pass\n",
        " m.SSLError=SSLError\n",
        " class SSLWantReadError(SSLError):pass\n",
        " m.SSLWantReadError=SSLWantReadError\n",
        " class SSLWantWriteError(SSLError):pass\n",
        " m.SSLWantWriteError=SSLWantWriteError\n",
        " class SSLSocket:\n",
        "  __slots__=('_s',)\n",
        "  def __init__(self,s):self._s=s\n",
        "  def recv(self,*a,**k):return self._s.recv(*a,**k)\n",
        "  def read(self,n=-1):return self._s.recv(n)\n",
        "  def send(self,*a,**k):return self._s.send(*a,**k)\n",
        "  def sendall(self,d,f=0):return self._s.sendall(d,f)\n",
        "  def makefile(self,*a,**k):return self._s.makefile(*a,**k)\n",
        "  def close(self):return self._s.close()\n",
        "  def fileno(self):return self._s.fileno()\n",
        "  def settimeout(self,t):return self._s.settimeout(t)\n",
        "  def gettimeout(self):return self._s.gettimeout()\n",
        "  def setsockopt(self,*a,**k):return self._s.setsockopt(*a,**k)\n",
        "  def getpeername(self):return self._s.getpeername()\n",
        "  def getpeercert(self,b=False):return {}\n",
        "  def version(self):return 'TLSv1.3'\n",
        "  def cipher(self):return None\n",
        "  def do_handshake(self):pass\n",
        "  def unwrap(self):return self._s\n",
        "  def shutdown(self,h):return self._s.shutdown(h)\n",
        "  def __enter__(self):return self\n",
        "  def __exit__(self,*a):self.close()\n",
        " m.SSLSocket=SSLSocket\n",
        " class SSLContext:\n",
        "  def __init__(self,p=None):\n",
        "   self.check_hostname=False;self.verify_mode=m.CERT_REQUIRED\n",
        "   self.post_handshake_auth=False;self.options=0\n",
        "   self.minimum_version=None;self.maximum_version=None\n",
        "  def load_default_certs(self,*a,**k):pass\n",
        "  def load_verify_locations(self,*a,**k):pass\n",
        "  def set_alpn_protocols(self,*a,**k):pass\n",
        "  def set_ciphers(self,*a,**k):pass\n",
        "  def set_servername_callback(self,*a,**k):pass\n",
        "  def wrap_socket(self,s,server_hostname=None,server_side=False,\n",
        "                  do_handshake_on_connect=True,suppress_ragged_eofs=True,**k):\n",
        "   return SSLSocket(s)\n",
        " m.SSLContext=SSLContext\n",
        " def cdc(purpose=None,**k):\n",
        "  c=SSLContext();c.check_hostname=True;c.verify_mode=m.CERT_REQUIRED;return c\n",
        " m.create_default_context=cdc\n",
        " m._create_unverified_context=cdc\n",
        " m._create_default_https_context=cdc\n",
        " m.match_hostname=lambda *a,**k:None\n",
        " return m\n",
        "_sys.modules['ssl']=_mk_ssl()\n",
        "del _mk_ssl,_sys,_t\n",
        "try:\n",
        " import certifi as _c,os as _o;_o.environ['SSL_CERT_FILE']=_c.where()\n",
        "except Exception:\n",
        " pass\n",
    );
    let combined_source = format!("{SSL_SHIM}{python_source}");
    run_booted_pyodide(&combined_source, None, &mut store, &instance)
}

/// The program's captured stdout: the BINARY sink `/.afb/stdout.bin` the
/// injected preamble redirects `sys.stdout` to, read back byte-exact (a PNG or
/// audio bytes survive bit-for-bit). Falls back to `wasi_stdout` (fd 1/2
/// C-level writes) when the sink is empty - e.g. a run that trapped before the
/// preamble installed, or output written straight to WASI.
fn captured_stdout(store: &Store<EmbedderState>) -> Vec<u8> {
    let from_file = store
        .data()
        .fs
        .read_file("/.afb/stdout.bin")
        .unwrap_or_default();
    if from_file.is_empty() {
        store.data().wasi_stdout.clone()
    } else {
        from_file
    }
}

/// The program's captured stderr: the BINARY sink `/.afb/stderr.bin` the
/// injected preamble redirects `sys.stderr` to, byte-exact. Empty when the
/// program wrote nothing to stderr.
fn captured_stderr(store: &Store<EmbedderState>) -> Vec<u8> {
    store
        .data()
        .fs
        .read_file("/.afb/stderr.bin")
        .unwrap_or_default()
}

/// The program's typed return value, lifted from `/.afb/output.frame`.
///
/// The guest postamble writes `[kind_byte] + payload` there when the program
/// called `__afb_emit__` (kind `1` = raw bytes, kind `0` = UTF-8 JSON). The
/// Pyodide stdlib has no BLAKE3, so the guest cannot build a self-verifying
/// `"AFBF"` frame; instead the host reframes the raw payload through
/// afterburner-core's one canonical carrier ([`encode_frame`] +
/// [`decode_output_value`]) - the BLAKE3 stays native, the decode path is the
/// same one every substrate uses (DRY), and the payload round-trips byte-exact
/// into an [`OutputValue`]. An absent or empty frame means no value was
/// surfaced -> `Json(Null)`; a present-but-malformed frame is a loud error
/// (honesty fence), never a silent empty value.
fn captured_output(store: &Store<EmbedderState>) -> Result<OutputValue> {
    match store.data().fs.read_file("/.afb/output.frame") {
        Some(raw) if !raw.is_empty() => {
            let kind = OutputTag::from_u8(raw[0]).ok_or_else(|| {
                AfterburnerError::Engine(format!(
                    "python output frame at /.afb/output.frame: unknown kind byte {}",
                    raw[0]
                ))
            })?;
            let frame = encode_frame(kind, &raw[1..]);
            decode_output_value(&frame)
        }
        _ => Ok(OutputValue::Json(serde_json::Value::Null)),
    }
}

// ---- persistent session (R4) -----------------------------------------------

/// A persistent Python session over a fixed host-filesystem root.
///
/// Implements the substrate-agnostic [`Session`] contract (R4): a stable
/// rw-preopen root (a real host directory) survives byte-exact across
/// successive [`run`](Session::run) calls, so a file one run writes under the
/// session's guest root is visible to the next run and to the `fs_*`
/// accessors. [`fs_read`](Session::fs_read) / [`fs_write`](Session::fs_write) /
/// [`fs_exists`](Session::fs_exists) operate directly on that host directory
/// without entering guest code.
///
/// Each [`run`](Session::run) mounts the session root as the guest rw-preopen
/// via [`run_pyodide_with_preopens`] (the existing durable-FS seam), so a
/// multimodal artifact (a PNG, an audio buffer) a run writes there reads back
/// bit-identical on the next run or through `fs_read`.
///
// vertexia: each run boots a fresh interpreter mounted on the session root
// (correctness: state persists via the host dir). Reusing ONE booted CPython
// across runs for speed is blocked by the interpreter model - `__main_argc_argv`
// runs `Py_Initialize` then `Py_Main` finalizes CPython, so a second run needs a
// re-entrant `PyRun_String` export the Pyodide build does not surface; wire that
// export to reuse the post-ctors `run_booted_pyodide` store across runs.
pub struct PySession {
    /// Host directory backing the session; persists across runs.
    root: PathBuf,
    /// Guest mount path the root is preopened at (e.g. `/session`).
    guest_root: String,
}

impl PySession {
    /// Open a session backed by host directory `root`, mounted in the guest at
    /// `/session`. The directory is created if absent.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        Self::open_at(root, "/session")
    }

    /// Open a session backed by host directory `root`, mounted in the guest at
    /// `guest_root`. The host directory is created if absent.
    pub fn open_at(root: impl Into<PathBuf>, guest_root: impl Into<String>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| {
            AfterburnerError::Engine(format!("session root {}: {e}", root.display()))
        })?;
        Ok(Self {
            root,
            guest_root: guest_root.into(),
        })
    }

    /// The guest mount path of the session root (e.g. `/session`). Guest code
    /// reads and writes durable session state under this directory.
    pub fn guest_root(&self) -> &str {
        &self.guest_root
    }

    /// Resolve a session-relative or guest-absolute `path` to its host path,
    /// rejecting any `..` component so an accessor call cannot escape the root.
    fn host_path(&self, path: &str) -> Result<PathBuf> {
        let rel = path
            .strip_prefix(&self.guest_root)
            .unwrap_or(path)
            .trim_start_matches('/');
        if Path::new(rel)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(AfterburnerError::Engine(format!(
                "session path {path:?} escapes the root (`..` is not allowed)"
            )));
        }
        Ok(self.root.join(rel))
    }
}

impl Session for PySession {
    fn run(&mut self, code: &[u8], lang: Language) -> Result<RunResult> {
        if lang != Language::Python {
            return Err(AfterburnerError::Engine(format!(
                "PySession runs Python; got {lang:?}"
            )));
        }
        let source = std::str::from_utf8(code)
            .map_err(|e| AfterburnerError::Engine(format!("python source is not UTF-8: {e}")))?;
        let rt = resolve_runtime()?;
        let out = run_pyodide_with_preopens(
            &rt,
            source,
            &[(self.root.clone(), self.guest_root.clone())],
        )?;
        Ok(RunResult {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
            output: out.output,
        })
    }

    fn fs_read(&self, path: &str) -> Result<Vec<u8>> {
        let hp = self.host_path(path)?;
        std::fs::read(&hp)
            .map_err(|e| AfterburnerError::Engine(format!("session fs_read {}: {e}", hp.display())))
    }

    fn fs_write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let hp = self.host_path(path)?;
        if let Some(parent) = hp.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AfterburnerError::Engine(format!(
                    "session fs_write mkdir {}: {e}",
                    parent.display()
                ))
            })?;
        }
        std::fs::write(&hp, data).map_err(|e| {
            AfterburnerError::Engine(format!("session fs_write {}: {e}", hp.display()))
        })
    }

    fn fs_exists(&self, path: &str) -> bool {
        self.host_path(path).map(|p| p.exists()).unwrap_or(false)
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
    /// runs on the resolved (zero-config) runtime and prints the value computed
    /// via the sibling. Proves the package's `.py` files are mounted into the
    /// guest FS and its directory is on `sys.path`.
    ///
    /// `#[ignore]`: a cold cache makes `resolve_runtime` fetch the stock Python
    /// runtime (and `wasm-opt`-translate it) into `~/.burn`, so it is opt-in
    /// (the operator's CLI cold-download verify exercises that path). The
    /// network-free manifest-resolution logic is covered by
    /// [`crate::pyodide_bundle`]'s `resolve_dir` tests.
    #[test]
    #[ignore = "fetches/uses the real ~/.burn Python runtime; run explicitly"]
    fn run_python_package_resolves_sibling_import() {
        let rt = match resolve_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!("skip: no python runtime available");
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
            vendor_pip_wheels: Vec::new(),
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

    /// Build a minimal synthetic pure-Python wheel (a zip containing
    /// `stubpkg/__init__.py`) as raw bytes.
    ///
    /// A wheel is a zip; this uses stored (method 0) entries to keep the
    /// helper self-contained. The filename follows PEP 427:
    /// `stubpkg-1.0.0-py3-none-any.whl`.
    fn make_synthetic_wheel() -> Vec<u8> {
        let name: &[u8] = b"stubpkg/__init__.py";
        let data: &[u8] = b"def hello():\n    return 'vendor_ok'\n";
        build_stored_zip(&[(name, data)])
    }

    /// Build a zip archive containing zero-compression (stored) entries.
    /// Used to construct synthetic `.whl` files for tests.
    fn build_stored_zip(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        let mut offset = 0u32;

        for (name, data) in entries {
            let name_len = name.len() as u16;
            let data_len = data.len() as u32;
            let crc = crc32_ieee(data);

            // Local file header.
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method 0 = stored
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&data_len.to_le_bytes()); // compressed size
            out.extend_from_slice(&data_len.to_le_bytes()); // uncompressed size
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            out.extend_from_slice(name);
            out.extend_from_slice(data);

            // Central directory entry.
            let local_offset = offset;
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&0u16.to_le_bytes()); // method
            central.extend_from_slice(&0u16.to_le_bytes()); // mod time
            central.extend_from_slice(&0u16.to_le_bytes()); // mod date
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&data_len.to_le_bytes());
            central.extend_from_slice(&data_len.to_le_bytes());
            central.extend_from_slice(&name_len.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk start
            central.extend_from_slice(&0u16.to_le_bytes()); // int attributes
            central.extend_from_slice(&0u32.to_le_bytes()); // ext attributes
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name);

            offset += 30 + name_len as u32 + data_len;
        }

        let central_start = out.len() as u32;
        let central_len = central.len() as u32;
        let entry_count = entries.len() as u16;
        out.extend_from_slice(&central);

        // End of central directory record.
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir start
        out.extend_from_slice(&entry_count.to_le_bytes());
        out.extend_from_slice(&entry_count.to_le_bytes());
        out.extend_from_slice(&central_len.to_le_bytes());
        out.extend_from_slice(&central_start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length

        out
    }

    /// CRC-32 (IEEE 802.3 polynomial) of `data`. Written inline so the test
    /// module has no extra dependency on a crc crate.
    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc: u32 = !0u32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                let carry = crc & 1;
                crc >>= 1;
                if carry != 0 {
                    crc ^= 0xEDB8_8320u32;
                }
            }
        }
        !crc
    }

    /// End-to-end vendor pip wheel mount test.
    ///
    /// Proves that a Python `.afb` with a `vendor/pip/<wheel>.whl` member mounts
    /// the wheel into site-packages before CPython's import machinery activates,
    /// so `import stubpkg` resolves offline with no network.
    ///
    /// Flow:
    /// 1. Build a synthetic pure-Python wheel containing `stubpkg/__init__.py`.
    /// 2. Build a real `.afb` (via `afterburner_afb::pack::Builder`) with the
    ///    wheel under `vendor/pip/stubpkg-1.0.0-py3-none-any.whl`, a minimal
    ///    source entry, and `[pip] stubpkg = "*"` in the manifest.
    /// 3. Unpack the `.afb` (full verification path) and extract the vendor
    ///    wheels into `PyPackage.vendor_pip_wheels`.
    /// 4. Run `import stubpkg; print(stubpkg.hello())` on the resolved runtime
    ///    and assert the sentinel appears in stdout.
    ///
    /// `#[ignore]`: requires the real Python runtime in `~/.burn` (same
    /// condition as `run_python_package_resolves_sibling_import`). Skips
    /// gracefully when the runtime is absent, matching the survey-test precedent.
    #[test]
    #[ignore = "requires the real ~/.burn Python runtime; run explicitly"]
    fn vendor_pip_wheel_mounts_and_imports_offline() {
        use afterburner_afb::{
            Afb,
            manifest::{Format, Manifest, Package, Runtime},
            pack::Builder,
        };
        use afterburner_core::Manifold;
        use std::collections::BTreeMap;

        let rt = match resolve_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!(
                    "[vendor_pip] SKIP: no python runtime available \
                     (populate ~/.burn and re-run)"
                );
                return;
            }
        };

        // 1. Build the synthetic wheel bytes (pure-Python, no .so).
        let wheel_bytes = make_synthetic_wheel();
        let wheel_archive_path = "vendor/pip/stubpkg-1.0.0-py3-none-any.whl";

        // 2. Build a minimal Python .afb with the wheel vendored in.
        let mut pip = BTreeMap::new();
        pip.insert("stubpkg".to_owned(), "*".to_owned());

        let manifest = Manifest {
            format: Format {
                version: "1.3".to_owned(),
                min_reader: None,
            },
            package: Package {
                name: "vendor-pip-test".to_owned(),
                namespace: "test".to_owned(),
                version: "0.0.1".to_owned(),
                language: "python".to_owned(),
                entry: "source/main.py".to_owned(),
                description: None,
                homepage: None,
                license: None,
                keywords: Vec::new(),
            },
            runtime: Runtime {
                min: "0.1.0".to_owned(),
                target: None,
            },
            dependencies: BTreeMap::new(),
            npm: BTreeMap::new(),
            pip,
            gem: BTreeMap::new(),
            signature: None,
            metadata: toml::Table::new(),
            extra: toml::Table::new(),
        };

        let (afb_bytes, _digest) = Builder::new(manifest, Manifold::sealed())
            .source(
                "source/main.py",
                b"import stubpkg\nprint('VENDOR_PIP_OK ' + stubpkg.hello())\n".to_vec(),
            )
            .vendor(wheel_archive_path, wheel_bytes)
            .build()
            .expect("Builder::build");

        // 3. Unpack the .afb (full verification path - exercises the vendor/
        //    materialization in unpack.rs).
        let afb = Afb::from_bytes(&afb_bytes).expect("Afb::from_bytes");

        let vendor_pip_wheels: Vec<Vec<u8>> = afb
            .vendor
            .iter()
            .filter(|(k, _)| k.starts_with("vendor/pip/") && k.ends_with(".whl"))
            .map(|(_, v)| v.clone())
            .collect();
        assert_eq!(vendor_pip_wheels.len(), 1, "one vendored wheel in archive");

        let entry_source = std::str::from_utf8(
            afb.source
                .get("source/main.py")
                .expect("source/main.py in afb"),
        )
        .expect("entry source is UTF-8");

        // 4. Mount the vendored wheel and run Python.
        let pkg = PyPackage {
            files: BTreeMap::new(),
            sys_path_dir: "/pkg/source".to_owned(),
            vendor_pip_wheels,
        };

        let out =
            run_pyodide_package_with(&rt, entry_source, &pkg).expect("run_pyodide_package_with");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();

        assert_eq!(
            out.exit_code, 0,
            "python must exit cleanly; stdout={text:?}"
        );
        assert!(
            text.contains("VENDOR_PIP_OK vendor_ok"),
            "vendored stubpkg must be importable offline; stdout={text:?}"
        );
    }

    /// Sanity check: Python `open('/data/test.txt', 'w')` writes a file to
    /// the host filesystem via a rw-preopen. This verifies the N3 host-FS
    /// routing works before any sqlite3 test is run.
    ///
    /// Uses the 3.14 runtime when `BURN_PYTHON_RUNTIME` / `BURN_PYTHON_STDLIB_VER`
    /// are set, otherwise the default (0.28.3) runtime.
    #[test]
    #[ignore = "requires /tmp/pyodide-exnref.wasm and /tmp/python_stdlib.zip"]
    fn host_preopen_file_write_roundtrip() {
        let runtime_path =
            std::env::var("BURN_PYTHON_RUNTIME").unwrap_or_else(|_| TEST_WASM_PATH.to_owned());
        if !std::path::Path::new(&runtime_path).exists() {
            eprintln!("skip: python runtime not found at {runtime_path}");
            return;
        }
        let rt = match resolve_runtime() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip: {e}");
                return;
            }
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let host_dir = tmp.path().to_path_buf();
        let out = run_pyodide_with_preopens(
            &rt,
            r#"
with open('/data/hello.txt', 'w') as f:
    f.write('host-ok\n')
with open('/data/hello.txt', 'r') as f:
    print(f.read().strip())
"#,
            &[(host_dir.clone(), "/data".to_owned())],
        )
        .expect("run_pyodide_with_preopens failed");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(out.exit_code, 0, "expected exit 0; stdout={text:?}");
        assert!(
            text.contains("host-ok"),
            "expected 'host-ok' in stdout; got: {text:?}"
        );
        assert!(
            host_dir.join("hello.txt").exists(),
            "file not found on host at {:?}",
            host_dir.join("hello.txt")
        );
    }

    /// R2/R3: a program writing raw non-UTF-8 bytes (NULs, 0xFF, a lone
    /// continuation byte) to `sys.stdout.buffer` reads back BIT-IDENTICAL - the
    /// binary sink does not mangle stdout the way the old text redirect did.
    #[test]
    #[ignore = "requires the real ~/.burn Python runtime; run explicitly"]
    fn binary_stdout_roundtrip_bit_identical() {
        let rt = match resolve_runtime() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip: {e}");
                return;
            }
        };
        // Every byte 0..=255 plus an explicit invalid-UTF-8 pair (0xC3 0x28).
        let src = "import sys\n\
                   sys.stdout.buffer.write(bytes(range(256)))\n\
                   sys.stdout.buffer.write(b'\\xc3\\x28')\n";
        let out = run_pyodide_with(&rt, src).expect("run");
        let mut expected: Vec<u8> = (0..=255u8).collect();
        expected.extend_from_slice(&[0xc3, 0x28]);
        assert_eq!(out.exit_code, 0, "stderr={:?}", out.stderr);
        assert_eq!(
            out.stdout, expected,
            "binary stdout must round-trip bit-identical"
        );
    }

    /// R1: with a record host attached via [`run_python_with_host`], the
    /// emscripten effect seam actually FIRES - a guest fs write produces a
    /// captured `Fs(Write)` `HostEffectRecord` in the host's effect log,
    /// content-addressed by BLAKE3. Before the `host_context` wiring this seam
    /// was instrumented but unreachable (dead code): no runner set the store's
    /// host, so Python surfaced zero effects. This is the parity proof that
    /// Python captures effects like the JS substrate.
    #[test]
    #[ignore = "requires the real ~/.burn Python runtime; run explicitly"]
    fn host_effect_seam_captures_fs_write() {
        use afterburner_core::HostContext;
        if resolve_runtime().is_err() {
            eprintln!("skip: no python runtime available");
            return;
        }

        #[derive(Default)]
        struct RecordingHost {
            log: std::sync::Mutex<Vec<afterburner_core::HostEffectRecord>>,
        }
        impl afterburner_core::HostContext for RecordingHost {
            fn record_host_effect(&self, record: afterburner_core::HostEffectRecord) {
                self.log.lock().unwrap().push(record);
            }
            fn get_effect_log(&self) -> Vec<afterburner_core::HostEffectRecord> {
                self.log.lock().unwrap().clone()
            }
        }

        let host = std::sync::Arc::new(RecordingHost::default());
        let payload = b"multimodal\x00\xff bytes";
        let out = run_python_with_host(
            "open('/cap_probe.bin', 'wb').write(b'multimodal\\x00\\xff bytes')",
            host.clone() as std::sync::Arc<dyn afterburner_core::HostContext>,
        )
        .expect("run_python_with_host");
        assert_eq!(out.exit_code, 0, "stderr={:?}", out.stderr);

        let log = host.get_effect_log();
        // afterburner's own /.afb capture plumbing must NOT leak in as guest effects.
        assert!(
            !log.iter()
                .any(|r| r.effect.target.starts_with("file::/.afb")),
            "internal /.afb plumbing leaked into the effect log: {:?}",
            log.iter()
                .map(|r| r.effect.target.clone())
                .collect::<Vec<_>>()
        );
        // The seam must have fired for the guest's own write, byte-exact.
        let write = log
            .iter()
            .find(|r| {
                r.effect.target == "file::/cap_probe.bin"
                    && matches!(
                        r.effect.kind,
                        afterburner_core::EffectKind::Fs(afterburner_core::FileOp::Write)
                    )
            })
            .unwrap_or_else(|| {
                panic!(
                    "effect seam must capture the guest fs write; captured targets = {:?}",
                    log.iter()
                        .map(|r| r.effect.target.clone())
                        .collect::<Vec<_>>()
                )
            });
        assert_eq!(
            write.effect.input_hash,
            afterburner_core::content_hash(payload),
            "captured write content must content-address identically (BLAKE3 parity)"
        );
    }

    /// R3: the typed return value carried via `__afb_emit__` -> the AFBF frame
    /// at `/.afb/output.frame` -> [`PyodideRunOutput::output`]. Raw bytes come
    /// back as [`OutputValue::Bytes`] byte-exact (audio/image payloads survive);
    /// a JSON value comes back as [`OutputValue::Json`]; no emit -> `Json(Null)`.
    #[test]
    #[ignore = "requires the real ~/.burn Python runtime; run explicitly"]
    fn typed_output_frame_bytes_and_json() {
        let rt = match resolve_runtime() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skip: {e}");
                return;
            }
        };

        let audio: Vec<u8> = (0..=255u8).rev().collect();
        let bytes_out = run_pyodide_with(&rt, "__afb_emit__(bytes(range(255, -1, -1)))")
            .expect("run bytes emit");
        assert_eq!(bytes_out.exit_code, 0, "stderr={:?}", bytes_out.stderr);
        assert_eq!(
            bytes_out.output,
            OutputValue::Bytes(audio),
            "emitted bytes must survive byte-exact"
        );

        let json_out =
            run_pyodide_with(&rt, "__afb_emit__({'k': [1, 2, 3], 's': 'hi'})").expect("run json");
        assert_eq!(
            json_out.output,
            OutputValue::Json(serde_json::json!({"k": [1, 2, 3], "s": "hi"})),
            "emitted JSON must decode structurally"
        );

        let none_out = run_pyodide_with(&rt, "print('no emit')").expect("run no emit");
        assert_eq!(
            none_out.output,
            OutputValue::Json(serde_json::Value::Null),
            "no emit -> Json(Null)"
        );
        assert_eq!(none_out.stdout, b"no emit\n");
    }

    /// R4: a [`PySession`] keeps a durable root across runs. Run 1 writes a
    /// binary file (all 256 byte values) under the guest root; run 2 reads it
    /// back and emits it; the host-side `fs_read` sees the same bytes - all
    /// bit-identical.
    #[test]
    #[ignore = "requires the real ~/.burn Python runtime; run explicitly"]
    fn session_persists_binary_across_runs() {
        if resolve_runtime().is_err() {
            eprintln!("skip: no python runtime available");
            return;
        }
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sess = PySession::open(tmp.path().to_path_buf()).expect("open session");

        let w = sess
            .run(
                b"open('/session/img.bin', 'wb').write(bytes(range(256)))",
                Language::Python,
            )
            .expect("run 1 write");
        assert_eq!(w.exit_code, 0, "stderr={:?}", w.stderr);

        let r = sess
            .run(
                b"__afb_emit__(open('/session/img.bin', 'rb').read())",
                Language::Python,
            )
            .expect("run 2 read");
        assert_eq!(r.exit_code, 0, "stderr={:?}", r.stderr);
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(
            r.output,
            OutputValue::Bytes(all.clone()),
            "run 2 must read back what run 1 wrote"
        );

        // Host-side accessor sees the same bytes without entering guest code.
        assert!(sess.fs_exists("/session/img.bin"));
        assert_eq!(
            sess.fs_read("/session/img.bin").expect("fs_read"),
            all,
            "fs_read must be bit-identical to the guest write"
        );

        // `..` traversal is rejected at the accessor boundary.
        assert!(sess.fs_read("/session/../escape").is_err());
    }
}
