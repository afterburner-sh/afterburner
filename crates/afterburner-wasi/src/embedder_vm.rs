// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Generic, embedder-driven Wasm VM - sealed and deterministic.
//!
//! Provides [`EmbedderVm`] for running arbitrary Wasm modules whose host
//! imports are supplied by the caller as Rust closures at build time. This
//! path is entirely independent of the Javy/QuickJS plugin machinery; it
//! never touches `host_imports`, `HostState`, or the 189-import linker.
//!
//! ## Design
//!
//! * One `Engine` per `EmbedderVm`, configured with the deterministic
//!   profile (NaN canonicalization, relaxed-SIMD determinism, threads and
//!   shared memory off). See [`deterministic_engine`].
//! * One `Arc<InstancePre<EmbedderState>>` per compiled module, built once by
//!   [`EmbedderVm::compile`]. Per-call cost is a fresh `Store::new` plus
//!   `instance_pre.instantiate` - no linker re-walk, no import re-typecheck.
//!   This is the same caching pattern the Javy path uses for its plugin.
//! * Host imports are wired once, at `compile` time, via a callback
//!   `FnOnce(&mut EmbedderLinker) -> Result<()>`. [`EmbedderLinker`] is a
//!   public newtype over the internal `Linker<EmbedderState>` so callers
//!   define imports without knowing the store data type.
//! * Fuel (not epoch) bounds execution: deterministic instruction budget,
//!   no background ticker thread, no epoch increment races.
//! * Returns the i64 result of a named export plus any bytes the module
//!   wrote to stdout via WASI (optional WASI must be opted in per compile).
//!
//! ## Thread safety
//!
//! `Engine`, `Module`, and `InstancePre<EmbedderState>` are all
//! `Send + Sync`. Each `run` call builds a fresh `Store<EmbedderState>`, so
//! concurrent calls never share mutable state. `EmbedderVm` is `Send + Sync`.

use crate::emscripten_fs::InMemFs;
use crate::emscripten_sidemodule::SideModuleRegistry;
use afterburner_core::log::Level;
use afterburner_core::{AfterburnerError, Result, ab_event};
use std::path::PathBuf;
use std::sync::Arc;
use wasmtime::{
    Config, Engine, InstancePre, Linker, Module, OptLevel, Store, Trap, WasmBacktraceDetails,
};
use wasmtime_wasi::p1::{WasiP1Ctx, add_to_linker_sync};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{DirPerms, FilePerms, I32Exit, WasiCtxBuilder};

// ---- deterministic engine config -----------------------------------------

/// Fuel budget used when the caller passes `None` to [`EmbedderVm::run`].
/// Generous enough for unit tests; production callers supply their own bound.
const DEFAULT_FUEL: u64 = 100_000_000;

// ---- WASI command options ---------------------------------------------------

/// Options for running a WASI command module via [`EmbedderVm::run_command`].
///
/// A WASI command module exports `_start` (signature `() -> ()`). It receives
/// its arguments through `args_get` and its filesystem through preopened
/// directories. `WasiCommandOpts` encapsulates all of these plus optional
/// environment variable grants.
///
/// ## Sandbox posture
///
/// By default (`WasiCommandOpts::new()`) no preopens are added and no env
/// vars are forwarded - the module runs sealed: pure compute over stdin/args.
/// Callers explicitly opt in to each capability.
///
/// ## Example
///
/// ```no_run
/// use afterburner_wasi::embedder_vm::WasiCommandOpts;
///
/// let opts = WasiCommandOpts::new()
///     .args(["python", "-c", "print('hello from CPython')"])
///     .preopen_ro("/tmp/stdlib", "/usr/lib/python3.12");
/// ```
#[derive(Debug, Default, Clone)]
pub struct WasiCommandOpts {
    /// argv passed to the module via `args_get` / `args_sizes_get`.
    /// The first element is conventionally the program name (`argv[0]`).
    pub args: Vec<String>,
    /// Read-only preopens: (host_path, guest_path). Added with
    /// `DirPerms::READ | FilePerms::READ`.
    pub preopens_ro: Vec<(PathBuf, String)>,
    /// Read-write preopens: (host_path, guest_path). Added with
    /// `DirPerms::all() | FilePerms::all()`.
    pub preopens_rw: Vec<(PathBuf, String)>,
    /// Environment variables forwarded as `(key, value)` pairs.
    pub env_vars: Vec<(String, String)>,
}

impl WasiCommandOpts {
    /// Create empty options (no args, no preopens, no env). Sealed posture.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the argument list. Replaces any previously set args.
    /// The first element should be the program name (`argv[0]`).
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Add a read-only preopened directory. `host_path` must exist on the
    /// host; `guest_path` is the path the module sees. The module can list
    /// and read files but not create or write them.
    pub fn preopen_ro(
        mut self,
        host_path: impl Into<PathBuf>,
        guest_path: impl Into<String>,
    ) -> Self {
        self.preopens_ro.push((host_path.into(), guest_path.into()));
        self
    }

    /// Backward-compatible alias: calls [`preopen_ro`][Self::preopen_ro].
    pub fn preopen(self, host_path: impl Into<PathBuf>, guest_path: impl Into<String>) -> Self {
        self.preopen_ro(host_path, guest_path)
    }

    /// Add a read-write preopened directory. The module can create, read,
    /// and write files under this path.
    pub fn preopen_rw(
        mut self,
        host_path: impl Into<PathBuf>,
        guest_path: impl Into<String>,
    ) -> Self {
        self.preopens_rw.push((host_path.into(), guest_path.into()));
        self
    }

    /// Forward an environment variable into the module's WASI env.
    /// Repeatable; each call appends one `(key, value)` pair.
    pub fn env_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }
}

/// Build a Wasmtime `Engine` configured for determinism and fuel metering.
///
/// Profile (all flags are deterministic-profile defaults):
///
/// * `cranelift_nan_canonicalization(true)` - NaN payloads are canonicalized
///   so floating-point results are identical across host CPUs that produce
///   different NaN bit patterns.
/// * `relaxed_simd_deterministic(true)` - relaxed-SIMD instructions choose
///   the single deterministic result instead of the host-preferred one. This
///   keeps SIMD output byte-identical across micro-architectures.
/// * `wasm_threads(false)` - shared-memory multi-threading disabled; modules
///   using `shared` memories or `wait`/`notify` fail at compile time. No
///   shared mutable state can leak between runs.
/// * `consume_fuel(true)` - every run is bounded by an instruction budget
///   supplied by the caller. An infinite loop surfaces as
///   `AfterburnerError::FuelExhausted` rather than a hung thread.
/// * Epoch interruption and pooling are intentionally omitted: the generic
///   path hosts short-lived modules with embedder-supplied imports, not the
///   long-lived plugin. Fuel is sufficient and simpler; pooling is worth the
///   configuration cost only for the plugin's large linear-memory image.
///
/// ## On-disk compile cache (determinism-neutral)
///
/// Wasmtime's built-in compilation cache ([`Config::cache`]) is installed
/// rooted at the owner-only [`crate::wasm_engine::private_cache_dir`]. The
/// first compile of a runtime module (the ~25-34 MiB CRuby / Pyodide wasm, or
/// any numpy `.so` side module) runs Cranelift and writes the native artifact;
/// every later compile of byte-identical input reuses it and skips Cranelift,
/// turning the multi-second cold compile into a near-instant load. So a repeat
/// `burn run x.rb` / `x.py` pays the compile once, not every run.
///
/// This changes nothing about execution. The cache is keyed by the module
/// bytes **plus this exact `Config` plus the wasmtime version** (wasmtime folds
/// all three into the entry key), so any change to a deterministic flag above,
/// or a wasmtime bump, lands on a fresh key and the old entry is simply never
/// read - no manual invalidation. The stored artifact is the same native code
/// Cranelift would emit cold; NaN canonicalization, threads-off, relaxed-SIMD
/// determinism, and fuel metering are all inputs to the key, not things the
/// cache can alter. A warm run is therefore byte-identical (output and fuel) to
/// a cold one. Cache init failure is downgraded to a warning and the engine
/// runs without it - the cache is an optimisation, never a correctness
/// dependency, and never a determinism one.
pub fn deterministic_engine() -> Result<Engine> {
    let mut cfg = Config::new();
    cfg.cranelift_opt_level(OptLevel::Speed)
        .cranelift_nan_canonicalization(true)
        // Keep relaxed-SIMD enabled but force deterministic semantics so
        // modules that use relaxed-SIMD instructions produce identical output
        // across host micro-architectures (AVX-512 vs SSE4, Neon variants, etc).
        .wasm_relaxed_simd(true)
        .relaxed_simd_deterministic(true)
        // Threads + shared memory allow cross-instance communication that
        // breaks determinism. Disable both at the engine level so any module
        // that declares a shared memory or uses thread-local atomics fails at
        // compile time, not silently.
        .wasm_threads(false)
        // Fuel metering: every Wasm instruction decrements a per-Store
        // counter. When the counter reaches zero the next instruction traps
        // with `OutOfFuel`. This is the only bound we need for short-lived
        // modules; no epoch ticker, no background thread.
        .consume_fuel(true)
        // Enable the new (exnref/try_table) exceptions proposal plus the
        // function-references and GC proposals that it depends on. This lets
        // Cranelift compile modules translated from legacy-EH via
        // `wasm-opt --translate-to-exnref`.
        .wasm_function_references(true)
        .wasm_gc(true)
        .wasm_exceptions(true)
        // Always capture Wasm backtraces so the probe can print trap frames.
        .wasm_backtrace_details(WasmBacktraceDetails::Enable);

    // On-disk compile cache (see the doc above). Added strictly after the
    // deterministic flags so they are part of the cache key, never altered by
    // it. Mirrors `wasm_engine::build_engine`'s wiring; failure is a warning,
    // the engine runs cache-less rather than failing the run.
    install_compile_cache(&mut cfg);

    Engine::new(&cfg).map_err(|e| AfterburnerError::Engine(format!("embedder engine: {e}")))
}

/// Install wasmtime's on-disk compilation cache on `cfg`, rooted at the
/// owner-only [`crate::wasm_engine::private_cache_dir`].
///
/// Best-effort: if no private cache directory is available, or the cache fails
/// to initialise, the engine simply compiles cold every time. The cache is an
/// optimisation, never a correctness or determinism dependency, so every
/// failure path is a warning, not an error. Sharing `private_cache_dir` keeps
/// one owner-only cache root for the whole crate (the plugin `.cwasm` cache
/// uses the same directory).
fn install_compile_cache(cfg: &mut Config) {
    let Some(dir) = crate::wasm_engine::private_cache_dir() else {
        ab_event!(
            Level::Debug,
            "embedder.compile_cache_disabled",
            "reason" => "no private cache directory",
        );
        return;
    };
    let mut cache_config = wasmtime::CacheConfig::new();
    cache_config.with_directory(&dir);
    match wasmtime::Cache::new(cache_config) {
        Ok(cache) => {
            cfg.cache(Some(cache));
        }
        Err(e) => ab_event!(
            Level::Warn,
            "embedder.compile_cache_disabled",
            "dir" => dir.display().to_string(),
            "error" => e.to_string(),
        ),
    }
}

// ---- internal store-data type ------------------------------------------------

/// Per-call store state that parameterises the embedder linker and stores.
/// Exposed as `pub` so it can appear in the `IntoFunc` bound on
/// [`EmbedderLinker::func_wrap`]; external callers do not construct it.
pub struct EmbedderState {
    wasi: Option<WasiStateInner>,
    /// Linear memory imported as `env.memory` by Emscripten-compiled modules
    /// (e.g. `pyodide.asm.wasm`). Set after the store is created and the
    /// memory is defined via `wire_env_memory_and_table_in_store`. Custom
    /// `wasi_snapshot_preview1` shims use this handle instead of the standard
    /// wasmtime-wasi preview-1 accessor, which requires a `"memory"` *export*
    /// that Emscripten modules do not provide.
    pub pyodide_memory: Option<wasmtime::Memory>,
    /// Indirect function table imported as `env.__indirect_function_table` by
    /// Emscripten-compiled modules. Set by `wire_env_memory_and_table_in_store`.
    /// Used by `invoke_dispatch` to call funcrefs by table index without
    /// `caller.get_export`, which only works for module *exports* (not imports).
    pub pyodide_table: Option<wasmtime::Table>,
    /// The main module's mutable `env.__stack_pointer` global, captured by
    /// `wire_env_memory_and_table_in_store`. Retained for diagnostics and so a
    /// future change can unify the side and main stacks; the side modules use the
    /// separate [`Self::pyodide_side_stack_pointer`] today.
    pub pyodide_stack_pointer: Option<wasmtime::Global>,
    /// ONE mutable `env.__stack_pointer` shared by every loaded SIDE_MODULE.
    /// Created lazily by `pre_load_side_module` on the first side-module load and
    /// reused for all subsequent ones, so cross-module C calls between side
    /// modules (e.g. a Cython extension calling into numpy's `_multiarray_umath`)
    /// build and read C-stack argument frames at the same address. Without this
    /// each side module had its own stack pointer and they clobbered each other's
    /// frames, surfacing as the numpy.random `pool_size` default reading back as a
    /// stray numpy rodata pointer.
    pub pyodide_side_stack_pointer: Option<wasmtime::Global>,
    /// ONE shared exnref EH tag for C++ exceptions (`env.__cpp_exception`),
    /// created for the main interpreter module and reused by every side module
    /// so a C++ exception thrown in one module can be caught in another.
    /// Without this, exnref-translated `.so` files fail to instantiate with
    /// "unknown import: env::__cpp_exception has not been defined".
    pub pyodide_cpp_exception_tag: Option<wasmtime::Tag>,
    /// ONE shared exnref EH tag for C longjmp (`env.__c_longjmp`),
    /// created for the main interpreter module and reused by every side module.
    /// Required by side modules that use setjmp/longjmp across module boundaries.
    pub pyodide_c_longjmp_tag: Option<wasmtime::Tag>,
    /// Accumulated stdout bytes from custom WASI `fd_write` calls (fd 1/2).
    /// Appended by the `wasi_snapshot_preview1::fd_write` shim; read after
    /// `__wasm_call_ctors` returns.
    pub wasi_stdout: Vec<u8>,
    /// In-memory filesystem for Emscripten syscall shims. Holds the Python
    /// stdlib (mounted from `python_stdlib.zip`) and the current working
    /// directory state. Populated by `mount_zip_into_fs` before instantiation.
    pub fs: InMemFs,
    /// The last table index passed to `invoke_dispatch`. Set on every call so
    /// the probe can report which table slot was active when the trap fired.
    pub last_invoke_idx: u64,
    /// Exception pointer set by `__cxa_throw`. Read by `__cxa_find_matching_catch_*`
    /// to return the thrown object pointer to the C++ EH landing pad.
    pub cxa_thrown_ptr: i32,
    /// Running count of all `__cxa_throw` calls (caught + uncaught).
    pub cxa_throw_count: u32,
    /// Log of (count_at_throw, mangled_type_name) for every `__cxa_throw` call.
    /// Mangled name is read from `type_info_ptr + 4` in guest memory (wasm32 layout:
    /// `[vtable_ptr @0][name_ptr @4]`). Capped at 64 entries; older entries dropped.
    pub cxa_throw_log: Vec<(u32, String)>,
    /// Rolling log of the last 12 paths passed to `__syscall_openat` or
    /// `__syscall_stat64`. Used to identify which module CPython was looking for
    /// when the uncaught exception escaped.
    pub fs_path_log: std::collections::VecDeque<String>,
    /// Pre-loaded SIDE_MODULE instances (numpy `.so` files).
    /// Populated before Python runs; `_dlopen_js` looks handles up here.
    pub side_modules: SideModuleRegistry,
    /// The main (pyodide) wasm instance. Set after instantiation so that
    /// on-demand `_dlopen_js` loading can wire env.* imports of new side
    /// modules against both the main instance and already-loaded side modules.
    pub main_instance: Option<wasmtime::Instance>,
    /// Indirect-function-table slot indices freed by `ffi_closure_free_js`,
    /// reused by `ffi_closure_alloc_js` before growing the table. Mirrors
    /// Emscripten libffi's `freeTableIndexes` (see [`crate::emscripten_ffi`]): a
    /// closure's trampoline table slot is recycled, not leaked, so repeated
    /// ctypes closure alloc/free cycles do not grow the table without bound.
    /// A plain `Vec` is correct here: the store is single-threaded.
    pub ffi_free_slots: Vec<u32>,
}

impl EmbedderState {
    /// Create a non-WASI state (no stdout capture, no WASI context).
    /// Used by host-import modules that need a store but no WASI.
    pub fn headless() -> Self {
        Self {
            wasi: None,
            pyodide_memory: None,
            pyodide_table: None,
            pyodide_stack_pointer: None,
            pyodide_side_stack_pointer: None,
            pyodide_cpp_exception_tag: None,
            pyodide_c_longjmp_tag: None,
            wasi_stdout: Vec::new(),
            fs: InMemFs::new(),
            last_invoke_idx: u64::MAX,
            cxa_thrown_ptr: 0,
            cxa_throw_count: 0,
            cxa_throw_log: Vec::new(),
            fs_path_log: std::collections::VecDeque::new(),
            side_modules: SideModuleRegistry::new(),
            main_instance: None,
            ffi_free_slots: Vec::new(),
        }
    }

    /// Create a state suitable for the Emscripten/Pyodide boot path.
    ///
    /// Unlike `with_wasi` (which wires a real wasmtime-wasi preview-1 context
    /// requiring a `"memory"` export), this state pairs with the custom
    /// `wasi_snapshot_preview1` shims in [`crate::emscripten_wasi`] that read
    /// guest memory via the `env.memory` import handle stored in
    /// [`EmbedderState::pyodide_memory`].
    ///
    /// The in-memory filesystem is pre-opened with `/` at fd 3 so that WASI
    /// `fd_prestat_get`/`path_open` work for CPython's module loader. Call
    /// `store.data_mut().pyodide_memory = Some(mem)` immediately after
    /// `wire_env_memory_and_table_in_store` to activate the shims. Call
    /// `mount_zip_into_fs` to populate `store.data_mut().fs` with the Python
    /// stdlib before calling `__wasm_call_ctors`.
    pub fn for_emscripten() -> Self {
        Self {
            wasi: None,
            pyodide_memory: None,
            pyodide_table: None,
            pyodide_stack_pointer: None,
            pyodide_side_stack_pointer: None,
            pyodide_cpp_exception_tag: None,
            pyodide_c_longjmp_tag: None,
            wasi_stdout: Vec::new(),
            fs: InMemFs::new_with_root_preopen(),
            last_invoke_idx: u64::MAX,
            cxa_thrown_ptr: 0,
            cxa_throw_count: 0,
            cxa_throw_log: Vec::new(),
            fs_path_log: std::collections::VecDeque::new(),
            side_modules: SideModuleRegistry::new(),
            main_instance: None,
            ffi_free_slots: Vec::new(),
        }
    }

    /// Create a WASI-enabled state with stdout captured to an in-memory pipe.
    ///
    /// Required when the store is used with a linker that wired
    /// `wasmtime_wasi::p1::add_to_linker_sync`, such as ordinary WASI command
    /// modules. Not used for Emscripten modules that import rather than export
    /// their linear memory; use [`EmbedderState::for_emscripten`] instead.
    pub fn with_wasi() -> Self {
        let pipe = MemoryOutputPipe::new(4 * 1024 * 1024);
        let ctx = WasiCtxBuilder::new().stdout(pipe.clone()).build_p1();
        Self {
            wasi: Some(WasiStateInner { ctx, stdout: pipe }),
            pyodide_memory: None,
            pyodide_table: None,
            pyodide_stack_pointer: None,
            pyodide_side_stack_pointer: None,
            pyodide_cpp_exception_tag: None,
            pyodide_c_longjmp_tag: None,
            wasi_stdout: Vec::new(),
            fs: InMemFs::new(),
            last_invoke_idx: u64::MAX,
            cxa_thrown_ptr: 0,
            cxa_throw_count: 0,
            cxa_throw_log: Vec::new(),
            fs_path_log: std::collections::VecDeque::new(),
            side_modules: SideModuleRegistry::new(),
            main_instance: None,
            ffi_free_slots: Vec::new(),
        }
    }

    /// Return a mutable reference to the WASI preview-1 context.
    ///
    /// Panics when called on a headless (non-WASI) state. Only call this
    /// from a linker accessor registered for a WASI-enabled store.
    pub fn wasi_ctx_mut(&mut self) -> &mut WasiP1Ctx {
        self.wasi
            .as_mut()
            .map(|w| &mut w.ctx)
            .unwrap_or_else(|| unreachable!("WASI accessor reached non-WASI store"))
    }
}

struct WasiStateInner {
    ctx: WasiP1Ctx,
    stdout: MemoryOutputPipe,
}

// ---- public linker wrapper ---------------------------------------------------

/// Public handle to the Wasmtime linker used during [`EmbedderVm::compile`].
///
/// Passed to the embedder's `setup` callback so it can define host imports
/// via [`EmbedderLinker::func_wrap`] and other linker methods, without
/// needing to name the internal store-data type.
///
/// The full wasmtime `Linker<EmbedderState>` is exposed via
/// [`EmbedderLinker::inner_mut`] for callers that need lower-level control
/// (e.g. defining imports by name with custom types).
pub struct EmbedderLinker<'a> {
    inner: &'a mut Linker<EmbedderState>,
}

impl<'a> EmbedderLinker<'a> {
    /// Define a host function import. Delegates directly to
    /// [`wasmtime::Linker::func_wrap`]; any type that implements
    /// `wasmtime::WasmRet + wasmtime::WasmParams` is accepted.
    ///
    /// Returns an error (mapped to `AfterburnerError::Engine`) if the import
    /// is already defined or the type is incompatible.
    pub fn func_wrap<Params, Results, F>(&mut self, module: &str, name: &str, func: F) -> Result<()>
    where
        F: wasmtime::IntoFunc<EmbedderState, Params, Results>,
    {
        self.inner
            .func_wrap(module, name, func)
            .map(|_| ())
            .map_err(|e| {
                AfterburnerError::Engine(format!("embedder func_wrap `{module}::{name}`: {e}"))
            })
    }

    /// Direct access to the underlying `Linker<EmbedderState>` for callers
    /// that need to use methods not proxied by `EmbedderLinker` (e.g.
    /// `linker.define`, `linker.instance`, etc.).
    pub fn inner_mut(&mut self) -> &mut Linker<EmbedderState> {
        self.inner
    }
}

// ---- compiled module ---------------------------------------------------------

/// A compiled, self-contained Wasm module ready for repeated deterministic
/// execution. Produced by [`EmbedderVm::compile`]; the underlying native
/// code is shared across every [`EmbedderVm::run`] call.
///
/// `EmbedderModule` is `Send + Sync`: the `Arc<InstancePre<EmbedderState>>`
/// wraps a wasmtime type that is itself `Send + Sync`, and the engine is
/// cloned cheaply (reference-counted).
pub struct EmbedderModule {
    engine: Engine,
    // Shared compiled artifact. Per-call cost: one `Store::new` + one
    // `InstancePre::instantiate` - no linker re-walk, no import typecheck.
    instance_pre: Arc<InstancePre<EmbedderState>>,
    wasi: bool,
}

// Safety: wasmtime::InstancePre<T> is Send + Sync when T: Send.
// EmbedderState holds only owned types (WasiP1Ctx + MemoryOutputPipe), both Send.
// EmbedderModule holds only Arc + Engine (both Send + Sync) and bool.
// The auto-derive would work if wasmtime derived the bounds; we assert manually.
unsafe impl Send for EmbedderModule {}
unsafe impl Sync for EmbedderModule {}

// ---- output ------------------------------------------------------------------

/// Result of one [`EmbedderVm::run`] call.
#[derive(Debug, Clone)]
pub struct EmbedderRunOutput {
    /// The i64 value returned by the named export.
    pub result: i64,
    /// Bytes written to stdout (fd 1) during execution. Non-empty only when the
    /// module was compiled with `wasi: true` and actually wrote to stdout.
    pub stdout: Vec<u8>,
    /// Bytes written to stderr (fd 2) during execution. Captured for
    /// [`run_command`][EmbedderVm::run_command] (so a command module's
    /// diagnostics are not silently dropped); empty for [`run`][EmbedderVm::run]
    /// and for non-WASI modules.
    pub stderr: Vec<u8>,
}

// ---- VM ----------------------------------------------------------------------

/// Generic embedder-driven Wasm VM. Holds one `Engine` (shared across all
/// compiled modules from this VM) and exposes `compile` + `run`.
///
/// ## Example
///
/// ```no_run
/// use afterburner_wasi::embedder_vm::EmbedderVm;
///
/// let vm = EmbedderVm::new().unwrap();
/// let wat = br#"
///   (module
///     (import "host" "value" (func $v (result i64)))
///     (func (export "run") (result i64)
///       call $v
///       i64.const 2
///       i64.mul
///       i64.const 1
///       i64.add))
/// "#;
/// let module = vm.compile(wat, false, |linker| {
///     linker.func_wrap("host", "value", || -> i64 { 21 })
/// }).unwrap();
/// let out = vm.run(&module, "run", None).unwrap();
/// assert_eq!(out.result, 43);
/// ```
pub struct EmbedderVm {
    engine: Engine,
}

// EmbedderVm holds only a wasmtime::Engine, which is Send + Sync.
unsafe impl Send for EmbedderVm {}
unsafe impl Sync for EmbedderVm {}

impl EmbedderVm {
    /// Create a new VM with the deterministic engine profile.
    pub fn new() -> Result<Self> {
        Ok(Self {
            engine: deterministic_engine()?,
        })
    }

    /// Compile `wasm` (raw `.wasm` bytes or WAT text) into a reusable
    /// [`EmbedderModule`].
    ///
    /// `wasi` - when `true`, a sealed WASI preview1 context is wired into
    /// every run, making `wasi_snapshot_preview1` imports available (stdout
    /// is captured; no filesystem, no env, no stdin). When `false`, any
    /// module that imports from `wasi_snapshot_preview1` fails to
    /// instantiate unless the `setup` callback supplies those imports itself.
    ///
    /// `setup` - a callback that receives an [`EmbedderLinker`] and may
    /// define any number of host imports via `linker.func_wrap`. Called once
    /// at compile time; the linker is not shared across calls. Any import
    /// left unsatisfied causes `AfterburnerError::Engine` when
    /// `instantiate_pre` runs (wasmtime names the missing import in the
    /// error). The callback returns `afterburner_core::Result<()>`.
    ///
    /// Content-identical bytes compiled twice produce two independent
    /// `EmbedderModule` values (no global cache at this layer). Callers
    /// that reuse a module across many calls should keep the
    /// `EmbedderModule` alive and call `run` on it repeatedly.
    pub fn compile<F>(&self, wasm: &[u8], wasi: bool, setup: F) -> Result<EmbedderModule>
    where
        F: FnOnce(&mut EmbedderLinker<'_>) -> Result<()>,
    {
        let module = Module::new(&self.engine, wasm)
            .map_err(|e| AfterburnerError::CompileFailed(format!("embedder compile: {e}")))?;

        let mut raw_linker: Linker<EmbedderState> = Linker::new(&self.engine);

        if wasi {
            // Invariant: this accessor is only registered when `wasi == true`;
            // every `run` call on such a module builds `EmbedderState::wasi = Some(...)`,
            // so `wasi.as_mut()` is always `Some` here.
            add_to_linker_sync(&mut raw_linker, |s| {
                s.wasi
                    .as_mut()
                    .map(|w| &mut w.ctx)
                    .unwrap_or_else(|| unreachable!("wasi accessor reached a non-WASI store"))
            })
            .map_err(|e| AfterburnerError::Engine(format!("embedder wasi linker: {e}")))?;
        }

        // Embedder-supplied imports wired after WASI so the callback can
        // override WASI definitions if needed (unusual but not forbidden).
        let mut linker_ref = EmbedderLinker {
            inner: &mut raw_linker,
        };
        setup(&mut linker_ref)?;

        let instance_pre = raw_linker
            .instantiate_pre(&module)
            .map_err(|e| AfterburnerError::Engine(format!("embedder instantiate_pre: {e}")))?;

        Ok(EmbedderModule {
            engine: self.engine.clone(),
            instance_pre: Arc::new(instance_pre),
            wasi,
        })
    }

    /// Execute the named export of `module`, returning its i64 result and
    /// any stdout bytes the module wrote.
    ///
    /// A fresh `Store` is created for every call so runs are fully isolated.
    /// The `InstancePre` inside `module` is shared (reference-counted), so
    /// repeated calls reuse the compiled native code without re-linking.
    ///
    /// `export` - the name of the exported function to call. It must accept
    /// no parameters and return exactly one i64. Any other signature
    /// surfaces as `AfterburnerError::Engine`.
    ///
    /// `fuel` - optional instruction budget. `None` uses the crate-internal
    /// default (100 million instructions). Pass `Some(u64::MAX)` for an effectively unlimited
    /// budget (production callers should supply an explicit bound so runaway
    /// modules surface as `FuelExhausted` rather than hanging the thread).
    pub fn run(
        &self,
        module: &EmbedderModule,
        export: &str,
        fuel: Option<u64>,
    ) -> Result<EmbedderRunOutput> {
        // Build the store state. For WASI modules, create the pipe once and
        // share it: one clone goes to the WASI context (receives the writes),
        // the other is kept in `WasiStateInner::stdout` for reading after the run.
        let state = if module.wasi {
            let pipe = MemoryOutputPipe::new(1024 * 1024);
            let ctx = WasiCtxBuilder::new().stdout(pipe.clone()).build_p1();
            EmbedderState {
                wasi: Some(WasiStateInner { ctx, stdout: pipe }),
                pyodide_memory: None,
                pyodide_table: None,
                pyodide_stack_pointer: None,
                pyodide_side_stack_pointer: None,
                pyodide_cpp_exception_tag: None,
                pyodide_c_longjmp_tag: None,
                wasi_stdout: Vec::new(),
                fs: InMemFs::new(),
                last_invoke_idx: u64::MAX,
                cxa_thrown_ptr: 0,
                cxa_throw_count: 0,
                cxa_throw_log: Vec::new(),
                fs_path_log: std::collections::VecDeque::new(),
                side_modules: SideModuleRegistry::new(),
                main_instance: None,
                ffi_free_slots: Vec::new(),
            }
        } else {
            EmbedderState {
                wasi: None,
                pyodide_memory: None,
                pyodide_table: None,
                pyodide_stack_pointer: None,
                pyodide_side_stack_pointer: None,
                pyodide_cpp_exception_tag: None,
                pyodide_c_longjmp_tag: None,
                wasi_stdout: Vec::new(),
                fs: InMemFs::new(),
                last_invoke_idx: u64::MAX,
                cxa_thrown_ptr: 0,
                cxa_throw_count: 0,
                cxa_throw_log: Vec::new(),
                fs_path_log: std::collections::VecDeque::new(),
                side_modules: SideModuleRegistry::new(),
                main_instance: None,
                ffi_free_slots: Vec::new(),
            }
        };

        let mut store = Store::new(&module.engine, state);
        store
            .set_fuel(fuel.unwrap_or(DEFAULT_FUEL))
            .map_err(|e| AfterburnerError::Engine(format!("embedder set_fuel: {e}")))?;

        let instance = module
            .instance_pre
            .instantiate(&mut store)
            .map_err(|e| AfterburnerError::Engine(format!("embedder instantiate: {e}")))?;

        let func = instance
            .get_typed_func::<(), i64>(&mut store, export)
            .map_err(|e| {
                AfterburnerError::Engine(format!(
                    "embedder export `{export}`: {e} \
                     (must exist and have signature () -> i64)"
                ))
            })?;

        let result = func.call(&mut store, ()).map_err(|trap| {
            if let Some(t) = trap.downcast_ref::<Trap>() {
                return match t {
                    Trap::OutOfFuel => AfterburnerError::FuelExhausted,
                    Trap::Interrupt => AfterburnerError::Timeout,
                    other => AfterburnerError::WasmTrap(format!("embedder trap: {other}")),
                };
            }
            AfterburnerError::WasmTrap(format!("embedder trap: {trap}"))
        })?;

        let stdout = match store.into_data().wasi {
            Some(w) => w.stdout.contents().to_vec(),
            None => Vec::new(),
        };

        // `run` wires no stderr pipe (the typed-export path is for pure compute,
        // not a command emitting diagnostics); stderr is captured by
        // `run_command` instead.
        Ok(EmbedderRunOutput {
            result,
            stdout,
            stderr: Vec::new(),
        })
    }

    /// Run a WASI *command* module: one that exports `_start` with signature
    /// `() -> ()` and signals its exit code via `proc_exit`.
    ///
    /// Unlike [`run`][Self::run], `run_command`:
    ///
    /// * Calls `_start` (no typed result - the module exits via `proc_exit`).
    /// * Threads argv and preopened directories from `opts` into the WASI
    ///   context so the module can read its arguments and access its stdlib.
    /// * Returns `Ok(EmbedderRunOutput { result: exit_code, stdout, stderr })`
    ///   on a clean exit (exit code 0 is success; non-zero is surfaced in
    ///   `result` rather than as an error, matching POSIX convention). Both
    ///   fd 1 (`stdout`) and fd 2 (`stderr`) are captured.
    /// * Returns `Err(AfterburnerError::FuelExhausted)` if the module runs out
    ///   of fuel, and `Err(AfterburnerError::WasmTrap(_))` for any other trap.
    ///
    /// The module must be compiled with `wasi: true`; `run_command` asserts
    /// this and returns `AfterburnerError::Engine` if not.
    ///
    /// ## CPython example
    ///
    /// ```no_run
    /// use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};
    ///
    /// let wasm = std::fs::read("/tmp/python.wasm").unwrap();
    /// let vm = EmbedderVm::new().unwrap();
    /// let module = vm.compile(&wasm, true, |_| Ok(())).unwrap();
    /// let opts = WasiCommandOpts::new()
    ///     .args(["python", "-c", "print(sum(range(100)))"]);
    /// let out = vm.run_command(&module, opts, None).unwrap();
    /// println!("{}", String::from_utf8_lossy(&out.stdout));
    /// ```
    pub fn run_command(
        &self,
        module: &EmbedderModule,
        opts: WasiCommandOpts,
        fuel: Option<u64>,
    ) -> Result<EmbedderRunOutput> {
        if !module.wasi {
            return Err(AfterburnerError::Engine(
                "run_command requires a module compiled with wasi: true".into(),
            ));
        }

        let pipe = MemoryOutputPipe::new(4 * 1024 * 1024);
        // Capture stderr too. A command module (CRuby, a C program) writes its
        // diagnostics to fd 2; without this they are silently dropped and a
        // failing run looks like an empty success. The pipe is read after the
        // run via this retained handle (it is `Clone`; the clone goes to the
        // ctx, this copy stays here).
        let err_pipe = MemoryOutputPipe::new(4 * 1024 * 1024);

        let mut builder = WasiCtxBuilder::new();
        builder.stdout(pipe.clone()).stderr(err_pipe.clone());

        if !opts.args.is_empty() {
            builder.args(&opts.args);
        }

        for (key, val) in &opts.env_vars {
            builder.env(key, val);
        }

        for (host_path, guest_path) in &opts.preopens_ro {
            builder
                .preopened_dir(host_path, guest_path, DirPerms::READ, FilePerms::READ)
                .map_err(|e| {
                    AfterburnerError::Engine(format!(
                        "embedder preopen-ro {}: {e}",
                        host_path.display()
                    ))
                })?;
        }

        for (host_path, guest_path) in &opts.preopens_rw {
            builder
                .preopened_dir(host_path, guest_path, DirPerms::all(), FilePerms::all())
                .map_err(|e| {
                    AfterburnerError::Engine(format!(
                        "embedder preopen-rw {}: {e}",
                        host_path.display()
                    ))
                })?;
        }

        let ctx = builder.build_p1();
        let state = EmbedderState {
            wasi: Some(WasiStateInner { ctx, stdout: pipe }),
            pyodide_memory: None,
            pyodide_table: None,
            pyodide_stack_pointer: None,
            pyodide_side_stack_pointer: None,
            pyodide_cpp_exception_tag: None,
            pyodide_c_longjmp_tag: None,
            wasi_stdout: Vec::new(),
            fs: InMemFs::new(),
            last_invoke_idx: u64::MAX,
            cxa_thrown_ptr: 0,
            cxa_throw_count: 0,
            cxa_throw_log: Vec::new(),
            fs_path_log: std::collections::VecDeque::new(),
            side_modules: SideModuleRegistry::new(),
            main_instance: None,
            ffi_free_slots: Vec::new(),
        };

        let mut store = Store::new(&module.engine, state);
        store
            .set_fuel(fuel.unwrap_or(DEFAULT_FUEL))
            .map_err(|e| AfterburnerError::Engine(format!("embedder set_fuel: {e}")))?;

        let instance = module
            .instance_pre
            .instantiate(&mut store)
            .map_err(|e| AfterburnerError::Engine(format!("embedder instantiate: {e}")))?;

        let start_fn = instance.get_func(&mut store, "_start").ok_or_else(|| {
            AfterburnerError::Engine(
                "module does not export `_start` (not a WASI command module)".into(),
            )
        })?;

        // Call _start with no params and no expected results.
        // proc_exit() causes an anyhow error wrapping I32Exit; any other trap
        // surfaces as WasmTrap. We extract the stdout before returning in all
        // paths so captures are never lost.
        let call_result = start_fn.call(&mut store, &[], &mut []);

        let stdout = match store.into_data().wasi {
            Some(w) => w.stdout.contents().to_vec(),
            None => Vec::new(),
        };

        let exit_code = match call_result {
            Ok(_) => 0i64,
            Err(ref e) => {
                // proc_exit(N) produces I32Exit(N). Depending on the wasmtime
                // version, I32Exit may be the outermost error (direct downcast)
                // or buried inside an anyhow context chain; check both.
                let i32_exit = e
                    .downcast_ref::<I32Exit>()
                    .or_else(|| e.chain().find_map(|cause| cause.downcast_ref::<I32Exit>()));
                if let Some(exit) = i32_exit {
                    exit.0 as i64
                } else if let Some(t) = e.downcast_ref::<Trap>() {
                    return match t {
                        Trap::OutOfFuel => Err(AfterburnerError::FuelExhausted),
                        Trap::Interrupt => Err(AfterburnerError::Timeout),
                        other => Err(AfterburnerError::WasmTrap(format!(
                            "embedder command trap: {other}"
                        ))),
                    };
                } else {
                    return Err(AfterburnerError::WasmTrap(format!(
                        "embedder command trap: {e}"
                    )));
                }
            }
        };

        Ok(EmbedderRunOutput {
            result: exit_code,
            stdout,
            stderr: err_pipe.contents().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests;
