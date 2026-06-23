// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Full Emscripten environment import layer for Pyodide's `pyodide.asm.wasm`.
//!
//! ## Scope
//!
//! Provides ALL imports that `pyodide.asm.wasm` (0.26.4) requires:
//!
//! - 288 `env.*` functions (pure i32/i64/f64 implemented; externref JS-FFI
//!   recorded-and-trap stubs)
//! - 3 `env.*` globals (`__memory_base`, `__stack_pointer`, `__table_base`)
//! - 169 `GOT.func.*` globals (i32 mutable, zero-initialized)
//! - 3 `GOT.mem.*` globals (`__heap_base`, `__stack_low`, `__stack_high`)
//! - 1 `env.memory` linear memory (320 initial pages, 32768 max)
//! - 1 `env.__indirect_function_table` funcref table (6642 initial)
//!
//! ## Cross-store constraint
//!
//! `env.memory`, `env.__indirect_function_table`, all `env.__*_base` globals,
//! and ALL GOT.* globals must be created in the exact `Store` later passed to
//! `linker.instantiate`. Call [`wire_env_memory_and_table_in_store`] (which
//! creates all of these) immediately before instantiation, using the same store.
//!
//! ## WASI
//!
//! [`add_pyodide_imports`] wires `wasi_snapshot_preview1` via custom host
//! shims in [`crate::emscripten_wasi`]. These shims access guest memory
//! through `EmbedderState::pyodide_memory` (the `env.memory` import handle)
//! rather than `caller.get_export("memory")`, which does not exist because
//! Emscripten modules import rather than export their linear memory.
//!
//! After calling `wire_env_memory_and_table_in_store`, the returned `Memory`
//! handle is set into the store: `store.data_mut().pyodide_memory = Some(mem)`.
//! The store must be created with [`EmbedderState::for_emscripten`].
//!
//! ## Determinism
//!
//! All clock functions return fixed virtual constants from
//! [`crate::emscripten_abi`]. No real wall clock.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::{
    embedder_vm::EmbedderState,
    emscripten_dylink::{
        GOT_FUNC_NAMES, GotGlobalMap, WASM_TABLE_WITH_GOT_SIZE, prefill_got_func_globals,
        prefill_got_mem_globals,
    },
    emscripten_jsffi::wire_jsffi_stubs,
    emscripten_mechanical::wire_mechanical_env_funcs,
    emscripten_wasi::wire_wasi_snapshot_preview1,
};
use afterburner_core::{AfterburnerError, Result};
use wasmtime::{
    Engine, Global, GlobalType, Linker, MemoryType, Mutability, Table, TableType, Val, ValType,
};

// ---- ref-type-safe value default --------------------------------------------

/// Return the correct zero/null [`Val`] for a declared [`ValType`].
///
/// wasmtime pre-initializes every result slot in a `func_new` closure with
/// `Val::null_func_ref()` (i.e. `Val::FuncRef(None)`, which has type
/// `(ref null nofunc)`). Matching on the pre-initialized value is therefore
/// wrong for externref-typed slots: the match arm `Val::FuncRef(_)` fires and
/// leaves the slot as `(ref null nofunc)`, but the module expects
/// `(ref null extern)`. Keying off the declared type avoids the mismatch.
pub(crate) fn default_val_for(vt: &ValType) -> Val {
    // `ValType::default_value()` returns `Some` for all nullable refs and all
    // primitives. Non-nullable ref types return `None` (they have no default),
    // but import stubs must always have a return value, so fall back to the
    // null funcref (the wasmtime pre-fill) - those won't appear in practice
    // for Pyodide's externref-bearing imports.
    vt.default_value().unwrap_or(Val::FuncRef(None))
}

// ---- mechanical env.* call trace --------------------------------------------

/// Capacity of the mechanical-call ring buffer (power of two).
const MECH_RING_CAP: usize = 64;

/// One recorded mechanical env.* call.
#[derive(Clone, Debug)]
pub struct MechCallEntry {
    /// The function name (e.g. `"__syscall_openat"`).
    pub name: &'static str,
    /// First integer argument (fd / dirfd / path ptr), or 0 when not applicable.
    pub arg0: i32,
    /// Second integer argument, or 0 when not applicable.
    pub arg1: i32,
}

/// Shared lock-free-ish ring buffer of the last `MECH_RING_CAP` mechanical
/// env.* calls. Single-threaded wasmtime execution means the `Mutex` is never
/// contended; it serves only to satisfy `Send + Sync` for `Arc`.
pub struct MechCallLog {
    ring: Mutex<VecDeque<MechCallEntry>>,
}

impl MechCallLog {
    /// Create a new, empty log.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ring: Mutex::new(VecDeque::with_capacity(MECH_RING_CAP)),
        })
    }

    /// Record one mechanical env.* call. Keeps only the last `MECH_RING_CAP` entries.
    pub fn push(&self, name: &'static str, arg0: i32, arg1: i32) {
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() == MECH_RING_CAP {
            ring.pop_front();
        }
        ring.push_back(MechCallEntry { name, arg0, arg1 });
    }

    /// Return the last `n` entries in chronological order.
    pub fn tail(&self, n: usize) -> Vec<MechCallEntry> {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let skip = ring.len().saturating_sub(n);
        ring.iter().skip(skip).cloned().collect()
    }

    /// Total entries ever pushed (wraps at `usize::MAX`, irrelevant for diagnostics).
    pub fn len(&self) -> usize {
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Returns true if no entries have been recorded.
    pub fn is_empty(&self) -> bool {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
}

// ---- wasmtime Result alias ---------------------------------------------------

pub(crate) type WtResult<T> = wasmtime::Result<T>;

// ---- JS-FFI call log ---------------------------------------------------------

/// Shared log of JS-FFI function names called during the Pyodide boot attempt.
///
/// Lock-free: each stub uses `kovan_map::HashMap::get_or_insert` (CAS-based)
/// to mark the name as called, and a separate `AtomicUsize` for the total.
pub struct JsFfiCallLog {
    names: kovan_map::HashMap<String, u64>,
    total: AtomicUsize,
}

impl JsFfiCallLog {
    /// Create an empty log.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            names: kovan_map::HashMap::new(),
            total: AtomicUsize::new(0),
        })
    }

    /// Record one call to `name`. Lock-free.
    pub fn record(&self, name: &str) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.names.get_or_insert(name.to_owned(), 1);
    }

    /// Return all recorded function names, sorted.
    pub fn snapshot(&self) -> Vec<String> {
        let mut out: Vec<String> = self.names.iter().map(|(k, _v)| k).collect();
        out.sort_unstable();
        out
    }

    /// Total number of JS-FFI calls recorded (including repeated calls).
    pub fn total_calls(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

// ---- sizes / constants -------------------------------------------------------

/// Wasm page size: 64 KiB.
const WASM_PAGE_BYTES: u64 = 65_536;

/// Hard ceiling imposed by the wasm32 address space: 4 GiB.
const WASM32_MAX_BYTES: u64 = 4_294_967_296;

/// Default initial linear memory: 30 MiB (480 pages), matching the payload's
/// dylink.0 mem-info rounded up to page granularity.
const DEFAULT_MEMORY_INITIAL_BYTES: u64 = 31_457_280; // 30 MiB

/// Default maximum linear memory: 4 GiB - the wasm32 address-space ceiling.
/// The payload was built with MAXIMUM=4GB so this matches the expected upper bound.
const DEFAULT_MEMORY_MAX_BYTES: u64 = WASM32_MAX_BYTES;

/// Default stack size: 10 MiB, matching the payload build flag `-sSTACK_SIZE=10MB`.
const DEFAULT_STACK_SIZE_BYTES: u64 = 10_485_760; // 10 MiB

/// Validate and convert three byte values into a [`WasmMemoryConfig`].
///
/// All three values are in bytes. Validation rules:
/// - initial > 0, max > 0, stack > 0
/// - max <= 4 GiB (wasm32 limit)
/// - initial <= max
///
/// This is the pure core used by [`wasm_memory_config`] (which reads from env)
/// and by unit tests (which call with explicit byte values directly).
pub fn wasm_memory_config_from(
    initial_bytes: u64,
    max_bytes: u64,
    stack_bytes: u64,
) -> std::result::Result<WasmMemoryConfig, String> {
    if initial_bytes == 0 {
        return Err("BURN_WASM_MEMORY_INITIAL_BYTES must be > 0".to_owned());
    }
    if max_bytes == 0 {
        return Err("BURN_WASM_MEMORY_MAX_BYTES must be > 0".to_owned());
    }
    if stack_bytes == 0 {
        return Err("BURN_WASM_STACK_SIZE_BYTES must be > 0".to_owned());
    }
    if max_bytes > WASM32_MAX_BYTES {
        return Err(format!(
            "BURN_WASM_MEMORY_MAX_BYTES={max_bytes} exceeds wasm32 limit ({WASM32_MAX_BYTES})"
        ));
    }
    if initial_bytes > max_bytes {
        return Err(format!(
            "BURN_WASM_MEMORY_INITIAL_BYTES={initial_bytes} > BURN_WASM_MEMORY_MAX_BYTES={max_bytes}"
        ));
    }
    // Convert bytes to pages, rounding up.
    let initial_pages = initial_bytes.div_ceil(WASM_PAGE_BYTES) as u32;
    let max_pages = max_bytes.div_ceil(WASM_PAGE_BYTES) as u32;
    Ok(WasmMemoryConfig {
        initial_pages,
        max_pages,
        stack_size_bytes: stack_bytes as u32,
    })
}

/// Parse `BURN_WASM_MEMORY_INITIAL_BYTES`, `BURN_WASM_MEMORY_MAX_BYTES`, and
/// `BURN_WASM_STACK_SIZE_BYTES` from the environment and return validated page
/// counts and a byte-size stack value.
///
/// Validation rules (all return `Err` with a human-readable message on failure):
/// - initial > 0, max > 0, stack > 0
/// - max <= 4 GiB (wasm32 limit)
/// - initial <= max
///
/// Env vars absent or empty fall back to the documented defaults.
pub fn wasm_memory_config() -> std::result::Result<WasmMemoryConfig, String> {
    fn parse_env(name: &str, default: u64) -> std::result::Result<u64, String> {
        match std::env::var(name) {
            Ok(s) if !s.is_empty() => s
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("{name}={s:?} is not a valid u64: {e}")),
            _ => Ok(default),
        }
    }

    let initial_bytes = parse_env(
        "BURN_WASM_MEMORY_INITIAL_BYTES",
        DEFAULT_MEMORY_INITIAL_BYTES,
    )?;
    let max_bytes = parse_env("BURN_WASM_MEMORY_MAX_BYTES", DEFAULT_MEMORY_MAX_BYTES)?;
    let stack_bytes = parse_env("BURN_WASM_STACK_SIZE_BYTES", DEFAULT_STACK_SIZE_BYTES)?;
    wasm_memory_config_from(initial_bytes, max_bytes, stack_bytes)
}

/// Resolved and validated wasm memory configuration.
#[derive(Clone, Copy, Debug)]
pub struct WasmMemoryConfig {
    /// Initial linear memory size in 64-KiB pages.
    pub initial_pages: u32,
    /// Maximum linear memory size in 64-KiB pages.
    pub max_pages: u32,
    /// Stack region size in bytes.
    pub stack_size_bytes: u32,
}

// ---- generic named constants -------------------------------------------------
//
// These express the same values as the legacy PYODIDE_* names but are generic
// and are used wherever a compile-time constant is needed. Callers that need the
// runtime-configurable values should call `wasm_memory_config()` instead.

/// Initial linear memory in pages (compile-time default: 480 pages = ~30 MiB).
///
/// Use `wasm_memory_config().initial_pages` for the env-driven value.
pub const WASM_MEMORY_INITIAL_PAGES: u32 = 480; // 30 MiB / 64 KiB

/// Maximum linear memory in pages (compile-time default: 65536 = 4 GiB).
///
/// Use `wasm_memory_config().max_pages` for the env-driven value.
pub const WASM_MEMORY_MAX_PAGES: u32 = 65_536; // 4 GiB / 64 KiB

/// Initial size of the indirect function table.
///
/// Emscripten's `dylink.0` section declares `table_size = 6642` for
/// `pyodide.asm.wasm`. The element segment starts at `__table_base` (the
/// host provides this as a global). With `table_base = 1` (the standard
/// Emscripten convention that reserves index 0 as a null/trap slot), the
/// table must be at least `table_base + table_size = 1 + 6642 = 6643`.
pub const WASM_TABLE_INITIAL_SIZE: u32 = 6643;

/// Stack base (= `__stack_high`) for CPython. Top of dylink.0 data segment
/// plus the default stack region (10 MiB). A smaller value causes
/// MemoryOutOfBounds when deep generic-alias machinery exhausts the C stack.
///
/// Use `wasm_memory_config().stack_size_bytes` to get the runtime-configurable
/// stack size; the base address is `DYLINK_MEMORY_SIZE + stack_size_bytes`.
///
/// vertexia: fixed stack base; upgrade path is to read `__stack_pointer`
/// export after data-reloc to get the actual initial value.
pub const WASM_STACK_BASE: u32 = 4_632_232 + 10 * 1024 * 1024;

// Backward-compatible aliases so callers that import by the old names still
// compile without changes. These will be removed in a follow-up cleanup.
#[doc(hidden)]
#[allow(non_upper_case_globals)]
pub const PYODIDE_MEMORY_INITIAL_PAGES: u32 = WASM_MEMORY_INITIAL_PAGES;
#[doc(hidden)]
#[allow(non_upper_case_globals)]
pub const PYODIDE_MEMORY_MAX_PAGES: u32 = WASM_MEMORY_MAX_PAGES;
#[doc(hidden)]
#[allow(non_upper_case_globals)]
pub const PYODIDE_TABLE_INITIAL_SIZE: u32 = WASM_TABLE_INITIAL_SIZE;
#[doc(hidden)]
#[allow(non_upper_case_globals)]
pub const PYODIDE_STACK_BASE: u32 = WASM_STACK_BASE;

// ---- public API --------------------------------------------------------------

/// Wire all `env.*` function imports and `wasi_snapshot_preview1.*` imports
/// into `linker`.
///
/// Does NOT wire memory, table, or any globals (those are store-bound); call
/// [`wire_env_memory_and_table_in_store`] with the instantiation store, then
/// set `store.data_mut().pyodide_memory = Some(mem)` with the returned handle.
///
/// The store must be created with [`EmbedderState::for_emscripten`] (not
/// `with_wasi`). Custom `wasi_snapshot_preview1` shims read guest memory via
/// `EmbedderState::pyodide_memory` because Emscripten modules import rather
/// than export their linear memory.
///
/// `js_log` receives the name of every JS-FFI stub call during execution.
/// Returns the [`MechCallLog`] that records every mechanical env.* call;
/// inspect it after a trap with [`MechCallLog::tail`] to diagnose the failure.
pub fn add_pyodide_imports(
    engine: &Engine,
    linker: &mut Linker<EmbedderState>,
    js_log: Arc<JsFfiCallLog>,
) -> Result<Arc<MechCallLog>> {
    // Custom WASI shims that read guest memory via EmbedderState::pyodide_memory
    // (the env.memory import handle). The standard wasmtime-wasi preview-1
    // cannot be used here because it calls caller.get_export("memory"), but
    // Emscripten modules import (not export) their linear memory.
    wire_wasi_snapshot_preview1(linker)?;

    let mech_log = MechCallLog::new();
    wire_mechanical_env_funcs(engine, linker, mech_log.clone())?;
    wire_jsffi_stubs(engine, linker, js_log)?;
    Ok(mech_log)
}

/// Wire WASI imports only, without mechanical env.* or JS-FFI stubs.
///
/// Use this for Pyodide 0.28+ modules translated to exnref via
/// `wasm-opt --translate-to-exnref`: the translation changes JS-FFI and some
/// mechanical import signatures (externref appears in former i32 positions),
/// making the 0.26.4-typed stubs incompatible. Callers should follow up with
/// [`fill_unknown_imports_as_traps`] passing the translated module so that all
/// remaining env.* imports are auto-filled from the module's actual types.
pub fn wire_wasi_only(linker: &mut Linker<EmbedderState>) -> Result<()> {
    wire_wasi_snapshot_preview1(linker)
}

/// Wire WASI + mechanical env imports without the JS-FFI type stubs.
///
/// Use this when the module was translated to exnref (Pyodide 0.28+ via
/// `wasm-opt --translate-to-exnref`): the exnref translation changes the
/// JS-FFI import signatures (i32 sentinel/externref args appear), making the
/// 0.26.4-typed stubs from [`wire_jsffi_stubs`] incompatible. Callers should
/// follow up with [`fill_unknown_imports_as_traps`] to auto-fill the remaining
/// JS-FFI imports from the module's actual types.
pub fn add_pyodide_imports_no_jsffi(
    engine: &Engine,
    linker: &mut Linker<EmbedderState>,
) -> Result<Arc<MechCallLog>> {
    wire_wasi_snapshot_preview1(linker)?;
    let mech_log = MechCallLog::new();
    wire_mechanical_env_funcs(engine, linker, mech_log.clone())?;
    Ok(mech_log)
}

/// Wire `env.memory`, `env.__indirect_function_table`, the three env base
/// globals, and ALL GOT.* globals into a store-bound linker.
///
/// Everything is created in `store` to satisfy wasmtime's same-store
/// requirement. Must be called with the exact store passed to instantiate.
///
/// Memory size is driven by the env vars `BURN_WASM_MEMORY_INITIAL_BYTES` and
/// `BURN_WASM_MEMORY_MAX_BYTES` (see [`wasm_memory_config`]). The table is
/// sized to `WASM_TABLE_WITH_GOT_SIZE` (module slots + host-GOT slots) so that
/// `fill_got_table_slots` can place host funcrefs into the pre-reserved host
/// slots after instantiation.
///
/// GOT.func globals are pre-filled with their pre-assigned table slot indices
/// (not zero) and GOT.mem globals are pre-filled with the known symbol
/// addresses. Both happen before instantiation so any code that reads these
/// globals during or after the active element segment fires sees valid values.
///
/// Sets `store.data_mut().pyodide_memory = Some(memory)` so the custom
/// `wasi_snapshot_preview1` shims can access guest linear memory via
/// `Caller::data()` rather than `caller.get_export("memory")`.
///
/// Returns the [`GotGlobalMap`] containing all `Global` handles keyed by
/// `"GOT.func::name"` and `"GOT.mem::name"`. Pass these to
/// `fill_got_table_slots` if further writes are needed (currently pre-filling
/// is complete).
pub fn wire_env_memory_and_table_in_store(
    store: &mut wasmtime::Store<EmbedderState>,
    linker: &mut Linker<EmbedderState>,
    memory_base: u32,
    table_base: u32,
    stack_base: u32,
) -> Result<GotGlobalMap> {
    let mem_cfg = wasm_memory_config()
        .map_err(|e| AfterburnerError::Engine(format!("wasm memory config: {e}")))?;
    let mem_ty = MemoryType::new(mem_cfg.initial_pages, Some(mem_cfg.max_pages));
    let memory = wasmtime::Memory::new(&mut *store, mem_ty)
        .map_err(|e| AfterburnerError::Engine(format!("wasm memory: {e}")))?;
    // Store the handle in EmbedderState so custom WASI shims can access
    // guest linear memory without relying on a "memory" export (which
    // Emscripten modules do not provide - they import, not export, memory).
    store.data_mut().pyodide_memory = Some(memory);
    linker
        .define(
            &mut *store,
            "env",
            "memory",
            wasmtime::Extern::Memory(memory),
        )
        .map_err(|e| AfterburnerError::Engine(format!("define env.memory: {e}")))?;

    // Size = module element region + pre-reserved host GOT slots.
    // The active element segment fires at instantiation and fills slots
    // [table_base .. table_base + 6642); host GOT slots follow at
    // [WASM_TABLE_INITIAL_SIZE .. WASM_TABLE_WITH_GOT_SIZE).
    let tbl_ty = TableType::new(wasmtime::RefType::FUNCREF, WASM_TABLE_WITH_GOT_SIZE, None);
    let table = Table::new(&mut *store, tbl_ty, wasmtime::Ref::Func(None))
        .map_err(|e| AfterburnerError::Engine(format!("pyodide table: {e}")))?;
    // Store the handle in EmbedderState so invoke_dispatch can reach the table
    // via caller.data().pyodide_table. caller.get_export("__indirect_function_table")
    // only resolves module *exports*; this module imports the table, not exports it.
    store.data_mut().pyodide_table = Some(table);
    linker
        .define(
            &mut *store,
            "env",
            "__indirect_function_table",
            wasmtime::Extern::Table(table),
        )
        .map_err(|e| {
            AfterburnerError::Engine(format!("define env.__indirect_function_table: {e}"))
        })?;

    // env.__memory_base: immutable i32.
    let mb = Global::new(
        &mut *store,
        GlobalType::new(ValType::I32, Mutability::Const),
        Val::I32(memory_base as i32),
    )
    .map_err(|e| AfterburnerError::Engine(format!("__memory_base global: {e}")))?;
    linker
        .define(
            &mut *store,
            "env",
            "__memory_base",
            wasmtime::Extern::Global(mb),
        )
        .map_err(|e| AfterburnerError::Engine(format!("define env.__memory_base: {e}")))?;

    // env.__table_base: immutable i32.
    let tb = Global::new(
        &mut *store,
        GlobalType::new(ValType::I32, Mutability::Const),
        Val::I32(table_base as i32),
    )
    .map_err(|e| AfterburnerError::Engine(format!("__table_base global: {e}")))?;
    linker
        .define(
            &mut *store,
            "env",
            "__table_base",
            wasmtime::Extern::Global(tb),
        )
        .map_err(|e| AfterburnerError::Engine(format!("define env.__table_base: {e}")))?;

    // env.__stack_pointer: mutable i32.
    let sp = Global::new(
        &mut *store,
        GlobalType::new(ValType::I32, Mutability::Var),
        Val::I32(stack_base as i32),
    )
    .map_err(|e| AfterburnerError::Engine(format!("__stack_pointer global: {e}")))?;
    linker
        .define(
            &mut *store,
            "env",
            "__stack_pointer",
            wasmtime::Extern::Global(sp),
        )
        .map_err(|e| AfterburnerError::Engine(format!("define env.__stack_pointer: {e}")))?;

    // GOT.func and GOT.mem globals: mutable i32.
    // We collect handles into a map so callers can pre-fill and update them.
    let mut got_globals: GotGlobalMap = HashMap::new();
    let got_ty = GlobalType::new(ValType::I32, Mutability::Var);

    for name in GOT_FUNC_NAMES {
        let g = Global::new(&mut *store, got_ty.clone(), Val::I32(0))
            .map_err(|e| AfterburnerError::Engine(format!("GOT.func.{name}: {e}")))?;
        linker
            .define(&mut *store, "GOT.func", name, wasmtime::Extern::Global(g))
            .map_err(|e| AfterburnerError::Engine(format!("define GOT.func.{name}: {e}")))?;
        got_globals.insert(format!("GOT.func::{name}"), g);
    }
    for name in GOT_MEM_NAMES {
        let g = Global::new(&mut *store, got_ty.clone(), Val::I32(0))
            .map_err(|e| AfterburnerError::Engine(format!("GOT.mem.{name}: {e}")))?;
        linker
            .define(&mut *store, "GOT.mem", name, wasmtime::Extern::Global(g))
            .map_err(|e| AfterburnerError::Engine(format!("define GOT.mem.{name}: {e}")))?;
        got_globals.insert(format!("GOT.mem::{name}"), g);
    }

    // Pre-fill GOT.func with pre-assigned table slot indices (not zero).
    // Pre-fill GOT.mem with known symbol addresses.
    prefill_got_func_globals(store, &got_globals)?;
    prefill_got_mem_globals(store, &got_globals, memory_base, stack_base)?;

    Ok(got_globals)
}

// ---- GOT.mem name table ------------------------------------------------------
// GOT.func names live in emscripten_dylink::GOT_FUNC_NAMES (imported above).

const GOT_MEM_NAMES: &[&str] = &["__heap_base", "__stack_low", "__stack_high"];

// ---- invoke_* dispatch helper -----------------------------------------------
//
// Emscripten compiles C++ virtual dispatch through `invoke_*` trampolines.
// Each trampoline takes `(i32 table_index, ...forwarded_args)` and calls the
// funcref at `table_index` in `__indirect_function_table`.
//
// All invoke_* share one generic dispatch path: params[0] is the index,
// params[1..] are forwarded to the funcref. The result is written to results.

pub(crate) fn invoke_dispatch(
    mut caller: wasmtime::Caller<'_, EmbedderState>,
    params: &[Val],
    results: &mut [Val],
) -> WtResult<()> {
    let idx = match params.first() {
        Some(Val::I32(i)) => *i as u64,
        _ => return Err(wasmtime::Trap::UnreachableCodeReached.into()),
    };
    // The table is a host-defined import, not a module export. caller.get_export
    // only resolves module exports, so we read the handle stored in EmbedderState
    // by wire_env_memory_and_table_in_store.
    let Some(tbl) = caller.data().pyodide_table else {
        return Err(wasmtime::Trap::UnreachableCodeReached.into());
    };
    // Record this dispatch so the probe can read the last active table index
    // from store.data().last_invoke_idx when a trap is reported.
    caller.data_mut().last_invoke_idx = idx;

    let slot_content = tbl.get(&mut caller, idx);
    let is_null = !matches!(&slot_content, Some(wasmtime::Ref::Func(Some(_))));
    eprintln!(
        "[invoke_dispatch] idx={idx} slot_is_null={is_null} params_len={}",
        params.len()
    );
    let Some(wasmtime::Ref::Func(Some(func))) = slot_content else {
        // Return a named error (not a Trap) so the probe's "debug chain" shows
        // the exact table index rather than just UnreachableCodeReached.
        return Err(wasmtime::Error::msg(format!(
            "invoke_dispatch: null or absent funcref at table[{idx}] (params_len={})",
            params.len()
        )));
    };
    // Emscripten's C ABI allows function-pointer casts that mismatch arity.
    // Wasmtime enforces strict arity, so we must call the callee with EXACTLY
    // its declared parameter count N:
    //   - if N < provided: truncate (extra trampoline args dropped, C ABI semantics).
    //   - if N > provided: pad with the zero/null default for each undeclared param.
    //
    // This is the CPython 3.13 emscripten trampoline pad-to-arity contract:
    // `wasmTable.get(func)(arg1, arg2, arg3)` in JS pads missing args with 0;
    // we replicate that here for the headless (no-reflection) path.
    // METH_FASTCALL|METH_KEYWORDS C functions take 4 i32 params (self, args, nargs,
    // kwnames); the trampoline is wired (i32,i32,i32,i32)->i32 and provides only
    // 3 forwarded args, so we pad the 4th with Val::I32(0). This fixes `import
    // typing` which uses such functions in `_typing`.
    let func_ty = func.ty(&caller);
    let forwarded = &params[1..];
    let call_params: Vec<Val> = func_ty
        .params()
        .enumerate()
        .map(|(i, vt)| {
            forwarded
                .get(i)
                .copied()
                .unwrap_or_else(|| default_val_for(&vt))
        })
        .collect();

    // Emscripten legacy JS EH semantics (invoke_<sig> contract):
    //
    //   var sp = stackSave();
    //   try { return callee(args); }
    //   catch(e) { stackRestore(sp); if (e !== e+0) throw e; setThrew(1,0); }
    //
    // Step 1: save the stack pointer via the module export.
    let saved_sp: i32 = if let Some(wasmtime::Extern::Func(f)) =
        caller.get_export("emscripten_stack_get_current")
    {
        let mut sp_out = [Val::I32(0)];
        if f.call(&mut caller, &[], &mut sp_out).is_ok() {
            match sp_out[0] {
                Val::I32(v) => v,
                _ => 0,
            }
        } else {
            0
        }
    } else {
        0
    };

    // Step 2: call the callee; handle a trap as a caught C++ exception.
    // vertexia: trap-based EH - destructors in intervening wasm frames do NOT
    // run (no stack unwinding). This is correct for CPython's EH boundary
    // (the exception is re-raised inside the interpreter loop), but C++
    // objects allocated between the invoke_ site and the throw site may leak.
    // Upgrade path: compile with Emscripten Wasm EH (-fwasm-exceptions) for
    // proper zero-cost EH with destructor support.
    let call_result = func.call(&mut caller, &call_params, results);
    if call_result.is_err() {
        // Step 3a: restore the stack pointer.
        if saved_sp != 0
            && let Some(wasmtime::Extern::Func(f)) = caller.get_export("_emscripten_stack_restore")
        {
            let _ = f.call(&mut caller, &[Val::I32(saved_sp)], &mut []);
        }
        // Step 3b: call setThrew(1, 0) to signal an exception was thrown.
        if let Some(wasmtime::Extern::Func(f)) = caller.get_export("setThrew") {
            let _ = f.call(&mut caller, &[Val::I32(1), Val::I32(0)], &mut []);
        }
        // Step 3c: fill results with the default zero for each return type,
        // then return Ok so the wasm caller (the landing pad) can run.
        for r in results.iter_mut() {
            *r = match &*r {
                Val::I32(_) => Val::I32(0),
                Val::I64(_) => Val::I64(0),
                Val::F32(_) => Val::F32(0),
                Val::F64(_) => Val::F64(0),
                other => *other,
            };
        }
        return Ok(());
    }
    Ok(())
}

// ---- no-op stub call log -----------------------------------------------------

/// Ring buffer that records the name of every auto-filled no-op stub that is
/// actually invoked during execution. Each stub emits its name to stderr on
/// first call and appends it to the ring. Use [`NoopCallLog::snapshot`] after a
/// trap to see which stubs CPython reached before failing.
pub struct NoopCallLog {
    ring: Mutex<VecDeque<String>>,
}

impl NoopCallLog {
    /// Create an empty log.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ring: Mutex::new(VecDeque::with_capacity(MECH_RING_CAP)),
        })
    }

    /// Record one call. Prints to stderr and appends to the ring.
    pub fn record(&self, name: &str) {
        eprintln!("[noop-stub CALLED] {name}");
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() == MECH_RING_CAP {
            ring.pop_front();
        }
        ring.push_back(name.to_owned());
    }

    /// Return all recorded calls in chronological order.
    pub fn snapshot(&self) -> Vec<String> {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

/// Scan `module`'s import list and fill any remaining unsatisfied function
/// imports with a trap stub. Returns the list of auto-filled import names.
/// Auto-fill all unsatisfied imports with no-ops (return zero/null for each result).
///
/// Use for bring-up probes where you want execution to continue past unknown
/// stubs rather than trap immediately. Returns the list of filled import names.
///
/// Every stub that is actually *called* at runtime logs its name via `call_log`
/// (to stderr immediately + to the ring buffer for post-mortem inspection).
///
/// Call after all known imports are registered (WASI + GOT + known stubs) so
/// only truly unknown functions get the no-op treatment.
pub fn fill_unknown_imports_as_noops(
    store: &mut wasmtime::Store<EmbedderState>,
    linker: &mut Linker<EmbedderState>,
    module: &wasmtime::Module,
    call_log: Arc<NoopCallLog>,
) -> Vec<String> {
    let mut auto_filled = Vec::new();
    for import in module.imports() {
        if linker
            .get(&mut *store, import.module(), import.name())
            .is_ok()
        {
            continue;
        }
        let full_name = format!("{}::{}", import.module(), import.name());
        auto_filled.push(full_name.clone());
        if let wasmtime::ExternType::Func(ft) = import.ty() {
            let m = import.module().to_owned();
            let n = import.name().to_owned();
            // Pre-compute the correct default for each result type from the
            // declared FuncType. wasmtime pre-fills every result slot with
            // `Val::FuncRef(None)` (`(ref null nofunc)`), so matching on the
            // slot's current value would return the wrong type for externref
            // results. Keying off the declared type is correct.
            let defaults: Vec<Val> = ft.results().map(|vt| default_val_for(&vt)).collect();
            let log = call_log.clone();
            let _ = linker.func_new(&m, &n, ft, move |_, _, results| {
                log.record(&full_name);
                for (r, d) in results.iter_mut().zip(defaults.iter()) {
                    *r = *d;
                }
                Ok(())
            });
        }
    }
    auto_filled
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use wasmtime::ValType;

    // ---- MechCallLog -------------------------------------------------------

    /// Ring drops oldest when capacity is exceeded; tail returns the last `n`.
    #[test]
    fn mech_call_log_ring_capacity() {
        const CAP: usize = 64;
        let log = MechCallLog::new();
        for i in 0..CAP + 1 {
            log.push("x", i as i32, 0);
        }
        assert_eq!(log.len(), CAP, "ring must cap at 64");
        let tail = log.tail(1);
        assert_eq!(tail[0].arg0, CAP as i32, "tail must be the last pushed");
    }

    /// Push "a", "b", "c"; tail(2) returns ["b", "c"] in order.
    #[test]
    fn mech_call_log_push_tail_ordering() {
        let log = MechCallLog::new();
        log.push("a", 0, 0);
        log.push("b", 0, 0);
        log.push("c", 0, 0);
        let tail = log.tail(2);
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].name, "b");
        assert_eq!(tail[1].name, "c");
    }

    // ---- JsFfiCallLog ------------------------------------------------------

    /// record + snapshot: sorted output; total_calls counts all including repeats.
    #[test]
    fn jsffi_call_log_record_snapshot() {
        let log = JsFfiCallLog::new();
        log.record("foo");
        log.record("foo");
        log.record("foo");
        log.record("bar");
        let snap = log.snapshot();
        assert!(snap.contains(&"bar".to_string()));
        assert!(snap.contains(&"foo".to_string()));
        assert_eq!(log.total_calls(), 4);
    }

    // ---- default_val_for ---------------------------------------------------

    /// I32 type yields Val::I32(0).
    #[test]
    fn default_val_for_i32() {
        let v = default_val_for(&ValType::I32);
        assert!(matches!(v, Val::I32(0)));
    }

    /// EXTERNREF type yields Val::ExternRef(None).
    #[test]
    fn default_val_for_externref() {
        let v = default_val_for(&ValType::EXTERNREF);
        assert!(matches!(v, Val::ExternRef(None)));
    }

    /// FUNCREF type yields a null funcref (Val::FuncRef(None)).
    #[test]
    fn default_val_for_funcref() {
        let v = default_val_for(&ValType::FUNCREF);
        assert!(matches!(v, Val::FuncRef(None)));
    }

    // ---- wasm_memory_config_from (pure, no env mutation) ----------------------

    /// Default byte values produce the documented page counts.
    #[test]
    fn wasm_memory_config_from_defaults() {
        // 30 MiB initial -> 480 pages; 4 GiB max -> 65536 pages; 10 MiB stack.
        let cfg = wasm_memory_config_from(31_457_280, 4_294_967_296, 10_485_760)
            .expect("default byte values must parse");
        assert_eq!(cfg.initial_pages, 480, "initial pages mismatch");
        assert_eq!(cfg.max_pages, 65_536, "max pages mismatch");
        assert_eq!(
            cfg.stack_size_bytes,
            10 * 1024 * 1024,
            "stack size mismatch"
        );
    }

    /// 2 GiB max produces 32768 pages.
    #[test]
    fn wasm_memory_config_from_2gib_max() {
        // 2 GiB = 2_147_483_648 bytes = 32768 pages
        let cfg = wasm_memory_config_from(31_457_280, 2_147_483_648, 10_485_760)
            .expect("2GiB max must parse");
        assert_eq!(cfg.max_pages, 32_768, "2GiB should be 32768 pages");
    }

    /// initial > max returns Err.
    #[test]
    fn wasm_memory_config_from_initial_gt_max_is_err() {
        // 2 pages initial, 1 page max.
        let result = wasm_memory_config_from(131_072, 65_536, 10_485_760);
        assert!(result.is_err(), "initial > max must return Err");
    }

    /// max > 4 GiB returns Err.
    #[test]
    fn wasm_memory_config_from_max_exceeds_wasm32_is_err() {
        let result = wasm_memory_config_from(65_536, 4_294_967_297, 10_485_760);
        assert!(result.is_err(), "max > 4GiB must return Err");
    }

    /// zero initial returns Err.
    #[test]
    fn wasm_memory_config_from_zero_initial_is_err() {
        let result = wasm_memory_config_from(0, 4_294_967_296, 10_485_760);
        assert!(result.is_err(), "zero initial must return Err");
    }

    /// 1 byte initial rounds up to 1 page.
    #[test]
    fn wasm_memory_config_from_bytes_round_up_to_pages() {
        let cfg =
            wasm_memory_config_from(1, 65_536, 10_485_760).expect("1-byte initial must parse");
        assert_eq!(cfg.initial_pages, 1, "1 byte should round up to 1 page");
    }

    /// Exactly one page initial stays at 1 page (no rounding needed).
    #[test]
    fn wasm_memory_config_from_exact_page_no_roundup() {
        let cfg =
            wasm_memory_config_from(65_536, 65_536, 10_485_760).expect("exact page must parse");
        assert_eq!(cfg.initial_pages, 1);
        assert_eq!(cfg.max_pages, 1);
    }
}

///
/// Call after [`add_pyodide_imports`] and [`wire_env_memory_and_table_in_store`]
/// so only truly unknown functions get auto-filled.
pub fn fill_unknown_imports_as_traps(
    store: &mut wasmtime::Store<EmbedderState>,
    linker: &mut Linker<EmbedderState>,
    module: &wasmtime::Module,
) -> Vec<String> {
    let mut auto_filled = Vec::new();
    for import in module.imports() {
        if linker
            .get(&mut *store, import.module(), import.name())
            .is_ok()
        {
            continue;
        }
        auto_filled.push(format!("{}::{}", import.module(), import.name()));
        if let wasmtime::ExternType::Func(ft) = import.ty() {
            let m = import.module().to_owned();
            let n = import.name().to_owned();
            // Include the import name in the error so the probe's debug chain
            // reveals which auto-filled stub fired under the trapped frame.
            let label = format!("unimplemented import: {}::{}", m, n);
            let _ = linker.func_new(&m, &n, ft, move |_, _, _| {
                Err(wasmtime::Error::msg(label.clone()))
            });
        }
    }
    auto_filled
}
