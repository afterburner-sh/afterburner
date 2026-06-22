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
        GOT_FUNC_NAMES, GotGlobalMap, PYODIDE_TABLE_WITH_GOT_SIZE, prefill_got_func_globals,
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

/// Initial memory size in pages for pyodide.asm.wasm (from dylink.0 mem-info).
pub const PYODIDE_MEMORY_INITIAL_PAGES: u32 = 320;

/// Maximum memory pages allowed (32768 = 2 GiB, Pyodide's declared max).
pub const PYODIDE_MEMORY_MAX_PAGES: u32 = 32768;

/// Initial size of the indirect function table.
///
/// Emscripten's `dylink.0` section declares `table_size = 6642` for
/// `pyodide.asm.wasm`. The element segment starts at `__table_base` (the
/// host provides this as a global). With `table_base = 1` (the standard
/// Emscripten convention that reserves index 0 as a null/trap slot), the
/// table must be at least `table_base + table_size = 1 + 6642 = 6643`.
pub const PYODIDE_TABLE_INITIAL_SIZE: u32 = 6643;

/// Stack base for the CPython stack. Top of dylink.0 data segment plus 5 MiB.
///
/// vertexia: fixed stack base; upgrade path is to read `__stack_pointer`
/// export after data-reloc to get the actual initial value.
pub const PYODIDE_STACK_BASE: u32 = 4_632_232 + 5 * 1024 * 1024;

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

/// Wire `env.memory`, `env.__indirect_function_table`, the three env base
/// globals, and ALL GOT.* globals into a store-bound linker.
///
/// Everything is created in `store` to satisfy wasmtime's same-store
/// requirement. Must be called with the exact store passed to instantiate.
///
/// The table is sized to `PYODIDE_TABLE_WITH_GOT_SIZE` (module slots +
/// host-GOT slots) so that `fill_got_table_slots` can place host funcrefs
/// into the pre-reserved host slots after instantiation.
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
    let mem_ty = MemoryType::new(PYODIDE_MEMORY_INITIAL_PAGES, Some(PYODIDE_MEMORY_MAX_PAGES));
    let memory = wasmtime::Memory::new(&mut *store, mem_ty)
        .map_err(|e| AfterburnerError::Engine(format!("pyodide memory: {e}")))?;
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
    // [PYODIDE_TABLE_INITIAL_SIZE .. PYODIDE_TABLE_WITH_GOT_SIZE).
    let tbl_ty = TableType::new(
        wasmtime::RefType::FUNCREF,
        PYODIDE_TABLE_WITH_GOT_SIZE,
        None,
    );
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
    // DIAG: log every dispatch so the probe can see what table slot was requested
    // and whether it holds a null funcref.
    let slot_content = tbl.get(&mut caller, idx);
    let is_null = !matches!(&slot_content, Some(wasmtime::Ref::Func(Some(_))));
    eprintln!(
        "[invoke_dispatch] idx={idx} slot={slot_content:?} null={is_null} params_len={}",
        params.len()
    );
    let Some(wasmtime::Ref::Func(Some(func))) = slot_content else {
        return Err(wasmtime::Trap::UnreachableCodeReached.into());
    };
    func.call(&mut caller, &params[1..], results)
}

/// Scan `module`'s import list and fill any remaining unsatisfied function
/// imports with a trap stub. Returns the list of auto-filled import names.
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
            let _ = linker.func_new(&m, &n, ft, |_, _, _| {
                Err(wasmtime::Error::msg("unimplemented import"))
            });
        }
    }
    auto_filled
}
