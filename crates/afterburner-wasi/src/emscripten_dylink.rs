// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Emscripten GOT resolution for standalone (no-JS) hosting of SIDE_MODULEs.
//!
//! ## What this solves
//!
//! `pyodide.asm.wasm` is an Emscripten SIDE_MODULE. It imports 181 `GOT.func.*`
//! and 3 `GOT.mem.*` mutable i32 globals. The standard JS loader populates them
//! after instantiation via `assignGOTEntries`. Without that step every read of a
//! GOT slot returns 0, which an indirect `call_indirect` uses as a table index -
//! slot 0 is the Wasm null/trap slot, so `__wasm_call_ctors` traps immediately.
//!
//! ## Algorithm (mirrors Emscripten's assignGOTEntries)
//!
//! GOT.func.<name>:
//!   - Parse the module bytes once (via `parse_got_name_to_slot`) to build a
//!     `name -> table_slot` map from the wasm name section + active element
//!     segments. This is the correct source: the element segments place function
//!     references at specific table slots at instantiation time, and the name
//!     section records which function index owns which name. 178 of 181 GOT.func
//!     symbols are internal module functions not exported by name; they are only
//!     reachable via this path.
//!   - Each GOT.func global is pre-assigned a stub table slot at
//!     `WASM_TABLE_INITIAL_SIZE + index` before instantiation so that any
//!     `call_indirect` that fires before `fill_got_table_slots` lands on a
//!     defined (stub) entry rather than the null slot.
//!   - After instantiation, `fill_got_table_slots` overwrites the GOT global with
//!     the real table slot from the parsed map (resolution order: name+elem map
//!     first, then module export fallback, else leave stub slot).
//!
//! GOT.mem.<name>:
//!   - `__heap_base` = `memory_base` + dylink.0 `memory_size` (4 632 232 bytes).
//!   - `__stack_high` = initial stack pointer (top of stack region).
//!   - `__stack_low`  = `__stack_high` - stack region size.
//!   - All three are written by `prefill_got_mem_globals` before instantiation
//!     via the `Global` handles returned from `wire_env_memory_and_table_in_store`.
//!
//! ## Call order in the probe
//!
//!   1. `parse_got_name_to_slot` - parse wasm bytes to build name->table_slot.
//!   2. `wire_env_memory_and_table_in_store` - creates memory/table/GOT globals,
//!      pre-fills GOT.func with stub slot indices, GOT.mem with symbol addresses.
//!   3. `linker.instantiate` - active element segment populates module slots
//!      [table_base .. table_base + table_size); host stub slots follow.
//!   4. `fill_got_table_slots` - updates GOT.func globals to real table slots
//!      using the parsed name->slot map; places host funcs into the table for
//!      names that resolved via a linker export.
//!   5. `__wasm_apply_data_relocs` - relocates data symbols relative to memory_base.
//!   6. `__wasm_call_ctors` - C++ / CPython static init.

use std::collections::HashMap;

use afterburner_core::{AfterburnerError, Result};
use wasmparser::{ElementItems, ElementKind, ExternalKind, Name, Operator, Parser, Payload};
use wasmtime::{
    AsContext, AsContextMut, ExternType, Func, FuncType, Global, Instance, Linker, Module,
    Mutability, Ref, Store, Val, ValType,
};

use crate::embedder_vm::EmbedderState;
use crate::emscripten_runtime::{WASM_TABLE_INITIAL_SIZE, default_val_for};

/// Memory size declared in `pyodide.asm.wasm`'s `dylink.0` section (bytes).
#[allow(dead_code)]
const DYLINK_MEMORY_SIZE: u32 = 4_632_232;

/// Stack region size. The payload links CPython with `-sSTACK_SIZE=10MB`. The C
/// stack overflows below `__stack_low` with a MemoryOutOfBounds trap when this is
/// set smaller than the actual build value.
///
/// Use `wasm_memory_config().stack_size_bytes` for the runtime-configurable value.
pub const WASM_STACK_SIZE: u32 = 10 * 1024 * 1024;

/// Number of host-slot entries: one per GOT.func symbol.
pub const GOT_FUNC_HOST_SLOTS: u32 = GOT_FUNC_NAMES.len() as u32;

/// Total table size that must be created: module region + host GOT slots.
///
/// Pass this to `TableType::new` instead of `WASM_TABLE_INITIAL_SIZE` so
/// the host slots exist before instantiation fires the active element segment.
pub const WASM_TABLE_WITH_GOT_SIZE: u32 = WASM_TABLE_INITIAL_SIZE + GOT_FUNC_HOST_SLOTS;

/// Pre-assigned table slot index for GOT.func entry at position `idx`
/// in `GOT_FUNC_NAMES`.
#[inline]
pub fn got_func_slot(idx: usize) -> u32 {
    WASM_TABLE_INITIAL_SIZE + idx as u32
}

// Backward-compatible aliases so existing callers continue to compile.
#[doc(hidden)]
pub const PYODIDE_STACK_SIZE: u32 = WASM_STACK_SIZE;
#[doc(hidden)]
pub const PYODIDE_TABLE_WITH_GOT_SIZE: u32 = WASM_TABLE_WITH_GOT_SIZE;

// ---- GOT global handles passed between wiring and resolution -----------------

/// Handles to every GOT global that was defined into the store by
/// `wire_env_memory_and_table_in_store`. Keyed by `"GOT.func::name"` or
/// `"GOT.mem::name"`. These handles are `Copy` (wasmtime::Global is Copy)
/// so they can be cloned and used after the linker/store are borrowed elsewhere.
pub type GotGlobalMap = HashMap<String, Global>;

// ---- pre-fill GOT.func globals -----------------------------------------------

/// Write the pre-assigned slot index into every `GOT.func.*` global.
///
/// Called from `wire_env_memory_and_table_in_store` after creating the globals
/// so that any code reading a GOT.func slot before `fill_got_table_slots` sees
/// a non-zero index (pointing to a null funcref slot rather than the trap slot 0).
///
/// `host_got_base` is the first table slot reserved for host GOT.func stubs,
/// derived from the main module's `dylink.0` layout via
/// [`MainModuleLayout::host_got_base`](crate::emscripten_runtime::MainModuleLayout::host_got_base).
pub fn prefill_got_func_globals(
    store: &mut Store<EmbedderState>,
    got_globals: &GotGlobalMap,
    host_got_base: u32,
) -> Result<()> {
    for (idx, name) in GOT_FUNC_NAMES.iter().enumerate() {
        let slot = host_got_base.saturating_add(idx as u32) as i32;
        let key = format!("GOT.func::{name}");
        if let Some(&g) = got_globals.get(&key) {
            g.set(&mut *store, Val::I32(slot))
                .map_err(|e| AfterburnerError::Engine(format!("prefill {key} = {slot}: {e}")))?;
        }
    }
    Ok(())
}

/// Write the known symbol addresses into every `GOT.mem.*` global.
///
/// - `__heap_base` = derived from `layout` (memory_base + memory_size + stack_size).
/// - `__stack_high` = top of the stack region (layout.stack_high()).
/// - `__stack_low`  = bottom of the stack region (layout.stack_low()).
///
/// Layout is: static data | stack | heap. The heap must start past both the
/// static data and the stack so they never overlap.
pub fn prefill_got_mem_globals(
    store: &mut Store<EmbedderState>,
    got_globals: &GotGlobalMap,
    memory_base: u32,
    layout: &crate::emscripten_runtime::MainModuleLayout,
) -> Result<()> {
    let heap_base = layout.heap_base(memory_base);
    let stack_low = layout.stack_low();
    let stack_high = layout.stack_high();

    let pairs: &[(&str, u32)] = &[
        ("__heap_base", heap_base),
        ("__stack_high", stack_high),
        ("__stack_low", stack_low),
    ];
    for (name, value) in pairs {
        let key = format!("GOT.mem::{name}");
        if let Some(&g) = got_globals.get(&key) {
            g.set(&mut *store, Val::I32(*value as i32))
                .map_err(|e| AfterburnerError::Engine(format!("prefill {key} = {value}: {e}")))?;
        }
    }
    Ok(())
}

// ---- updateGOT: resolve GOT.mem entries from an instance's immutable exports ---

/// Resolve `GOT.mem.<sym>` globals from a WASM instance's immutable-global exports.
///
/// Mirrors Emscripten's `updateGOT` / `relocateExports` semantics: every
/// immutable global export from `instance` whose name matches a `GOT.mem.<sym>`
/// entry is treated as a data-address symbol. Its i32 value (the linear-memory
/// address, already accounting for the module's `memory_base`) is written into
/// the corresponding `Global` handle in `entries`.
///
/// `entries` is a slice of `(symbol_name, Global)` pairs - one per `GOT.mem.*`
/// import that should be resolved. Pass the pairs for both main-module and
/// side-module GOT.mem imports; the logic is identical for both.
///
/// Returns `(resolved, zero)` where `resolved` is the count of entries whose
/// value was set to a non-zero address and `zero` is all others (symbol not
/// exported, mutable global export, or zero address).
pub fn resolve_got_mem<S>(
    store: &mut S,
    instance: &Instance,
    entries: &[(&str, Global)],
) -> (u32, u32)
where
    S: AsContextMut<Data = EmbedderState>,
{
    let mut resolved = 0u32;
    let mut zero = 0u32;
    for (name, g) in entries {
        let addr = instance
            .get_global(store.as_context_mut(), name)
            .filter(|eg| eg.ty(store.as_context()).mutability() == Mutability::Const)
            .and_then(|eg| match eg.get(store.as_context_mut()) {
                Val::I32(v) if v != 0 => Some(v),
                _ => None,
            });
        match addr {
            Some(v) => {
                // Ignore set errors: the global may be read-only in edge cases.
                let _ = g.set(store.as_context_mut(), Val::I32(v));
                resolved += 1;
            }
            None => {
                zero += 1;
            }
        }
    }
    (resolved, zero)
}

// ---- updateGOT: resolve GOT.func entries via addFunction (table slot alloc) ----

/// Resolve `GOT.func.<sym>` globals by inserting the named function from
/// `main_instance` into the shared indirect function table.
///
/// Mirrors Emscripten's `updateGOT` path for function exports: when a symbol
/// is a function, JS calls `addFunction(value)` which finds or allocates a table
/// slot for the funcref and returns the slot index. We replicate this by:
///
/// 1. Looking up `name` in `main_instance`'s exports.
/// 2. Growing the shared table by one slot.
/// 3. Placing the funcref at that slot via `table.set`.
/// 4. Writing the slot index into the GOT.func `Global` handle.
///
/// `entries` is a slice of `(symbol_name, Global)` pairs for each `GOT.func.*`
/// import in the side module that needs resolution.
///
/// Returns `(resolved, missing)` where `resolved` is the count of entries
/// successfully filled and `missing` is the count for which the main instance
/// has no matching export.
pub fn resolve_got_func(
    store: &mut Store<EmbedderState>,
    main_instance: &Instance,
    entries: &[(&str, Global)],
) -> (u32, u32) {
    let Some(table) = store.data().pyodide_table else {
        return (0, entries.len() as u32);
    };
    let mut resolved = 0u32;
    let mut missing = 0u32;
    for (name, g) in entries {
        let Some(func) = main_instance.get_func(&mut *store, name) else {
            missing += 1;
            continue;
        };
        // Grow the shared table by one slot to get a fresh index.
        let slot = table.size(&*store) as u32;
        if table
            .grow(&mut *store, 1, wasmtime::Ref::Func(None))
            .is_err()
        {
            missing += 1;
            continue;
        }
        // Place the funcref at the new slot.
        if table
            .set(&mut *store, slot as u64, wasmtime::Ref::Func(Some(func)))
            .is_err()
        {
            missing += 1;
            continue;
        }
        // Write the slot index into the GOT.func global.
        let _ = g.set(&mut *store, Val::I32(slot as i32));
        resolved += 1;
    }
    (resolved, missing)
}

/// Resolve every `GOT.func.<name>` global a SELF-PROVIDING module imports by
/// placing its host stub funcref into a fresh table slot and writing that slot
/// index into the global.
///
/// On the 0.28.x host-provided path the GOT.func globals are pre-filled to their
/// reserved host slots before instantiation (`prefill_got_func_globals`), and
/// `fill_got_table_slots` places the matching funcref at exactly that slot. The
/// 314 self-providing path cannot pre-fill (the table is the module's own and is
/// only adopted after instantiation), so this runs afterwards and covers EVERY
/// GOT.func import the module declares - not just the hardcoded `GOT_FUNC_NAMES`
/// subset. A 314 module imports its host functions (WebGL, console, ...) entirely
/// through GOT.func; any global left at 0 makes the module call through table
/// slot 0 (the null trap slot) and trap with `IndirectCallToNull` the moment that
/// pointer is invoked.
///
/// For each GOT.func import whose global is still 0 (not already resolved to a
/// real element-segment slot by `fill_got_table_slots`), the funcref is sourced
/// from the linker's `env.<name>` host stub (wired by
/// `wire_got_func_stubs_from_module` + `fill_unknown_imports_as_noops`), a fresh
/// table slot is grown, the funcref is placed there, and the slot index is
/// written into the GOT.func global. Names with no `env.<name>` stub are skipped
/// (their global stays 0; the module is not expected to dereference them).
///
/// Returns `(resolved, skipped)`.
pub fn resolve_self_provided_got_func(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    module: &Module,
    got_globals: &GotGlobalMap,
) -> Result<(u32, u32)> {
    let Some(table) = store.data().pyodide_table else {
        return Err(AfterburnerError::Engine(
            "resolve_self_provided_got_func: pyodide_table not set in store".into(),
        ));
    };

    // GOT.func import names in declaration order (deduplicated via the global map
    // lookup below).
    let names: Vec<String> = module
        .imports()
        .filter(|imp| imp.module() == "GOT.func")
        .map(|imp| imp.name().to_owned())
        .collect();

    let mut resolved = 0u32;
    let mut skipped = 0u32;
    for name in &names {
        let Some(&g) = got_globals.get(&format!("GOT.func::{name}")) else {
            skipped += 1;
            continue;
        };
        // Already resolved to a real slot (element-segment / module export)?
        if let Val::I32(v) = g.get(&mut *store)
            && v != 0
        {
            continue;
        }
        // Source the funcref from the linker's env.<name> host stub. If the name
        // has no env.<name> import (a GOT.func-only host symbol, e.g. a WebGL
        // entry the module references by address but never imports as a function),
        // place a void->void trap stub so the global points to a real slot rather
        // than the null trap slot 0: a stray call then surfaces as a clear
        // type-mismatch / trap at that symbol instead of a bare IndirectCallToNull.
        let func = match linker
            .get(&mut *store, "env", name)
            .ok()
            .and_then(|ext| ext.into_func())
        {
            Some(f) => {
                resolved += 1;
                f
            }
            None => {
                skipped += 1;
                let ft = FuncType::new(store.engine(), [], []);
                let label = format!("unresolved GOT.func host symbol: {name}");
                Func::new(&mut *store, ft, move |_, _, _| {
                    Err(wasmtime::Error::msg(label.clone()))
                })
            }
        };
        let slot = table.size(&*store) as u32;
        table
            .grow(&mut *store, 1, Ref::Func(None))
            .map_err(|e| AfterburnerError::Engine(format!("GOT.func.{name}: table grow: {e}")))?;
        table
            .set(&mut *store, slot as u64, Ref::Func(Some(func)))
            .map_err(|e| {
                AfterburnerError::Engine(format!("GOT.func.{name}: table.set({slot}): {e}"))
            })?;
        g.set(&mut *store, Val::I32(slot as i32)).map_err(|e| {
            AfterburnerError::Engine(format!("GOT.func.{name}: set global {slot}: {e}"))
        })?;
    }
    Ok((resolved, skipped))
}

// ---- parse name section + element segments to build name->table_slot ----------

/// Parse `wasm` bytes to build a `name -> table_slot` map for GOT.func resolution.
///
/// Emscripten SIDE_MODULE structure:
/// - Name section "functions" subsection: `func_index -> name` for every
///   function in the module (imports included, starting at index 0).
/// - Export section: `func_index -> export_name` for exported functions.
///   Used as a fallback when no name section is present (stripped production
///   builds omit the name section, but the export section is always present).
/// - One active element segment targeting table 0 with offset
///   `global.get $__table_base` (= `table_base`) followed by a list of function
///   indices. Position `k` in the list maps to table slot `table_base + k`.
///
/// Compose: `name -> func_index` (name or export section) + `func_index ->
/// table_slot` (element segment, inverted) = `name -> table_slot`.
///
/// The name section wins over the export section when both name a function:
/// the name section may contain internal (non-exported) functions, while the
/// export section only covers public exports.
///
/// `table_base` must match the value passed to `wire_env_memory_and_table_in_store`
/// (conventionally 1 for Emscripten SIDE_MODULEs).
///
/// Resolution is best-effort: names absent from both the name section and the
/// export section, or not placed in any element segment, are not in the output.
pub fn parse_got_name_to_slot(wasm: &[u8], table_base: u32) -> HashMap<String, u32> {
    // func_index -> name: name section wins; export section fills missing entries.
    let mut func_names: HashMap<u32, String> = HashMap::new();
    // func_index -> table_slot (inverted element segment).
    let mut func_to_slot: HashMap<u32, u32> = HashMap::new();

    for payload in Parser::new(0).parse_all(wasm) {
        let payload = match payload {
            Ok(p) => p,
            Err(_) => break,
        };
        match payload {
            Payload::CustomSection(cs) if cs.name() == "name" => {
                parse_name_section(cs.data(), cs.data_offset(), &mut func_names);
            }
            Payload::ExportSection(reader) => {
                parse_export_section_for_func_names(reader, &mut func_names);
            }
            Payload::ElementSection(reader) => {
                parse_element_section(reader, table_base, &mut func_to_slot);
            }
            Payload::End(_) => break,
            _ => {}
        }
    }

    // Compose: name -> table_slot.
    let mut out: HashMap<String, u32> = HashMap::with_capacity(func_names.len());
    for (fi, name) in &func_names {
        if let Some(&slot) = func_to_slot.get(fi) {
            out.insert(name.clone(), slot);
        }
    }
    out
}

/// Populate `func_index -> name` from the export section for func exports.
///
/// Only fills entries not already present (name section wins). This handles
/// the common case of stripped side modules that have no name section.
fn parse_export_section_for_func_names(
    reader: wasmparser::ExportSectionReader<'_>,
    out: &mut HashMap<u32, String>,
) {
    for export in reader.into_iter().flatten() {
        if export.kind == ExternalKind::Func {
            // Name section wins; only insert if not already present.
            out.entry(export.index)
                .or_insert_with(|| export.name.to_owned());
        }
    }
}

/// Parse the name-section bytes (already extracted from the custom section).
fn parse_name_section(data: &[u8], data_offset: usize, out: &mut HashMap<u32, String>) {
    use wasmparser::BinaryReader;
    use wasmparser::Subsections;

    let reader = BinaryReader::new(data, data_offset);
    let mut subs: Subsections<'_, Name<'_>> = Subsections::new(reader);
    while let Some(Ok(sub)) = subs.next() {
        if let Name::Function(map) = sub {
            for naming in map.into_iter().flatten() {
                out.insert(naming.index, naming.name.to_owned());
            }
        }
    }
}

/// Parse all active element segments and record `func_index -> table_slot`.
///
/// Emscripten emits the segment offset as `global.get $__table_base` (a single
/// GlobalGet operator, resolved at runtime to `table_base`). An `i32.const N`
/// offset is also handled for defensive coverage.
fn parse_element_section(
    reader: wasmparser::ElementSectionReader<'_>,
    table_base: u32,
    out: &mut HashMap<u32, u32>,
) {
    for elem in reader.into_iter().flatten() {
        let offset = match &elem.kind {
            ElementKind::Active {
                table_index,
                offset_expr,
            } => {
                // Only handle table 0 (None = implicit 0, Some(0) = explicit 0).
                if matches!(table_index, Some(n) if *n != 0) {
                    continue;
                }
                eval_offset_expr(offset_expr, table_base)
            }
            _ => continue,
        };
        let offset = match offset {
            Some(o) => o,
            None => continue,
        };

        match elem.items {
            ElementItems::Functions(fs) => {
                for (pos, fi) in fs.into_iter().flatten().enumerate() {
                    let slot = offset.saturating_add(pos as u32);
                    // First write wins (element segments don't overlap for a
                    // well-formed SIDE_MODULE).
                    out.entry(fi).or_insert(slot);
                }
            }
            ElementItems::Expressions(_, exprs) => {
                // Emscripten SIDE_MODULEs use Functions items, not Expressions.
                // Handle defensively in case a future version differs.
                for (pos, expr) in exprs.into_iter().flatten().enumerate() {
                    let mut ops = expr.get_operators_reader();
                    if let Ok(Operator::RefFunc { function_index }) = ops.read() {
                        let slot = offset.saturating_add(pos as u32);
                        out.entry(function_index).or_insert(slot);
                    }
                }
            }
        }
    }
}

/// Evaluate a ConstExpr to a u32 table offset.
///
/// Handles:
/// - `i32.const N` -> `N as u32`
/// - `global.get <any>` -> `table_base` (the only global.get in SIDE_MODULE
///   element offsets is `$__table_base`, resolved to `table_base` at runtime)
///
/// Returns `None` for compound or unsupported expressions.
fn eval_offset_expr(expr: &wasmparser::ConstExpr<'_>, table_base: u32) -> Option<u32> {
    let mut ops = expr.get_operators_reader();
    match ops.read().ok()? {
        Operator::I32Const { value } => Some(value as u32),
        Operator::GlobalGet { .. } => Some(table_base),
        _ => None,
    }
}

// ---- pre-instantiation: wire missing env.* stubs for GOT.func entries -------

/// For every `GOT.func.<name>` entry whose `env.<name>` counterpart is NOT yet
/// in the linker, wire a correctly-typed no-op stub (or a trap for terminal
/// functions). This must be called BEFORE `linker.instantiate`.
///
/// Uses the compiled module's import section to discover the exact `FuncType`
/// for each `env.<name>` import. A stub with the wrong type placed in the
/// indirect function table would cause a type-mismatch trap on `call_indirect`;
/// this function ensures every GOT.func slot gets a funcref with the right type.
///
/// Returns the number of stubs wired.
pub fn wire_got_func_stubs_from_module(
    store: &mut Store<EmbedderState>,
    linker: &mut Linker<EmbedderState>,
    module: &Module,
) -> Result<u32> {
    // Build name -> FuncType for all env.* function imports in the module.
    let env_func_types: HashMap<String, FuncType> = module
        .imports()
        .filter_map(|imp| {
            if imp.module() != "env" {
                return None;
            }
            if let ExternType::Func(ft) = imp.ty() {
                Some((imp.name().to_owned(), ft))
            } else {
                None
            }
        })
        .collect();

    let mut wired = 0u32;

    for name in GOT_FUNC_NAMES {
        // Skip if already in the linker (wired by mechanical/jsffi layers).
        if linker.get(&mut *store, "env", name).is_ok() {
            continue;
        }

        // Determine the FuncType from the module's env.* import, if present.
        let ft = match env_func_types.get(*name) {
            Some(ft) => ft.clone(),
            None => {
                // Not imported as env.* at all - use a safe void->void type.
                FuncType::new(store.engine(), [], [])
            }
        };

        // Wire a no-op stub (or a trap for terminal functions). Terminal
        // functions are those that must not return normally; they are the ones
        // already wired as traps in the mechanical layer and appear here only
        // because they were not yet in the linker.
        let name_owned = *name;
        let is_terminal = matches!(*name, "abort" | "__cxa_rethrow");

        if is_terminal {
            linker
                .func_new("env", name_owned, ft, |_, _, _| {
                    Err(wasmtime::Trap::UnreachableCodeReached.into())
                })
                .map_err(|e| {
                    AfterburnerError::Engine(format!("GOT stub terminal env.{name_owned}: {e}"))
                })?;
        } else {
            let result_tys: Vec<ValType> = ft.results().collect();
            linker
                .func_new("env", name_owned, ft.clone(), move |_, _, results| {
                    // Zero each result by its DECLARED type (see default_val_for):
                    // the slot's pre-fill is a null funcref regardless of type.
                    for (r, vt) in results.iter_mut().zip(&result_tys) {
                        *r = default_val_for(vt);
                    }
                    Ok(())
                })
                .map_err(|e| AfterburnerError::Engine(format!("GOT stub env.{name_owned}: {e}")))?;
        }
        wired += 1;
    }
    Ok(wired)
}

// ---- post-instantiation: resolve GOT.func globals ---------------------------

/// Resolution summary returned by `fill_got_table_slots`.
#[derive(Debug)]
pub struct GotResolutionReport {
    /// GOT.func globals updated to a real element-segment table slot.
    pub funcs_from_elem: u32,
    /// GOT.func globals resolved via a linker host export (env.* function).
    pub funcs_from_export: u32,
    /// GOT.func globals that remain on their pre-assigned stub slot.
    pub funcs_stubbed: u32,
    /// GOT.mem entries resolved (always 3 for pyodide.asm.wasm).
    pub mem_resolved: u32,
}

/// Update GOT.func globals with real table slot indices from the module's element
/// segments, then place host funcs into the stub slots for any name found in the
/// linker.
///
/// Must be called AFTER `linker.instantiate` and BEFORE
/// `__wasm_apply_data_relocs` / `__wasm_call_ctors`.
///
/// Resolution order per name:
/// 1. Name-section + element-segment table slot (`name_to_slot` map): update the
///    GOT global to that slot. The function reference was placed there by the
///    active element segment during instantiation.
/// 2. Module export fallback via `instance.get_func(name)`: place the func into
///    the pre-assigned stub slot and keep the global pointing to it.
/// 3. Linker host export (`env.<name>`): place the func into the stub slot.
///    After `wire_got_func_stubs_from_module` has been called, ALL 169 GOT.func
///    names have a matching `env.*` entry in the linker, so this path resolves
///    all remaining entries.
/// 4. Unresolved: place a void->void stub so the slot holds a defined funcref.
///
/// `name_to_slot` should come from `parse_got_name_to_slot` called on the same
/// wasm bytes before instantiation.
///
/// `got_globals` should be the map returned by `wire_env_memory_and_table_in_store`.
///
/// `module` is used to derive the correct `FuncType` for Path-4 fallback stubs
/// so that `call_indirect` type checks pass even in the absence of a linker entry.
pub fn fill_got_table_slots(
    store: &mut Store<EmbedderState>,
    linker: &Linker<EmbedderState>,
    instance: &Instance,
    got_globals: &GotGlobalMap,
    name_to_slot: &HashMap<String, u32>,
    module: &Module,
    host_got_base: u32,
) -> Result<GotResolutionReport> {
    // The indirect function table is host-defined and imported via `env` on the
    // 0.28.x path; on the 314 self-providing path the module exports it and the
    // host adopted it into the store (`adopt_self_provided_exports`). Prefer the
    // linker import when present, else fall back to the adopted store handle.
    let table = match linker.get(&mut *store, "env", "__indirect_function_table") {
        Ok(ext) => ext.into_table().ok_or_else(|| {
            AfterburnerError::Engine(
                "GOT resolution: env.__indirect_function_table is not a table".into(),
            )
        })?,
        Err(_) => store.data().pyodide_table.ok_or_else(|| {
            AfterburnerError::Engine(
                "GOT resolution: no env.__indirect_function_table import and no adopted \
                 self-provided table in the store"
                    .into(),
            )
        })?,
    };

    // Per-symbol FuncType from the module's env.* imports. Used for Path-4
    // fallback stubs to ensure call_indirect type checks pass.
    let env_func_types: HashMap<String, FuncType> = module
        .imports()
        .filter_map(|imp| {
            if imp.module() != "env" {
                return None;
            }
            if let ExternType::Func(ft) = imp.ty() {
                Some((imp.name().to_owned(), ft))
            } else {
                None
            }
        })
        .collect();

    // Fallback void->void type for names with no env.* import entry.
    let void_ft = FuncType::new(store.engine(), [], []);

    let mut funcs_from_elem = 0u32;
    let mut funcs_from_export = 0u32;
    let mut funcs_stubbed = 0u32;

    for (idx, name) in GOT_FUNC_NAMES.iter().enumerate() {
        let global_key = format!("GOT.func::{name}");

        // Path 1: name section + element segment -> real table slot.
        if let Some(&real_slot) = name_to_slot.get(*name) {
            if let Some(&g) = got_globals.get(&global_key) {
                g.set(&mut *store, Val::I32(real_slot as i32))
                    .map_err(|e| {
                        AfterburnerError::Engine(format!(
                            "GOT.func.{name}: set global to slot {real_slot}: {e}"
                        ))
                    })?;
            }
            funcs_from_elem += 1;
            continue;
        }

        // Path 2: module export by name.
        let stub_slot = host_got_base.saturating_add(idx as u32) as u64;
        if let Some(func) = instance.get_func(&mut *store, name) {
            if *name == "emscripten_out" || *name == "emscripten_err" {
                eprintln!("[GOT Path2] {name} -> stub_slot={stub_slot} (module export)");
            }
            table
                .set(&mut *store, stub_slot, Ref::Func(Some(func)))
                .map_err(|e| {
                    AfterburnerError::Engine(format!(
                        "GOT.func.{name}: table.set(slot={stub_slot}) [export]: {e}"
                    ))
                })?;
            funcs_from_export += 1;
            continue;
        }

        // Path 3: linker host export env.<name>.
        // After wire_got_func_stubs_from_module this covers all GOT.func entries
        // that have a matching env.* import in the module.
        if let Ok(ext) = linker.get(&mut *store, "env", name)
            && let Some(func) = ext.into_func()
        {
            if *name == "emscripten_out" || *name == "emscripten_err" {
                eprintln!("[GOT Path3] {name} -> stub_slot={stub_slot}");
            }
            table
                .set(&mut *store, stub_slot, Ref::Func(Some(func)))
                .map_err(|e| {
                    AfterburnerError::Engine(format!(
                        "GOT.func.{name}: table.set(slot={stub_slot}) [linker]: {e}"
                    ))
                })?;
            funcs_from_export += 1;
            continue;
        }

        if *name == "emscripten_out" || *name == "emscripten_err" {
            eprintln!("[GOT Path4-fallback] {name} -> stub_slot={stub_slot}");
        }

        // Path 4: unresolved - place a correctly-typed no-op stub so the slot
        // holds a defined funcref and call_indirect type checks pass.
        let ft = env_func_types
            .get(*name)
            .cloned()
            .unwrap_or_else(|| void_ft.clone());
        let stub_func = make_typed_stub(store, &ft);
        table
            .set(&mut *store, stub_slot, Ref::Func(Some(stub_func)))
            .map_err(|e| {
                AfterburnerError::Engine(format!(
                    "GOT.func.{name}: table.set(slot={stub_slot}) [stub]: {e}"
                ))
            })?;
        funcs_stubbed += 1;
    }

    // Apply updateGOT to all GOT.mem entries from the module's imports.
    //
    // The probe auto-fills every GOT.mem import with Val::I32(0) before
    // instantiation, but only the 3 layout symbols (__heap_base, __stack_low,
    // __stack_high) are in got_globals. All other GOT.mem imports (Python C API
    // data symbols: PyExc_ValueError, _Py_NoneStruct, PyType_Type, ...) are
    // defined in the linker but absent from got_globals.
    //
    // Collect all GOT.mem globals from the linker via the module's import list
    // so that every data-symbol GOT entry is resolved from the main instance's
    // immutable-global exports (updateGOT semantics).
    let mem_entries: Vec<(String, Global)> = module
        .imports()
        .filter(|imp| imp.module() == "GOT.mem")
        .filter_map(|imp| {
            linker
                .get(&mut *store, "GOT.mem", imp.name())
                .ok()
                .and_then(|ext| ext.into_global())
                .map(|g| (imp.name().to_owned(), g))
        })
        .collect();
    let mem_pairs: Vec<(&str, Global)> =
        mem_entries.iter().map(|(s, g)| (s.as_str(), *g)).collect();
    let (mem_resolved, mem_zero) = resolve_got_mem(store, instance, &mem_pairs);
    eprintln!(
        "[GOT] main-module GOT.mem: resolved={mem_resolved} zero={mem_zero} total={}",
        mem_entries.len()
    );

    Ok(GotResolutionReport {
        funcs_from_elem,
        funcs_from_export,
        funcs_stubbed,
        mem_resolved,
    })
}

// ---- internal helper ---------------------------------------------------------

/// Create a no-op `Func` with the given type, filling all result slots with
/// a type-appropriate zero. Used for Path-4 table stubs.
fn make_typed_stub(store: &mut Store<EmbedderState>, ft: &FuncType) -> Func {
    // Set each result from its DECLARED type. wasmtime initialises the `results`
    // slice to a null-funcref placeholder regardless of the declared type, so
    // matching on the runtime value (the old approach) returned a funcref for an
    // i32 result: "function attempted to return an incompatible value: expected
    // i32, found (ref null nofunc)". Drive the zero value off `ft.results()`.
    let results_ty: Vec<ValType> = ft.results().collect();
    Func::new(&mut *store, ft.clone(), move |_, _, results| {
        for (r, ty) in results.iter_mut().zip(&results_ty) {
            *r = default_val_for(ty);
        }
        Ok(())
    })
}

// ---- GOT.func symbol names ---------------------------------------------------
//
// 169 entries from `pyodide.asm.wasm` (0.26.4) GOT.func imports.
// Slot index = WASM_TABLE_INITIAL_SIZE + position in this list.

pub(crate) const GOT_FUNC_NAMES: &[&str] = &[
    "__cxa_end_catch",
    "__cxa_rethrow",
    "abort",
    "emscripten_glVertexAttribDivisorANGLE",
    "emscripten_glDrawElementsInstancedANGLE",
    "emscripten_glDrawArraysInstancedANGLE",
    "emscripten_glDrawBuffersWEBGL",
    "emscripten_glIsVertexArrayOES",
    "emscripten_glGenVertexArraysOES",
    "emscripten_glDeleteVertexArraysOES",
    "emscripten_glBindVertexArrayOES",
    "emscripten_glGetQueryObjectui64vEXT",
    "emscripten_glGetQueryObjecti64vEXT",
    "emscripten_glGetQueryObjectuivEXT",
    "emscripten_glGetQueryObjectivEXT",
    "emscripten_glGetQueryivEXT",
    "emscripten_glQueryCounterEXT",
    "emscripten_glEndQueryEXT",
    "emscripten_glBeginQueryEXT",
    "emscripten_glIsQueryEXT",
    "emscripten_glDeleteQueriesEXT",
    "emscripten_glGenQueriesEXT",
    "emscripten_err",
    "emscripten_out",
    "emscripten_console_warn",
    "emscripten_console_error",
    "emscripten_console_log",
    "emscripten_glViewport",
    "emscripten_glVertexAttribPointer",
    "emscripten_glVertexAttrib4fv",
    "emscripten_glVertexAttrib4f",
    "emscripten_glVertexAttrib3fv",
    "emscripten_glVertexAttrib3f",
    "emscripten_glVertexAttrib2fv",
    "emscripten_glVertexAttrib2f",
    "emscripten_glVertexAttrib1fv",
    "emscripten_glVertexAttrib1f",
    "emscripten_glValidateProgram",
    "emscripten_glUseProgram",
    "emscripten_glUniformMatrix4fv",
    "emscripten_glUniformMatrix3fv",
    "emscripten_glUniformMatrix2fv",
    "emscripten_glUniform4iv",
    "emscripten_glUniform4i",
    "emscripten_glUniform4fv",
    "emscripten_glUniform4f",
    "emscripten_glUniform3iv",
    "emscripten_glUniform3i",
    "emscripten_glUniform3fv",
    "emscripten_glUniform3f",
    "emscripten_glUniform2iv",
    "emscripten_glUniform2i",
    "emscripten_glUniform2fv",
    "emscripten_glUniform2f",
    "emscripten_glUniform1iv",
    "emscripten_glUniform1i",
    "emscripten_glUniform1fv",
    "emscripten_glUniform1f",
    "emscripten_glUniformBlockBinding",
    "emscripten_glTexSubImage2D",
    "emscripten_glTexParameteriv",
    "emscripten_glTexParameteri",
    "emscripten_glTexParameterfv",
    "emscripten_glTexParameterf",
    "emscripten_glTexImage3D",
    "emscripten_glTexImage2D",
    "emscripten_glStencilOpSeparate",
    "emscripten_glStencilOp",
    "emscripten_glStencilMaskSeparate",
    "emscripten_glStencilMask",
    "emscripten_glStencilFuncSeparate",
    "emscripten_glStencilFunc",
    "emscripten_glShaderSource",
    "emscripten_glScissor",
    "emscripten_glSampleCoverage",
    "emscripten_glRenderbufferStorage",
    "emscripten_glReadPixels",
    "emscripten_glPolygonOffset",
    "emscripten_glPixelStorei",
    "emscripten_glLinkProgram",
    "emscripten_glLineWidth",
    "emscripten_glIsVertexArray",
    "emscripten_glIsTexture",
    "emscripten_glIsShader",
    "emscripten_glIsRenderbuffer",
    "emscripten_glIsProgram",
    "emscripten_glIsFramebuffer",
    "emscripten_glIsEnabled",
    "emscripten_glIsBuffer",
    "emscripten_glGetVertexAttribPointerv",
    "emscripten_glGetVertexAttribiv",
    "emscripten_glGetVertexAttribfv",
    "emscripten_glGetUniformLocation",
    "emscripten_glGetUniformiv",
    "emscripten_glGetUniformfv",
    "emscripten_glGetUniformBlockIndex",
    "emscripten_glGetTexParameteriv",
    "emscripten_glGetTexParameterfv",
    "emscripten_glGetShaderSource",
    "emscripten_glGetShaderPrecisionFormat",
    "emscripten_glGetShaderiv",
    "emscripten_glGetShaderInfoLog",
    "emscripten_glGetRenderbufferParameteriv",
    "emscripten_glGetProgramiv",
    "emscripten_glGetProgramInfoLog",
    "emscripten_glGetIntegerv",
    "emscripten_glGetFramebufferAttachmentParameteriv",
    "emscripten_glGetError",
    "emscripten_glGetBufferParameteriv",
    "emscripten_glGetAttribLocation",
    "emscripten_glGetAttachedShaders",
    "emscripten_glGetActiveUniformBlockiv",
    "emscripten_glGetActiveUniformBlockName",
    "emscripten_glGetActiveUniform",
    "emscripten_glGetActiveAttrib",
    "emscripten_glGenVertexArrays",
    "emscripten_glGenTextures",
    "emscripten_glGenRenderbuffers",
    "emscripten_glGenFramebuffers",
    "emscripten_glGenBuffers",
    "emscripten_glFramebufferTextureLayer",
    "emscripten_glFramebufferTexture2D",
    "emscripten_glFramebufferRenderbuffer",
    "emscripten_glFlush",
    "emscripten_glFinish",
    "emscripten_glEnableVertexAttribArray",
    "emscripten_glEnable",
    "emscripten_glDrawRangeElements",
    "emscripten_glDrawElements",
    "emscripten_glDrawBuffers",
    "emscripten_glDrawArrays",
    "emscripten_glDisableVertexAttribArray",
    "emscripten_glDisable",
    "emscripten_glDetachShader",
    "emscripten_glDepthRange",
    "emscripten_glDepthMask",
    "emscripten_glDepthFunc",
    "emscripten_glDeleteVertexArrays",
    "emscripten_glDeleteTextures",
    "emscripten_glDeleteShader",
    "emscripten_glDeleteRenderbuffers",
    "emscripten_glDeleteProgram",
    "emscripten_glDeleteFramebuffers",
    "emscripten_glDeleteBuffers",
    "emscripten_glCullFace",
    "emscripten_glCreateShader",
    "emscripten_glCreateProgram",
    "emscripten_glCopyTexSubImage2D",
    "emscripten_glCompileShader",
    "emscripten_glColorMask",
    "emscripten_glClearStencil",
    "emscripten_glClearDepthf",
    "emscripten_glClearColor",
    "emscripten_glClear",
    "emscripten_glCheckFramebufferStatus",
    "emscripten_glBufferSubData",
    "emscripten_glBufferData",
    "emscripten_glBlendFuncSeparate",
    "emscripten_glBlendFunc",
    "emscripten_glBlendEquationSeparate",
    "emscripten_glBlendEquation",
    "emscripten_glBlendColor",
    "emscripten_glBindTexture",
    "emscripten_glBindRenderbuffer",
    "emscripten_glBindFramebuffer",
    "emscripten_glBindBuffer",
    "emscripten_glBindAttribLocation",
    "emscripten_glAttachShader",
    "emscripten_glActiveTexture",
    "emscripten_glShaderBinary",
    "emscripten_glReleaseShaderCompiler",
    "emscripten_glHint",
    "emscripten_glGetString",
    "emscripten_glGetFloatv",
    "emscripten_glGetBooleanv",
    "emscripten_glGenerateMipmap",
    "emscripten_glFrontFace",
    "emscripten_glDepthRangef",
    "emscripten_glCopyTexImage2D",
    "emscripten_glCompressedTexSubImage2D",
    "emscripten_glCompressedTexImage2D",
];

// ---- unit tests ------------------------------------------------------------

#[cfg(test)]
mod tests;
