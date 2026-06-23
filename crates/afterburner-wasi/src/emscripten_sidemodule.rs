// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Pre-loading and dispatch for Emscripten SIDE_MODULE `.so` files.
//!
//! ## Approach
//!
//! Emscripten SIDE_MODULEs are `.wasm` binaries that import all Python C API
//! functions from `env.*` (provided by the main `pyodide.asm.wasm` instance)
//! and share the main module's `env.memory` and `env.__indirect_function_table`.
//!
//! In a JS host, loading is async: packages are pre-loaded before Python runs
//! via `loadPackage()`. Headless, we replicate this synchronously:
//!
//! 1. After the main pyodide instance is created (all its functions are available
//!    as Wasmtime exports), call [`pre_load_side_module`] for each `.so` file.
//! 2. This compiles and instantiates the SIDE_MODULE, wiring its `env.*` imports
//!    from the main pyodide instance's exports.
//! 3. The resulting [`SideModuleHandle`] is stored in
//!    [`EmbedderState::side_modules`] keyed by the WASM-side path.
//! 4. When `_dlopen_js` is called during Python's `import numpy`, it reads the
//!    DSO path from the struct pointer, finds the pre-loaded handle, and returns
//!    a non-zero opaque handle integer.
//! 5. When `_dlsym_js` is called to look up `PyInit__multiarray_umath`, it finds
//!    the function in the pre-loaded instance's exports and returns its table slot.
//!
//! ## Memory layout for SIDE_MODULEs
//!
//! Each SIDE_MODULE is allocated:
//! - A `memory_base` at the next aligned position after the previous module.
//! - A `table_base` at the next available table slot.
//!
//! Both are passed as `env.__memory_base` and `env.__table_base` imports.
//! The shared `env.memory` and `env.__indirect_function_table` are the same
//! objects created by `wire_env_memory_and_table_in_store`.

use std::collections::HashMap;

use afterburner_core::{AfterburnerError, Result};
use wasmparser::{KnownCustom, Parser, Payload};
use wasmtime::{
    Caller, Engine, ExternType, FuncType, Global, GlobalType, Instance, Linker, Module, Mutability,
    Store, Val, ValType,
};

use crate::embedder_vm::EmbedderState;
use crate::emscripten_dylink::{parse_got_name_to_slot, resolve_got_mem};

/// Memory requirements declared in a SIDE_MODULE's `dylink.0` custom section.
#[derive(Debug, Clone, Copy)]
pub struct Dylink0MemInfo {
    /// Bytes the loader must reserve starting at `__memory_base`.
    pub mem_size: u32,
    /// Required alignment of the region, in bytes (already expanded from log2).
    pub mem_align: u32,
    /// Number of table slots the module needs starting at `__table_base`.
    pub table_size: u32,
}

impl Default for Dylink0MemInfo {
    fn default() -> Self {
        // Conservative fallback when the section is absent or unparseable.
        Self {
            mem_size: 1024 * 1024,
            mem_align: 16,
            table_size: 512,
        }
    }
}

/// Parse the `dylink.0` custom section of an Emscripten SIDE_MODULE and return
/// the `MEM_INFO` subsection fields.
///
/// Uses wasmparser's `Dylink0SectionReader` (via `CustomSectionReader::as_known`).
/// Falls back to a 1 MiB / 512-slot default if the section is missing or malformed.
pub fn parse_dylink0_mem_info(wasm_bytes: &[u8]) -> Dylink0MemInfo {
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let Ok(payload) = payload else { break };
        if let Payload::CustomSection(cs) = payload
            && let KnownCustom::Dylink0(reader) = cs.as_known()
        {
            for sub in reader.into_iter().flatten() {
                if let wasmparser::Dylink0Subsection::MemInfo(info) = sub {
                    return Dylink0MemInfo {
                        mem_size: info.memory_size,
                        // memory_alignment is log2 in the spec; expand to bytes.
                        mem_align: 1u32.checked_shl(info.memory_alignment).unwrap_or(1),
                        table_size: info.table_size,
                    };
                }
            }
        }
    }
    Dylink0MemInfo::default()
}

/// Allocate `size` bytes from the main Emscripten module's `malloc`, aligned to
/// `align` bytes.
///
/// Calls the main instance's exported `malloc(size)` and rounds the result up to
/// the required alignment. Returns the aligned guest pointer.
fn malloc_in_main(
    store: &mut Store<EmbedderState>,
    main_instance: &Instance,
    size: u32,
    align: u32,
    path: &str,
) -> Result<u32> {
    // Allocate with enough padding to guarantee alignment: size + (align - 1).
    let alloc_size = size.saturating_add(align.saturating_sub(1));
    let malloc_fn = main_instance
        .get_func(&mut *store, "malloc")
        .ok_or_else(|| {
            AfterburnerError::Engine(format!(
                "sidemodule {path}: main instance has no 'malloc' export"
            ))
        })?;
    let mut result = [Val::I32(0)];
    malloc_fn
        .call(&mut *store, &[Val::I32(alloc_size as i32)], &mut result)
        .map_err(|e| AfterburnerError::Engine(format!("malloc({alloc_size}) for {path}: {e}")))?;
    let raw = match result[0] {
        Val::I32(v) => v as u32,
        _ => {
            return Err(AfterburnerError::Engine(format!(
                "malloc for {path}: unexpected return type"
            )));
        }
    };
    if raw == 0 {
        return Err(AfterburnerError::Engine(format!(
            "malloc({alloc_size}) for {path}: returned NULL"
        )));
    }
    // Align up: (raw + align - 1) & !(align - 1)
    let aligned = if align <= 1 {
        raw
    } else {
        (raw.saturating_add(align - 1)) & !(align - 1)
    };
    Ok(aligned)
}

/// Table slot occupied by a pre-loaded SIDE_MODULE's `PyInit_*` function.
/// Used by `_dlsym_js` to return the callable table index.
#[derive(Debug, Clone)]
pub struct SideModuleHandle {
    /// Instance in the shared store.
    pub instance: Instance,
    /// Table slot of this module's element segment start. All exported function
    /// pointers are offsets from `table_base`. The `PyInit_*` export is
    /// available via `instance.get_func(store, "PyInit_*")` and its table slot
    /// is recorded here for O(1) lookup by `_dlsym_js`.
    /// Maps export name -> table slot (from the element segment placement).
    pub func_table_slots: HashMap<String, u32>,
}

/// Registry of pre-loaded SIDE_MODULEs.
///
/// Pre-loaded modules are stored by path. When `_dlopen_js` is called with a
/// DSO struct pointer it resolves the path, maps `dso_ptr -> index` in
/// `by_ptr`, and returns `dso_ptr` - exactly as Emscripten's JS LDSO does
/// (LDSO.loadedLibsByHandle keyed by the wasm pointer). `_dlsym_js` then
/// looks up by the same pointer.
#[derive(Default)]
pub struct SideModuleRegistry {
    /// All pre-loaded modules in insertion order, keyed by path.
    handles: Vec<(String, SideModuleHandle)>,
    /// dso struct pointer (raw wasm i32, cast to u32) -> Vec index.
    /// Populated by `map_ptr` when `_dlopen_js` resolves a path.
    by_ptr: HashMap<u32, usize>,
}

impl SideModuleRegistry {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
            by_ptr: HashMap::new(),
        }
    }

    /// Register a pre-loaded handle by path.
    ///
    /// Returns the Vec index (for caller reference; not used as a wasm handle).
    pub fn insert(&mut self, path: String, handle: SideModuleHandle) -> usize {
        let idx = self.handles.len();
        self.handles.push((path, handle));
        idx
    }

    /// Record that wasm pointer `dso_ptr` refers to the module at Vec `index`.
    ///
    /// Called from `_dlopen_js` after it resolves the path to an index.
    pub fn map_ptr(&mut self, dso_ptr: u32, idx: usize) {
        self.by_ptr.insert(dso_ptr, idx);
    }

    /// Look up a module by path (suffix match).
    ///
    /// Returns `(vec_index, &handle)` if found.
    pub fn find_by_path(&self, path: &str) -> Option<(usize, &SideModuleHandle)> {
        for (i, (p, h)) in self.handles.iter().enumerate() {
            if p == path || p.ends_with(path) || path.ends_with(p.as_str()) {
                return Some((i, h));
            }
        }
        None
    }

    /// Look up a module by the wasm DSO struct pointer registered via `map_ptr`.
    pub fn get_by_ptr(&self, dso_ptr: u32) -> Option<&SideModuleHandle> {
        self.by_ptr
            .get(&dso_ptr)
            .and_then(|&idx| self.handles.get(idx).map(|(_, h)| h))
    }

    /// Look up a mutable module by the wasm DSO struct pointer.
    pub fn get_by_ptr_mut(&mut self, dso_ptr: u32) -> Option<&mut SideModuleHandle> {
        if let Some(&idx) = self.by_ptr.get(&dso_ptr) {
            self.handles.get_mut(idx).map(|(_, h)| h)
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Cache a symbol->slot mapping for a module identified by dso pointer.
    ///
    /// Called by `_dlsym_js` after dynamically inserting a function into the
    /// shared table so that repeat lookups skip the table-grow step.
    pub fn set_slot(&mut self, dso_ptr: u32, name: String, slot: u32) {
        if let Some(h) = self.get_by_ptr_mut(dso_ptr) {
            h.func_table_slots.insert(name, slot);
        }
    }
}

/// Pre-load a SIDE_MODULE `.wasm` binary into the shared store and table.
///
/// `wasm_bytes` - raw bytes of the `.so` (which is a `.wasm` SIDE_MODULE).
/// `path` - the path the guest will pass to `dlopen`, used as the registry key.
/// `main_instance` - the already-instantiated `pyodide.asm.wasm` instance whose
///   exports provide all Python C API functions and the Emscripten heap allocator.
///
/// Memory layout is derived from the module's `dylink.0` custom section:
/// `__memory_base` is allocated via the main module's `malloc(mem_size)` so the
/// data segments land in already-backed linear memory. `__table_base` is the
/// current table size before growing by `table_size` from `dylink.0`.
///
/// Returns the [`SideModuleHandle`], the next available `memory_base` (pointer
/// after the allocated region), and the next available `table_base`.
///
/// vertexia: per-module GOT slot resolution; upgrade path is parsing the element
/// segment to get exact per-export table slots.
pub fn pre_load_side_module(
    engine: &Engine,
    store: &mut Store<EmbedderState>,
    main_instance: &Instance,
    wasm_bytes: &[u8],
    path: &str,
) -> Result<(SideModuleHandle, u32, u32)> {
    // Parse dylink.0 for exact memory and table requirements.
    let dylink = parse_dylink0_mem_info(wasm_bytes);
    eprintln!(
        "[sidemodule] {path}: dylink.0 mem_size={} mem_align={} table_size={}",
        dylink.mem_size, dylink.mem_align, dylink.table_size
    );

    // Allocate memory for the side module's data segments in the main module's
    // heap via malloc so the backing pages exist before data relocation.
    let memory_base = malloc_in_main(
        store,
        main_instance,
        dylink.mem_size,
        dylink.mem_align,
        path,
    )?;
    eprintln!(
        "[sidemodule] {path}: malloc({}) -> memory_base={:#x}",
        dylink.mem_size, memory_base
    );

    eprintln!(
        "[sidemodule] compiling {} ({} bytes) memory_base={:#x}",
        path,
        wasm_bytes.len(),
        memory_base,
    );

    let module = Module::new(engine, wasm_bytes)
        .map_err(|e| AfterburnerError::Engine(format!("side module compile {path}: {e}")))?;

    // table_base = current table size; grow by dylink.0 table_size to reserve slots.
    let table_base = {
        let Some(tbl) = store.data().pyodide_table else {
            return Err(AfterburnerError::Engine(
                "pre_load_side_module: pyodide_table not set in store".into(),
            ));
        };
        let current = tbl.size(&*store) as u32;
        let table_size = dylink.table_size.max(1);
        tbl.grow(&mut *store, table_size as u64, wasmtime::Ref::Func(None))
            .map_err(|e| {
                AfterburnerError::Engine(format!("sidemodule table grow by {table_size}: {e}"))
            })?;
        eprintln!(
            "[sidemodule] {path}: grew table {current} -> {} (table_base={current}, delta={table_size})",
            tbl.size(&*store)
        );
        current
    };

    // Build a linker for the SIDE_MODULE.
    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    linker.allow_shadowing(true);

    // Wire shared env.memory from the store state.
    // `define` takes `impl AsContext` (shared ref) so we can read from store.data().
    if let Some(mem) = store.data().pyodide_memory {
        linker
            .define(&mut *store, "env", "memory", mem)
            .map_err(|e| AfterburnerError::Engine(format!("sidemodule memory: {e}")))?;
    } else {
        return Err(AfterburnerError::Engine(
            "pre_load_side_module: pyodide_memory not set in store".into(),
        ));
    }

    // Wire shared __indirect_function_table.
    if let Some(tbl) = store.data().pyodide_table {
        linker
            .define(&mut *store, "env", "__indirect_function_table", tbl)
            .map_err(|e| AfterburnerError::Engine(format!("sidemodule table: {e}")))?;
    } else {
        return Err(AfterburnerError::Engine(
            "pre_load_side_module: pyodide_table not set in store".into(),
        ));
    }

    // env.__memory_base: this module's offset in shared memory.
    let mb_ty = GlobalType::new(ValType::I32, Mutability::Const);
    let mb_val = Global::new(&mut *store, mb_ty.clone(), Val::I32(memory_base as i32))
        .map_err(|e| AfterburnerError::Engine(format!("sidemodule __memory_base: {e}")))?;
    linker
        .define(&mut *store, "env", "__memory_base", mb_val)
        .map_err(|e| AfterburnerError::Engine(format!("define sidemodule __memory_base: {e}")))?;

    // env.__table_base: this module's table slot offset.
    let tb_val = Global::new(&mut *store, mb_ty.clone(), Val::I32(table_base as i32))
        .map_err(|e| AfterburnerError::Engine(format!("sidemodule __table_base: {e}")))?;
    linker
        .define(&mut *store, "env", "__table_base", tb_val)
        .map_err(|e| AfterburnerError::Engine(format!("define sidemodule __table_base: {e}")))?;

    // env.__stack_pointer: shared mutable i32 stack pointer.
    // Provided by main instance as an export, or use the main store's GOT.
    let sp_ty = GlobalType::new(ValType::I32, Mutability::Var);
    // vertexia: use a dummy stack pointer if not exported by pyodide; upgrade
    // path is reading __stack_pointer from the main module's GOT.mem global.
    if let Some(sp_ext) = main_instance.get_global(&mut *store, "__stack_pointer") {
        linker
            .define(&mut *store, "env", "__stack_pointer", sp_ext)
            .map_err(|e| {
                AfterburnerError::Engine(format!("define sidemodule __stack_pointer: {e}"))
            })?;
    } else {
        // Provide a stub stack pointer at the Pyodide stack base.
        let sp_val = Global::new(
            &mut *store,
            sp_ty,
            Val::I32(crate::emscripten_runtime::PYODIDE_STACK_BASE as i32),
        )
        .map_err(|e| AfterburnerError::Engine(format!("sidemodule stub __stack_pointer: {e}")))?;
        linker
            .define(&mut *store, "env", "__stack_pointer", sp_val)
            .map_err(|e| {
                AfterburnerError::Engine(format!("define sidemodule stub __stack_pointer: {e}"))
            })?;
    }

    // Wire GOT.func and GOT.mem globals for the SIDE_MODULE.
    //
    // All GOT globals are created with init 0. Resolution happens in two
    // phases: BEFORE instantiation (GOT.mem data-address symbols from main)
    // and AFTER instantiation (GOT.func from the side module's own element
    // segment + fallback to main). This mirrors Emscripten's call order:
    //
    //   1. GOTProxy traps/defers reads until updateGOT runs.
    //   2. instantiate() -> active element segment places funcs in table.
    //   3. relocateExports + updateGOT(moduleExports) writes slot indices.
    //   4. __wasm_apply_data_relocs reads correct GOT values.
    //   5. __wasm_call_ctors.
    //
    // Critically: GOT.func globals MUST be correct BEFORE apply_data_relocs
    // because that function reads fn-ptr-in-data fields from those globals to
    // fill PyTypeObject.tp_traverse and similar slots.
    let got_ty = GlobalType::new(ValType::I32, Mutability::Var);
    // Collect GOT imports first to avoid repeated borrow conflicts.
    let got_imports: Vec<(String, String)> = module
        .imports()
        .filter_map(|imp| {
            let m = imp.module();
            if m != "GOT.func" && m != "GOT.mem" {
                return None;
            }
            Some((m.to_owned(), imp.name().to_owned()))
        })
        .collect();

    // Build all GOT globals (init 0), collecting func and mem for resolution.
    let mut got_mem_globals: Vec<(String, Global)> = Vec::new();
    let mut got_func_globals: Vec<(String, Global)> = Vec::new();
    for (m, name) in &got_imports {
        if linker.get(&mut *store, m.as_str(), name.as_str()).is_ok() {
            continue;
        }
        let g = Global::new(&mut *store, got_ty.clone(), Val::I32(0)).map_err(|e| {
            AfterburnerError::Engine(format!("GOT stub for sidemodule {m}.{name}: {e}"))
        })?;
        if m == "GOT.mem" {
            got_mem_globals.push((name.clone(), g));
        } else {
            got_func_globals.push((name.clone(), g));
        }
        linker
            .define(&mut *store, m.as_str(), name.as_str(), g)
            .map_err(|e| {
                AfterburnerError::Engine(format!("define sidemodule GOT {m}.{name}: {e}"))
            })?;
    }

    // Pre-fill GOT.mem with resolved data-address symbols from the main
    // instance BEFORE instantiation (same pre-instantiation pass as Emscripten
    // does for imports resolved from the main module's exports).
    let got_mem_pairs: Vec<(&str, Global)> = got_mem_globals
        .iter()
        .map(|(s, g)| (s.as_str(), *g))
        .collect();
    let (got_mem_resolved, got_mem_zero) = resolve_got_mem(store, main_instance, &got_mem_pairs);
    eprintln!("[sidemodule] {path}: GOT.mem resolved={got_mem_resolved} zero={got_mem_zero}");

    // GOT.func is intentionally left at 0 here. The active element segment
    // runs during instantiation and places the side module's own functions into
    // the shared table at slots [table_base .. table_base + table_size). We
    // resolve the GOT.func globals to those slots AFTER instantiation (below),
    // mirroring Emscripten's updateGOT(moduleExports) call order.

    // Wire all env.* function imports from the main pyodide instance's exports.
    // For any env.* the main instance doesn't export, wire a typed no-op.
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

    let mut from_main = 0u32;
    let mut from_stub = 0u32;

    for (name, ft) in &env_func_types {
        // Skip already-defined (memory, table, __memory_base, etc.).
        if linker.get(&mut *store, "env", name.as_str()).is_ok() {
            continue;
        }

        if let Some(func) = main_instance.get_func(&mut *store, name.as_str()) {
            linker
                .define(&mut *store, "env", name.as_str(), func)
                .map_err(|e| {
                    AfterburnerError::Engine(format!("sidemodule wire env.{name} from main: {e}"))
                })?;
            from_main += 1;
        } else {
            // Not exported by main - wire a typed no-op stub.
            let ft2 = ft.clone();
            linker
                .func_new("env", name.as_str(), ft2, |_, _, results| {
                    for r in results.iter_mut() {
                        *r = match *r {
                            Val::I32(_) => Val::I32(0),
                            Val::I64(_) => Val::I64(0),
                            Val::F32(_) => Val::F32(0),
                            Val::F64(_) => Val::F64(0),
                            other => other,
                        };
                    }
                    Ok(())
                })
                .map_err(|e| {
                    AfterburnerError::Engine(format!("sidemodule wire stub env.{name}: {e}"))
                })?;
            from_stub += 1;
        }
    }
    eprintln!("[sidemodule] {path}: env imports: {from_main} from main, {from_stub} stubs");

    // Instantiate the SIDE_MODULE. The active element segment fires here and
    // places the side module's own functions into the shared table at slots
    // [table_base .. table_base + table_size).
    let instance = linker
        .instantiate(&mut *store, &module)
        .map_err(|e| AfterburnerError::Engine(format!("sidemodule instantiate {path}: {e}")))?;
    eprintln!("[sidemodule] {path}: instantiated");

    // Build a name->table_slot map from the side module's name section and
    // element segments. This is the source-of-truth for which table slot each
    // side-module function occupies after instantiation.
    let name_to_slot = parse_got_name_to_slot(wasm_bytes, table_base);
    eprintln!(
        "[sidemodule] {path}: element segment map has {} entries (table_base={table_base})",
        name_to_slot.len()
    );

    // updateGOT(moduleExports): write each GOT.func global with the table slot
    // of the corresponding function. Mirrors Emscripten's updateGOT which calls
    // addFunction(value) for each function export to get the slot index.
    //
    // Resolution order (mirrors Emscripten's updateGOT + resolveGlobalSymbol):
    // 1. Side module's own element segment (name_to_slot): the canonical slot
    //    the active element segment already wrote the funcref into. This is the
    //    path for the side module's own C functions (tp_traverse, etc.).
    // 2. Side module's exported function (not in element segment): insert into
    //    the shared table at the next available slot.
    // 3. Main module's exported function: same as (2) but from main.
    // 4. Leave at 0 if not found (will trap on indirect call, loudly).
    //
    // CRITICAL: this runs BEFORE __wasm_apply_data_relocs so that when that
    // function reads GOT.func globals to fill fn-ptr-in-data fields (e.g.
    // PyTypeObject.tp_traverse), the globals hold valid table slot indices
    // rather than 0 (which would write garbage/null into the type objects).
    let mut got_func_from_elem = 0u32;
    let mut got_func_from_side = 0u32;
    let mut got_func_from_main = 0u32;
    let mut got_func_zero = 0u32;

    let Some(tbl) = store.data().pyodide_table else {
        return Err(AfterburnerError::Engine(
            "pre_load_side_module: pyodide_table missing for updateGOT".into(),
        ));
    };

    for (name, g) in &got_func_globals {
        // Path 1: side module's own element segment.
        if let Some(&slot) = name_to_slot.get(name.as_str()) {
            let _ = g.set(&mut *store, Val::I32(slot as i32));
            got_func_from_elem += 1;
            continue;
        }

        // Path 2: side module's own exported function (not in element segment).
        if let Some(func) = instance.get_func(&mut *store, name.as_str()) {
            let slot = tbl.size(&*store) as u32;
            if tbl.grow(&mut *store, 1, wasmtime::Ref::Func(None)).is_ok()
                && tbl
                    .set(&mut *store, slot as u64, wasmtime::Ref::Func(Some(func)))
                    .is_ok()
            {
                let _ = g.set(&mut *store, Val::I32(slot as i32));
                got_func_from_side += 1;
                continue;
            }
        }

        // Path 3: main module's exported function.
        if let Some(func) = main_instance.get_func(&mut *store, name.as_str()) {
            let slot = tbl.size(&*store) as u32;
            if tbl.grow(&mut *store, 1, wasmtime::Ref::Func(None)).is_ok()
                && tbl
                    .set(&mut *store, slot as u64, wasmtime::Ref::Func(Some(func)))
                    .is_ok()
            {
                let _ = g.set(&mut *store, Val::I32(slot as i32));
                got_func_from_main += 1;
                continue;
            }
        }

        // Path 4: unresolved - leave at 0 (traps loudly on indirect call).
        got_func_zero += 1;
    }
    eprintln!(
        "[sidemodule] {path}: updateGOT: elem={got_func_from_elem} side={got_func_from_side} \
         main={got_func_from_main} zero={got_func_zero}"
    );

    // Build func_table_slots for every exported function:
    //
    // Phase A - element segment: if the export's func_index appears in the
    //   element segment (via name_to_slot from parse_got_name_to_slot), record
    //   the pre-placed slot directly.
    //
    // Phase B - eager insert: for exports NOT in the element segment (e.g.
    //   PyInit_* which Emscripten keeps out of the table until dlopen time),
    //   grow the shared table by 1, place the funcref there, and record the
    //   slot. This mirrors what _dlsym_js does lazily but done up front so
    //   path 1 (pre_slot) in _dlsym_js always hits.
    //
    // Exports that are internal helpers (__wasm_call_ctors, etc.) also get
    // table slots here; they may be needed by indirect calls during ctors.
    let Some(tbl) = store.data().pyodide_table else {
        return Err(AfterburnerError::Engine(
            "pre_load_side_module: pyodide_table missing for func_table_slots".into(),
        ));
    };

    let exported_funcs: Vec<String> = module
        .exports()
        .filter(|e| matches!(e.ty(), wasmtime::ExternType::Func(_)))
        .map(|e| e.name().to_owned())
        .collect();
    let total_exports = exported_funcs.len();

    let mut func_table_slots: HashMap<String, u32> = HashMap::with_capacity(total_exports);
    let mut from_elem = 0usize;
    let mut inserted = 0usize;

    for name in &exported_funcs {
        if let Some(&slot) = name_to_slot.get(name.as_str()) {
            // Phase A: already placed by the element segment.
            func_table_slots.insert(name.clone(), slot);
            from_elem += 1;
            continue;
        }
        // Phase B: not in element segment - insert into the shared table now.
        let Some(func) = instance.get_func(&mut *store, name.as_str()) else {
            continue;
        };
        let slot = tbl.size(&*store) as u32;
        if tbl.grow(&mut *store, 1, wasmtime::Ref::Func(None)).is_err() {
            continue;
        }
        if tbl
            .set(&mut *store, slot as u64, wasmtime::Ref::Func(Some(func)))
            .is_err()
        {
            continue;
        }
        func_table_slots.insert(name.clone(), slot);
        inserted += 1;
    }

    eprintln!(
        "[sidemodule] {path}: {} export table slots resolved ({} from element segment, \
         {} eagerly inserted) ({total_exports} exports total, {} not in table)",
        func_table_slots.len(),
        from_elem,
        inserted,
        total_exports - func_table_slots.len(),
    );

    // Call __wasm_apply_data_relocs AFTER updateGOT so it reads correct slot
    // indices when filling fn-ptr-in-data fields (PyTypeObject slots, etc.).
    if let Some(reloc_fn) = instance.get_func(&mut *store, "__wasm_apply_data_relocs") {
        reloc_fn.call(&mut *store, &[], &mut []).map_err(|e| {
            AfterburnerError::Engine(format!("sidemodule __wasm_apply_data_relocs {path}: {e}"))
        })?;
        eprintln!("[sidemodule] {path}: __wasm_apply_data_relocs OK");
    }

    // Call __wasm_call_ctors if present.
    if let Some(ctors_fn) = instance.get_func(&mut *store, "__wasm_call_ctors") {
        ctors_fn.call(&mut *store, &[], &mut []).map_err(|e| {
            AfterburnerError::Engine(format!("sidemodule __wasm_call_ctors {path}: {e}"))
        })?;
        eprintln!("[sidemodule] {path}: __wasm_call_ctors OK");
    }

    // Next bases: memory_base advances past this module's allocation;
    // table_base advances past this module's table slots.
    let next_memory_base = memory_base.saturating_add(dylink.mem_size);
    let next_table_base = table_base.saturating_add(dylink.table_size);

    Ok((
        SideModuleHandle {
            instance,
            func_table_slots,
        },
        next_memory_base,
        next_table_base,
    ))
}

/// Wire `env._dlopen_js`, `env._dlsym_js`, and `env._emscripten_dlopen_js`
/// against the [`SideModuleRegistry`] stored in [`EmbedderState::side_modules`].
///
/// Called from `emscripten_mechanical::wire_mechanical_env_funcs`. Extracted
/// here to keep that file under 1000 lines.
///
/// ## ABI (from pyodide.asm.js + wasm type section)
///
/// `_dlopen_js(handle_struct_ptr: i32) -> i32`  [wasm type 2]
///   - `handle_struct_ptr` points to the Emscripten LDSO DSO struct in linear
///     memory. The filename C string starts directly at `handle_struct_ptr + 36`
///     (from pyodide.asm.js: `UTF8ToString(handle+36)` - direct string, NOT a
///     pointer stored at +36).
///   - Returns the 1-based opaque handle integer, or 0 on failure.
///
/// `_dlsym_js(handle: i32, sym_ptr: i32, sym_idx_ptr: i32) -> i32`  [wasm type 1]
///   - `handle` is the value returned by `_dlopen_js`.
///   - `sym_ptr` points to the null-terminated symbol name.
///   - `sym_idx_ptr` receives the export index within the lib (written as u32).
///   - Returns the table slot at which the function was placed (non-zero = success).
///     For symbols not placed in the element segment (e.g. `PyInit_*`), the func
///     is inserted into the shared `__indirect_function_table` at the next slot
///     past the side module's pre-allocated range and that slot is returned.
pub fn wire_dlopen_dlsym(linker: &mut Linker<EmbedderState>) -> Result<()> {
    linker.allow_shadowing(true);

    linker
        .func_wrap(
            "env",
            "_dlopen_js",
            |mut caller: Caller<'_, EmbedderState>, handle_struct_ptr: i32| -> i32 {
                // The filename C string starts directly at handle_struct_ptr+36
                // (from emscripten libdylink.js: `UTF8ToString(handle + C_STRUCTS.dso.name)`
                // where dso.name = 36 - a direct string, not a pointer stored at +36).
                let name_str_ptr = (handle_struct_ptr as u32).saturating_add(36) as i32;
                let Some(name) = read_cstr_sidemodule(&caller, name_str_ptr) else {
                    eprintln!("[dlopen_js] cannot read filename at handle+36={name_str_ptr:#x}");
                    return 0;
                };
                eprintln!("[dlopen_js] looking up '{name}'");
                let dso_ptr = handle_struct_ptr as u32;
                // Fast path: already mapped from a prior call.
                if caller.data().side_modules.get_by_ptr(dso_ptr).is_some() {
                    eprintln!("[dlopen_js] cached dso_ptr={dso_ptr:#x} for '{name}'");
                    return handle_struct_ptr;
                }
                match caller
                    .data()
                    .side_modules
                    .find_by_path(&name)
                    .map(|(i, _)| i)
                {
                    Some(idx) => {
                        // Mirror Emscripten LDSO: key = raw DSO struct pointer.
                        // _dlsym_js will be called with the same pointer.
                        caller.data_mut().side_modules.map_ptr(dso_ptr, idx);
                        eprintln!(
                            "[dlopen_js] mapped dso_ptr={dso_ptr:#x} -> idx={idx} for '{name}'"
                        );
                        handle_struct_ptr
                    }
                    None => {
                        eprintln!("[dlopen_js] MISS: '{name}' not pre-loaded");
                        0
                    }
                }
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("wire _dlopen_js: {e}")))?;

    linker
        .func_wrap(
            "env",
            "_dlsym_js",
            |mut caller: Caller<'_, EmbedderState>,
             handle: i32,
             sym_ptr: i32,
             sym_idx_ptr: i32|
             -> i32 {
                let sym_name = match read_cstr_sidemodule(&caller, sym_ptr) {
                    Some(s) => s,
                    None => {
                        eprintln!("[dlsym_js] cannot read symbol at {sym_ptr:#x}");
                        return 0;
                    }
                };
                // handle is the raw DSO struct pointer returned by _dlopen_js,
                // which is the same pointer Emscripten uses as LDSO.loadedLibsByHandle key.
                let dso_ptr = handle as u32;
                eprintln!("[dlsym_js] dso_ptr={dso_ptr:#x} symbol='{sym_name}'");

                // Instance and table are Copy; snapshot them before any mut borrow.
                let instance_opt = caller
                    .data()
                    .side_modules
                    .get_by_ptr(dso_ptr)
                    .map(|h| h.instance);
                let table_opt = caller.data().pyodide_table;

                let (Some(instance), Some(table)) = (instance_opt, table_opt) else {
                    eprintln!("[dlsym_js] MISS: dso_ptr={dso_ptr:#x} not found or table absent");
                    return 0;
                };

                // Check if the slot was pre-computed from the element segment.
                let pre_slot = caller
                    .data()
                    .side_modules
                    .get_by_ptr(dso_ptr)
                    .and_then(|h| h.func_table_slots.get(&sym_name).copied());

                if let Some(slot) = pre_slot {
                    // Symbol is already in the table at the correct slot.
                    write_sym_idx(&mut caller, sym_idx_ptr, slot);
                    eprintln!("[dlsym_js] pre-slot '{sym_name}' -> {slot}");
                    return slot as i32;
                }

                // Symbol not in element segment - get its Func and insert into
                // the shared table at the next available slot past the current end.
                let func_opt = instance.get_func(&mut caller, sym_name.as_str());
                let Some(func) = func_opt else {
                    eprintln!("[dlsym_js] MISS: '{sym_name}' not exported by side module");
                    return 0;
                };

                // Grow the table by 1 to get a fresh slot, then place the func there.
                let slot = table.size(&caller) as u32;
                if let Err(e) = table.grow(&mut caller, 1, wasmtime::Ref::Func(None)) {
                    eprintln!("[dlsym_js] table grow for '{sym_name}': {e}");
                    return 0;
                }
                if let Err(e) = table.set(&mut caller, slot as u64, wasmtime::Ref::Func(Some(func)))
                {
                    eprintln!("[dlsym_js] table.set slot {slot} for '{sym_name}': {e}");
                    return 0;
                }

                // Cache the slot in the registry for future lookups.
                caller
                    .data_mut()
                    .side_modules
                    .set_slot(dso_ptr, sym_name.clone(), slot);

                write_sym_idx(&mut caller, sym_idx_ptr, slot);
                eprintln!("[dlsym_js] inserted '{sym_name}' -> table slot {slot}");
                slot as i32
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("wire _dlsym_js: {e}")))?;

    // Async dlopen variant: fire no callbacks (we pre-loaded everything).
    linker
        .func_wrap(
            "env",
            "_emscripten_dlopen_js",
            |_: Caller<'_, EmbedderState>, _h: i32, _ok: i32, _err: i32, _ud: i32| {},
        )
        .map_err(|e| AfterburnerError::Engine(format!("wire _emscripten_dlopen_js: {e}")))?;

    Ok(())
}

/// Write a u32 slot index into guest memory at `sym_idx_ptr` if the pointer
/// is non-zero and in bounds.
fn write_sym_idx(caller: &mut Caller<'_, EmbedderState>, sym_idx_ptr: i32, slot: u32) {
    if sym_idx_ptr == 0 {
        return;
    }
    let Some(mem) = caller.data().pyodide_memory else {
        return;
    };
    let data = mem.data_mut(caller);
    let off = sym_idx_ptr as u32 as usize;
    if off + 4 <= data.len() {
        data[off..off + 4].copy_from_slice(&slot.to_le_bytes());
    }
}

/// Read a NUL-terminated C string from guest memory using `EmbedderState::pyodide_memory`.
///
/// Private to this module; mirrors `emscripten_mechanical::read_cstr` to avoid
/// a circular import (both crates need the same helper in opposite directions).
fn read_cstr_sidemodule(caller: &Caller<'_, EmbedderState>, ptr: i32) -> Option<String> {
    let mem = caller.data().pyodide_memory?;
    let data = mem.data(caller);
    let start = ptr as u32 as usize;
    if start >= data.len() {
        return None;
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|n| start + n)?;
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}
