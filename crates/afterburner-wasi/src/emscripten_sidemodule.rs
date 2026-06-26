// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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
use std::sync::{Arc, OnceLock};

use afterburner_core::{AfterburnerError, Result};
use wasmparser::{KnownCustom, Parser, Payload};
use wasmtime::{
    AsContext, AsContextMut, Caller, Engine, ExternType, Func, FuncType, Global, GlobalType,
    Instance, Linker, Module, Mutability, Val, ValType,
};

use crate::embedder_vm::EmbedderState;
use crate::emscripten_dylink::{parse_got_name_to_slot, resolve_got_mem};
use crate::emscripten_runtime::default_val_for;
use crate::pyo_trace;

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
fn malloc_in_main<S>(
    store: &mut S,
    main_instance: &Instance,
    size: u32,
    align: u32,
    path: &str,
) -> Result<u32>
where
    S: AsContextMut<Data = EmbedderState>,
{
    // Allocate with enough padding to guarantee alignment: size + (align - 1).
    let alloc_size = size.saturating_add(align.saturating_sub(1));
    let malloc_fn = main_instance
        .get_func(store.as_context_mut(), "malloc")
        .ok_or_else(|| {
            AfterburnerError::Engine(format!(
                "sidemodule {path}: main instance has no 'malloc' export"
            ))
        })?;
    let mut result = [Val::I32(0)];
    malloc_fn
        .call(
            store.as_context_mut(),
            &[Val::I32(alloc_size as i32)],
            &mut result,
        )
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

    /// Return all loaded side module instances in insertion order.
    ///
    /// Used by `pre_load_side_module` to resolve `env.*` imports of a new
    /// side module against already-loaded side modules (e.g. `_umath_linalg`
    /// importing symbols exported by `_multiarray_umath`).
    pub fn all_instances(&self) -> Vec<Instance> {
        self.handles.iter().map(|(_, h)| h.instance).collect()
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
/// `side_instances` - already-loaded side module instances to resolve cross-module
///   `env.*` imports (e.g. `_umath_linalg` importing symbols from `_multiarray_umath`).
///
/// Memory layout is derived from the module's `dylink.0` custom section:
/// `__memory_base` is allocated via the main module's `malloc(mem_size)` so the
/// data segments land in already-backed linear memory. `__table_base` is the
/// current table size before growing by `table_size` from `dylink.0`.
///
/// Returns the [`SideModuleHandle`], the next available `memory_base` (pointer
/// after the allocated region), and the next available `table_base`.
///
/// Accepts any context implementing [`AsContextMut<Data = EmbedderState>`] so
/// it can be called both with a `&mut Store<EmbedderState>` and from within a
/// `func_wrap` host call passing `&mut Caller<EmbedderState>`.
///
/// vertexia: per-module GOT slot resolution; upgrade path is parsing the element
/// segment to get exact per-export table slots.
pub fn pre_load_side_module<S>(
    engine: &Engine,
    store: &mut S,
    main_instance: &Instance,
    side_instances: &[Instance],
    wasm_bytes: &[u8],
    path: &str,
) -> Result<(SideModuleHandle, u32, u32)>
where
    S: AsContextMut<Data = EmbedderState>,
{
    // The deterministic engine compiles the exnref EH proposal, not legacy
    // try/catch (wasmtime's Cranelift dropped legacy-EH codegen). A SIDE_MODULE
    // arriving from a stock wheel may still be legacy - notably CPython 3.14's
    // Pyodide emits legacy EH in its C-extension `.so` (numpy's core, pocketfft).
    // Translate it to exnref in process (the same lowering the build bundler
    // applies) so a stock wheel loads; a `.so` with no legacy EH passes through
    // unchanged. Without this the compile below fails with "legacy_exceptions
    // feature required", surfacing to CPython as "unknown dlopen() error".
    //
    // Done first so every subsequent parse (dylink.0, the GOT name->slot map)
    // reads the exact bytes the engine compiles and instantiates, keeping the
    // table-slot bookkeeping in lockstep with the instance regardless of any
    // reordering a future translator pass might do.
    let wasm_cow = crate::emscripten_exnref::maybe_translate_side_module(wasm_bytes, path)?;
    let wasm_bytes: &[u8] = wasm_cow.as_ref();

    // Parse dylink.0 for exact memory and table requirements.
    let dylink = parse_dylink0_mem_info(wasm_bytes);
    pyo_trace!(
        "[sidemodule] {path}: dylink.0 mem_size={} mem_align={} table_size={}",
        dylink.mem_size,
        dylink.mem_align,
        dylink.table_size
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
    pyo_trace!(
        "[sidemodule] {path}: malloc({}) -> memory_base={:#x}",
        dylink.mem_size,
        memory_base
    );

    pyo_trace!(
        "[sidemodule] compiling {} ({} bytes) memory_base={:#x}",
        path,
        wasm_bytes.len(),
        memory_base,
    );

    let module = Module::new(engine, wasm_bytes)
        .map_err(|e| AfterburnerError::Engine(format!("side module compile {path}: {e}")))?;

    // table_base = current table size; grow by dylink.0 table_size to reserve slots.
    let table_base = {
        let Some(tbl) = store.as_context().data().pyodide_table else {
            return Err(AfterburnerError::Engine(
                "pre_load_side_module: pyodide_table not set in store".into(),
            ));
        };
        let current = tbl.size(store.as_context()) as u32;
        let table_size = dylink.table_size.max(1);
        tbl.grow(
            store.as_context_mut(),
            table_size as u64,
            wasmtime::Ref::Func(None),
        )
        .map_err(|e| {
            AfterburnerError::Engine(format!("sidemodule table grow by {table_size}: {e}"))
        })?;
        pyo_trace!(
            "[sidemodule] {path}: grew table {current} -> {} (table_base={current}, delta={table_size})",
            tbl.size(store.as_context())
        );
        current
    };

    // Build a linker for the SIDE_MODULE.
    let mut linker: Linker<EmbedderState> = Linker::new(engine);
    linker.allow_shadowing(true);

    // Wire shared env.memory from the store state.
    // `define` takes `impl AsContext` (shared ref) so we can read from store.data().
    if let Some(mem) = store.as_context().data().pyodide_memory {
        linker
            .define(store.as_context_mut(), "env", "memory", mem)
            .map_err(|e| AfterburnerError::Engine(format!("sidemodule memory: {e}")))?;
    } else {
        return Err(AfterburnerError::Engine(
            "pre_load_side_module: pyodide_memory not set in store".into(),
        ));
    }

    // Wire shared __indirect_function_table.
    if let Some(tbl) = store.as_context().data().pyodide_table {
        linker
            .define(
                store.as_context_mut(),
                "env",
                "__indirect_function_table",
                tbl,
            )
            .map_err(|e| AfterburnerError::Engine(format!("sidemodule table: {e}")))?;
    } else {
        return Err(AfterburnerError::Engine(
            "pre_load_side_module: pyodide_table not set in store".into(),
        ));
    }

    // env.__memory_base: this module's offset in shared memory.
    let mb_ty = GlobalType::new(ValType::I32, Mutability::Const);
    let mb_val = Global::new(
        store.as_context_mut(),
        mb_ty.clone(),
        Val::I32(memory_base as i32),
    )
    .map_err(|e| AfterburnerError::Engine(format!("sidemodule __memory_base: {e}")))?;
    linker
        .define(store.as_context_mut(), "env", "__memory_base", mb_val)
        .map_err(|e| AfterburnerError::Engine(format!("define sidemodule __memory_base: {e}")))?;

    // env.__table_base: this module's table slot offset.
    let tb_val = Global::new(
        store.as_context_mut(),
        mb_ty.clone(),
        Val::I32(table_base as i32),
    )
    .map_err(|e| AfterburnerError::Engine(format!("sidemodule __table_base: {e}")))?;
    linker
        .define(store.as_context_mut(), "env", "__table_base", tb_val)
        .map_err(|e| AfterburnerError::Engine(format!("define sidemodule __table_base: {e}")))?;

    // env.__stack_pointer: ONE C stack pointer shared by ALL side modules.
    //
    // Emscripten's dynamic-linking C ABI keeps a single stack pointer across the
    // modules that pass C-stack pointers to one another: a callee reads the
    // argument frame the caller built on the stack, so two modules that call each
    // other with the wrong-aligned (private) stack pointer build and read frames
    // at different addresses and corrupt the C stack. The numpy.random failure is
    // exactly this: the Cython `bit_generator` side module builds the `np.zeros`
    // argument vector on its C stack and passes a pointer to numpy core's
    // `_multiarray_umath` side module; with per-module stacks the two clobber each
    // other and the boxed `pool_size=4` default reads back as a stray numpy rodata
    // pointer.
    //
    // The side modules therefore share ONE `__stack_pointer` global, created on the
    // first side-module load and reused for every subsequent one (stored in the
    // embedder state). It is deliberately NOT the main module's stack pointer: the
    // main CPython interpreter keeps its own stack, and side modules run nested
    // under it on a separate region, mirroring the layout the loader has always
    // used (`WASM_STACK_BASE`). Unifying only the side modules fixes the
    // cross-Cython-module corruption without disturbing the main interpreter's
    // independently-working stack.
    let side_sp = match store.as_context().data().pyodide_side_stack_pointer {
        Some(g) => g,
        None => {
            let g = Global::new(
                store.as_context_mut(),
                GlobalType::new(ValType::I32, Mutability::Var),
                Val::I32(crate::emscripten_runtime::WASM_STACK_BASE as i32),
            )
            .map_err(|e| {
                AfterburnerError::Engine(format!("sidemodule shared __stack_pointer: {e}"))
            })?;
            store.as_context_mut().data_mut().pyodide_side_stack_pointer = Some(g);
            g
        }
    };
    linker
        .define(store.as_context_mut(), "env", "__stack_pointer", side_sp)
        .map_err(|e| AfterburnerError::Engine(format!("define sidemodule __stack_pointer: {e}")))?;

    // Shared exnref EH tags from the main module, required for cross-module
    // exception interop. An exnref-translated .so imports these tags from
    // "env"; without them instantiation fails with "unknown import: env::__cpp_exception".
    // Both tags are Copy so reading from the context and passing to define both compile.
    if let Some(tag) = store.as_context().data().pyodide_cpp_exception_tag {
        linker
            .define(store.as_context_mut(), "env", "__cpp_exception", tag)
            .map_err(|e| {
                AfterburnerError::Engine(format!("define sidemodule __cpp_exception: {e}"))
            })?;
    }
    if let Some(tag) = store.as_context().data().pyodide_c_longjmp_tag {
        linker
            .define(store.as_context_mut(), "env", "__c_longjmp", tag)
            .map_err(|e| AfterburnerError::Engine(format!("define sidemodule __c_longjmp: {e}")))?;
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
        if linker
            .get(store.as_context_mut(), m.as_str(), name.as_str())
            .is_ok()
        {
            continue;
        }
        let g = Global::new(store.as_context_mut(), got_ty.clone(), Val::I32(0)).map_err(|e| {
            AfterburnerError::Engine(format!("GOT stub for sidemodule {m}.{name}: {e}"))
        })?;
        if m == "GOT.mem" {
            got_mem_globals.push((name.clone(), g));
        } else {
            got_func_globals.push((name.clone(), g));
        }
        linker
            .define(store.as_context_mut(), m.as_str(), name.as_str(), g)
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
    pyo_trace!("[sidemodule] {path}: GOT.mem resolved={got_mem_resolved} zero={got_mem_zero}");
    // Diagnostic: name the GOT.mem data-address symbols that stayed 0 (the main
    // module does not export them as a const global). A zeroed data pointer in a
    // side-module vtable / relocated field is a prime cause of a ctor-time trap.
    if crate::pyodide_trace::enabled() {
        for (name, g) in &got_mem_globals {
            if matches!(g.get(store.as_context_mut()), Val::I32(0)) {
                pyo_trace!("[sidemodule-gotmem-zero] {path}: GOT.mem.{name}");
            }
        }
    }

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

    // Function names this module itself exports. A SIDE_MODULE may both import a
    // symbol through `env` AND define+export it (Emscripten routes cross-symbol
    // references through `env`/`GOT` for dedup, then resolves them to a local
    // definition when one exists). Those imports must bind to the module's OWN
    // function, not a no-op stub - else a direct or indirect call through the
    // stub returns garbage / traps. CPython 3.14's newer LLVM emits these
    // self-`env` imports (e.g. numpy's `BOOL_*_wrapper`, `std::__2` helpers)
    // where the 3.13 wheels did not, so this only bites on 3.14.
    let self_exported_funcs: std::collections::HashSet<&str> = module
        .exports()
        .filter(|e| matches!(e.ty(), ExternType::Func(_)))
        .map(|e| e.name())
        .collect();

    let mut from_main = 0u32;
    let mut from_side = 0u32;
    let mut from_self = 0u32;
    let mut from_stub = 0u32;

    // Forwarding trampolines for self-`env` imports: each holds a cell filled
    // with the module's own export after instantiation (the instance does not
    // exist yet here). `Func` and `OnceLock<Func>` are `Send + Sync`, satisfying
    // the `func_new` closure bound. Collected so the cells can be filled below.
    let mut self_forward_cells: Vec<(String, Arc<OnceLock<Func>>)> = Vec::new();

    for (name, ft) in &env_func_types {
        // Skip already-defined (memory, table, __memory_base, etc.).
        if linker
            .get(store.as_context_mut(), "env", name.as_str())
            .is_ok()
        {
            continue;
        }

        if let Some(func) = main_instance.get_func(store.as_context_mut(), name.as_str()) {
            // Resolution path 1: main (pyodide) module.
            linker
                .define(store.as_context_mut(), "env", name.as_str(), func)
                .map_err(|e| {
                    AfterburnerError::Engine(format!("sidemodule wire env.{name} from main: {e}"))
                })?;
            from_main += 1;
        } else if let Some(func) = side_instances
            .iter()
            .find_map(|si| si.get_func(store.as_context_mut(), name.as_str()))
        {
            // Resolution path 2: already-loaded side modules (e.g. `_umath_linalg`
            // importing C-API symbols exported by `_multiarray_umath`).
            linker
                .define(store.as_context_mut(), "env", name.as_str(), func)
                .map_err(|e| {
                    AfterburnerError::Engine(format!("sidemodule wire env.{name} from side: {e}"))
                })?;
            from_side += 1;
        } else if self_exported_funcs.contains(name.as_str()) {
            // Resolution path 3: the module's OWN export. The instance does not
            // exist yet, so bind a forwarding trampoline whose target cell is
            // filled with `instance.get_func(name)` right after instantiation.
            let cell: Arc<OnceLock<Func>> = Arc::new(OnceLock::new());
            let cell_for_call = Arc::clone(&cell);
            let ft2 = ft.clone();
            let nparams = ft2.params().len();
            let nresults = ft2.results().len();
            let nm = name.clone();
            linker
                .func_new(
                    "env",
                    name.as_str(),
                    ft2,
                    move |mut caller, params, results| {
                        let Some(target) = cell_for_call.get() else {
                            return Err(wasmtime::Error::msg(format!(
                                "self-env forward env.{nm}: target not yet resolved"
                            )));
                        };
                        // Untyped forward: the trampoline's type equals the
                        // import's type equals the export's type, so the param /
                        // result slices line up one-to-one.
                        debug_assert_eq!(params.len(), nparams);
                        debug_assert_eq!(results.len(), nresults);
                        target.call(&mut caller, params, results)
                    },
                )
                .map_err(|e| {
                    AfterburnerError::Engine(format!("sidemodule wire self env.{name}: {e}"))
                })?;
            self_forward_cells.push((name.clone(), cell));
            from_self += 1;
        } else {
            // Not exported by main, any side module, or this module itself - wire
            // a typed no-op stub.
            pyo_trace!("[sidemodule-stub] {path}: env.{name}");
            let ft2 = ft.clone();
            let result_tys: Vec<ValType> = ft2.results().collect();
            linker
                .func_new("env", name.as_str(), ft2, move |_, _, results| {
                    // Zero each result by its DECLARED type (see default_val_for):
                    // the slot pre-fill is a null funcref regardless of type.
                    for (r, vt) in results.iter_mut().zip(&result_tys) {
                        *r = default_val_for(vt);
                    }
                    Ok(())
                })
                .map_err(|e| {
                    AfterburnerError::Engine(format!("sidemodule wire stub env.{name}: {e}"))
                })?;
            from_stub += 1;
        }
    }
    pyo_trace!(
        "[sidemodule] {path}: env imports: {from_main} from main, {from_side} from side, \
         {from_self} self-forward, {from_stub} stubs"
    );

    // Instantiate the SIDE_MODULE. The active element segment fires here and
    // places the side module's own functions into the shared table at slots
    // [table_base .. table_base + table_size).
    let instance = linker
        .instantiate(store.as_context_mut(), &module)
        .map_err(|e| AfterburnerError::Engine(format!("sidemodule instantiate {path}: {e}")))?;
    pyo_trace!("[sidemodule] {path}: instantiated");

    // Fill the self-`env` forwarding trampolines now that the instance exists:
    // point each at the module's own exported function. A name that does not
    // resolve (should not happen - it was in `self_exported_funcs`) leaves the
    // cell empty and the trampoline errors loudly if ever called.
    for (name, cell) in &self_forward_cells {
        if let Some(func) = instance.get_func(store.as_context_mut(), name.as_str()) {
            let _ = cell.set(func);
        } else {
            pyo_trace!("[sidemodule] {path}: self-env forward target missing: {name}");
        }
    }

    // GOT.mem self-resolution: a SIDE_MODULE imports the data-address symbols it
    // *defines itself* through `GOT.mem` (Emscripten routes every cross-symbol
    // data reference through the GOT for dedup) and exports the same symbols as
    // const globals. Those self-defined globals do not exist until the module is
    // instantiated, so the pre-instantiation `resolve_got_mem` pass (which reads
    // the MAIN instance) leaves them at 0. Re-resolve any still-zero GOT.mem
    // global now from the module's OWN export, before `__wasm_apply_data_relocs`
    // reads these globals to fill relocated data fields.
    //
    // CRITICAL: the module's exported global for a data symbol holds the symbol's
    // *static, segment-relative offset* (its link-time address taken with
    // `__memory_base` = 0), NOT an absolute address - the export is a plain
    // `(global (i32.const <offset>))` constant that never adds the runtime
    // `__memory_base`. A GOT.mem entry must be the ABSOLUTE address, so add this
    // module's `memory_base`. The MAIN-module pass needs no such adjustment: the
    // main module's data sits at memory base 0, so its exported globals are
    // already absolute.
    //
    // Without the `+ memory_base`, a vtable pointer (`_ZTV...`) is written as a raw
    // offset (e.g. 0x69d1c) far below the side module's data region
    // (`[memory_base, memory_base + mem_size)`); the first virtual call
    // dereferences that low MAIN-module address, reads a garbage function index,
    // and the `call_indirect` traps `TableOutOfBounds`. CPython 3.14's newer LLVM
    // emits these self-`GOT.mem` imports where the 3.13 wheels did not, so this
    // only bites on 3.14.
    {
        let mut self_resolved = 0u32;
        let mut still_zero = 0u32;
        for (name, g) in &got_mem_globals {
            if !matches!(g.get(store.as_context_mut()), Val::I32(0)) {
                continue;
            }
            let own_offset = instance
                .get_global(store.as_context_mut(), name.as_str())
                .filter(|eg| eg.ty(store.as_context()).mutability() == Mutability::Const)
                .and_then(|eg| match eg.get(store.as_context_mut()) {
                    Val::I32(v) => Some(v as u32),
                    _ => None,
                });
            match own_offset {
                Some(off) => {
                    let abs = memory_base.saturating_add(off);
                    let _ = g.set(store.as_context_mut(), Val::I32(abs as i32));
                    pyo_trace!(
                        "[sidemodule-gotmem-self] {path}: GOT.mem.{name} \
                         off={off:#x} + memory_base={memory_base:#x} = {abs:#x}"
                    );
                    self_resolved += 1;
                }
                None => still_zero += 1,
            }
        }
        pyo_trace!(
            "[sidemodule] {path}: GOT.mem self-resolve: {self_resolved} from own exports \
             (+ memory_base), {still_zero} still zero"
        );
    }

    // Build a name->table_slot map from the side module's name section and
    // element segments. This is the source-of-truth for which table slot each
    // side-module function occupies after instantiation.
    let name_to_slot = parse_got_name_to_slot(wasm_bytes, table_base);
    pyo_trace!(
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
    let mut got_func_from_self = 0u32;
    let mut got_func_from_side = 0u32;
    let mut got_func_from_main = 0u32;
    let mut got_func_zero = 0u32;

    let Some(tbl) = store.as_context().data().pyodide_table else {
        return Err(AfterburnerError::Engine(
            "pre_load_side_module: pyodide_table missing for updateGOT".into(),
        ));
    };

    for (name, g) in &got_func_globals {
        // Path 1: side module's own element segment.
        if let Some(&slot) = name_to_slot.get(name.as_str()) {
            let _ = g.set(store.as_context_mut(), Val::I32(slot as i32));
            got_func_from_elem += 1;
            continue;
        }

        // Path 2: this side module's own exported function (not in element segment).
        if let Some(func) = instance.get_func(store.as_context_mut(), name.as_str()) {
            let slot = tbl.size(store.as_context()) as u32;
            if tbl
                .grow(store.as_context_mut(), 1, wasmtime::Ref::Func(None))
                .is_ok()
                && tbl
                    .set(
                        store.as_context_mut(),
                        slot as u64,
                        wasmtime::Ref::Func(Some(func)),
                    )
                    .is_ok()
            {
                let _ = g.set(store.as_context_mut(), Val::I32(slot as i32));
                got_func_from_self += 1;
                continue;
            }
        }

        // Path 3: already-loaded side modules (cross-module GOT resolution).
        if let Some(func) = side_instances
            .iter()
            .find_map(|si| si.get_func(store.as_context_mut(), name.as_str()))
        {
            let slot = tbl.size(store.as_context()) as u32;
            if tbl
                .grow(store.as_context_mut(), 1, wasmtime::Ref::Func(None))
                .is_ok()
                && tbl
                    .set(
                        store.as_context_mut(),
                        slot as u64,
                        wasmtime::Ref::Func(Some(func)),
                    )
                    .is_ok()
            {
                let _ = g.set(store.as_context_mut(), Val::I32(slot as i32));
                got_func_from_side += 1;
                continue;
            }
        }

        // Path 4: main module's exported function.
        if let Some(func) = main_instance.get_func(store.as_context_mut(), name.as_str()) {
            let slot = tbl.size(store.as_context()) as u32;
            if tbl
                .grow(store.as_context_mut(), 1, wasmtime::Ref::Func(None))
                .is_ok()
                && tbl
                    .set(
                        store.as_context_mut(),
                        slot as u64,
                        wasmtime::Ref::Func(Some(func)),
                    )
                    .is_ok()
            {
                let _ = g.set(store.as_context_mut(), Val::I32(slot as i32));
                got_func_from_main += 1;
                continue;
            }
        }

        // Path 5: unresolved - leave at 0 (traps loudly on indirect call).
        got_func_zero += 1;
    }
    pyo_trace!(
        "[sidemodule] {path}: updateGOT: elem={got_func_from_elem} self={got_func_from_self} \
         side={got_func_from_side} main={got_func_from_main} zero={got_func_zero}"
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
    let Some(tbl) = store.as_context().data().pyodide_table else {
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
        let Some(func) = instance.get_func(store.as_context_mut(), name.as_str()) else {
            continue;
        };
        let slot = tbl.size(store.as_context()) as u32;
        if tbl
            .grow(store.as_context_mut(), 1, wasmtime::Ref::Func(None))
            .is_err()
        {
            continue;
        }
        if tbl
            .set(
                store.as_context_mut(),
                slot as u64,
                wasmtime::Ref::Func(Some(func)),
            )
            .is_err()
        {
            continue;
        }
        func_table_slots.insert(name.clone(), slot);
        inserted += 1;
    }

    pyo_trace!(
        "[sidemodule] {path}: {} export table slots resolved ({} from element segment, \
         {} eagerly inserted) ({total_exports} exports total, {} not in table)",
        func_table_slots.len(),
        from_elem,
        inserted,
        total_exports - func_table_slots.len(),
    );

    // Call __wasm_apply_data_relocs AFTER updateGOT so it reads correct slot
    // indices when filling fn-ptr-in-data fields (PyTypeObject slots, etc.).
    if let Some(reloc_fn) = instance.get_func(store.as_context_mut(), "__wasm_apply_data_relocs") {
        reloc_fn
            .call(store.as_context_mut(), &[], &mut [])
            .map_err(|e| {
                AfterburnerError::Engine(format!("sidemodule __wasm_apply_data_relocs {path}: {e}"))
            })?;
        pyo_trace!("[sidemodule] {path}: __wasm_apply_data_relocs OK");
    }

    // Call __wasm_call_ctors if present.
    if let Some(ctors_fn) = instance.get_func(store.as_context_mut(), "__wasm_call_ctors") {
        ctors_fn
            .call(store.as_context_mut(), &[], &mut [])
            .map_err(|e| {
                let kind = e
                    .downcast_ref::<wasmtime::Trap>()
                    .map(|t| format!(" [trap={t:?}]"))
                    .unwrap_or_default();
                let frames = e
                    .downcast_ref::<wasmtime::WasmBacktrace>()
                    .map(|bt| {
                        let f: Vec<u32> = bt
                            .frames()
                            .iter()
                            .take(6)
                            .map(|fr| fr.func_index())
                            .collect();
                        format!(" [frames={f:?}]")
                    })
                    .unwrap_or_default();
                AfterburnerError::Engine(format!(
                    "sidemodule __wasm_call_ctors {path}: {e}{kind}{frames}"
                ))
            })?;
        pyo_trace!("[sidemodule] {path}: __wasm_call_ctors OK");
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
                    pyo_trace!("[dlopen_js] cannot read filename at handle+36={name_str_ptr:#x}");
                    return 0;
                };
                pyo_trace!("[dlopen_js] looking up '{name}'");
                let dso_ptr = handle_struct_ptr as u32;
                // Fast path: already mapped from a prior call.
                if caller.data().side_modules.get_by_ptr(dso_ptr).is_some() {
                    pyo_trace!("[dlopen_js] cached dso_ptr={dso_ptr:#x} for '{name}'");
                    return handle_struct_ptr;
                }
                // Check if the path was already pre-loaded (just needs ptr mapping).
                if let Some(idx) = caller
                    .data()
                    .side_modules
                    .find_by_path(&name)
                    .map(|(i, _)| i)
                {
                    caller.data_mut().side_modules.map_ptr(dso_ptr, idx);
                    pyo_trace!(
                        "[dlopen_js] mapped dso_ptr={dso_ptr:#x} -> idx={idx} for '{name}'"
                    );
                    return handle_struct_ptr;
                }
                // On-demand load: read .so bytes from the in-memory FS, compile and
                // instantiate the SIDE_MODULE into the shared store, then register it.
                // This handles any .so CPython requests that was not pre-loaded.
                let so_bytes: Vec<u8> = {
                    // Build the full guest path: site-packages prefix + relative name.
                    // `name` is the basename as seen by CPython (e.g. "numpy/linalg/_umath_linalg...so").
                    // Try the name directly, then under SITE_PACKAGES, then common prefixes.
                    let candidates = [
                        name.clone(),
                        format!("/lib/python3.13/site-packages/{name}"),
                        format!("/lib/python3.12/site-packages/{name}"),
                        format!("/usr/lib/python3/site-packages/{name}"),
                    ];
                    let mut found = None;
                    for p in &candidates {
                        if let Some(b) = caller.data().fs.read_file(p.as_str()) {
                            found = Some(b.to_vec());
                            pyo_trace!("[dlopen_js] found '{name}' at '{p}'");
                            break;
                        }
                    }
                    match found {
                        Some(b) => b,
                        None => {
                            pyo_trace!(
                                "[dlopen_js] FS miss for '{name}' (tried {} paths)",
                                candidates.len()
                            );
                            return 0;
                        }
                    }
                };
                let engine = caller.engine().clone();
                let main_instance = match caller.data().main_instance {
                    Some(i) => i,
                    None => {
                        pyo_trace!("[dlopen_js] main_instance not set in store for '{name}'");
                        return 0;
                    }
                };
                let side_instances = caller.data().side_modules.all_instances();
                match pre_load_side_module(
                    &engine,
                    &mut caller,
                    &main_instance,
                    &side_instances,
                    &so_bytes,
                    &name,
                ) {
                    Ok((handle, _, _)) => {
                        let idx = caller.data_mut().side_modules.insert(name.clone(), handle);
                        caller.data_mut().side_modules.map_ptr(dso_ptr, idx);
                        pyo_trace!(
                            "[dlopen_js] on-demand loaded '{name}' -> idx={idx} dso_ptr={dso_ptr:#x}"
                        );
                        handle_struct_ptr
                    }
                    Err(e) => {
                        pyo_trace!("[dlopen_js] on-demand load FAILED for '{name}': {e}");
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
                        pyo_trace!("[dlsym_js] cannot read symbol at {sym_ptr:#x}");
                        return 0;
                    }
                };
                // handle is the raw DSO struct pointer returned by _dlopen_js,
                // which is the same pointer Emscripten uses as LDSO.loadedLibsByHandle key.
                let dso_ptr = handle as u32;
                pyo_trace!("[dlsym_js] dso_ptr={dso_ptr:#x} symbol='{sym_name}'");

                // Instance and table are Copy; snapshot them before any mut borrow.
                let instance_opt = caller
                    .data()
                    .side_modules
                    .get_by_ptr(dso_ptr)
                    .map(|h| h.instance);
                let table_opt = caller.data().pyodide_table;

                let (Some(instance), Some(table)) = (instance_opt, table_opt) else {
                    pyo_trace!("[dlsym_js] MISS: dso_ptr={dso_ptr:#x} not found or table absent");
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
                    pyo_trace!("[dlsym_js] pre-slot '{sym_name}' -> {slot}");
                    return slot as i32;
                }

                // Symbol not in element segment - get its Func and insert into
                // the shared table at the next available slot past the current end.
                let func_opt = instance.get_func(&mut caller, sym_name.as_str());
                let Some(func) = func_opt else {
                    pyo_trace!("[dlsym_js] MISS: '{sym_name}' not exported by side module");
                    return 0;
                };

                // Grow the table by 1 to get a fresh slot, then place the func there.
                let slot = table.size(&caller) as u32;
                if let Err(e) = table.grow(&mut caller, 1, wasmtime::Ref::Func(None)) {
                    pyo_trace!("[dlsym_js] table grow for '{sym_name}': {e}");
                    return 0;
                }
                if let Err(e) = table.set(&mut caller, slot as u64, wasmtime::Ref::Func(Some(func)))
                {
                    pyo_trace!("[dlsym_js] table.set slot {slot} for '{sym_name}': {e}");
                    return 0;
                }

                // Cache the slot in the registry for future lookups.
                caller
                    .data_mut()
                    .side_modules
                    .set_slot(dso_ptr, sym_name.clone(), slot);

                write_sym_idx(&mut caller, sym_idx_ptr, slot);
                pyo_trace!("[dlsym_js] inserted '{sym_name}' -> table slot {slot}");
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
