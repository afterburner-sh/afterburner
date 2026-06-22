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
//! [`add_pyodide_imports`] wires `wasi_snapshot_preview1` via a real WASI
//! preview-1 context so Pyodide's fd_write/fd_read/proc_exit calls succeed.
//! The caller must create the store with a WASI-enabled [`EmbedderState`];
//! see [`EmbedderState::with_wasi`].
//!
//! ## Determinism
//!
//! All clock functions return fixed virtual constants from
//! [`crate::emscripten_abi`]. No real wall clock.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{
    Caller, Engine, Global, GlobalType, Linker, MemoryType, Mutability, Table, TableType, Val,
    ValType,
};
use wasmtime_wasi::p1::add_to_linker_sync;

use crate::{
    embedder_vm::EmbedderState, emscripten_jsffi::wire_jsffi_stubs,
    emscripten_mechanical::wire_mechanical_env_funcs,
};

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

// ---- memory helper -----------------------------------------------------------

pub(crate) fn caller_memory(caller: &mut Caller<'_, EmbedderState>) -> Option<wasmtime::Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
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
/// [`wire_env_memory_and_table_in_store`] with the instantiation store.
///
/// `log` receives the name of every JS-FFI stub call during execution.
pub fn add_pyodide_imports(
    engine: &Engine,
    linker: &mut Linker<EmbedderState>,
    log: Arc<JsFfiCallLog>,
) -> Result<()> {
    // Wire real WASI preview-1. Pyodide imports fd_write, fd_read, proc_exit,
    // etc. The store must be created with a WASI EmbedderState so the accessor
    // is non-None at call time.
    add_to_linker_sync(linker, |s: &mut EmbedderState| s.wasi_ctx_mut())
        .map_err(|e| AfterburnerError::Engine(format!("wasi preview1 linker: {e}")))?;

    wire_mechanical_env_funcs(engine, linker)?;
    wire_jsffi_stubs(engine, linker, log)?;
    Ok(())
}

/// Wire `env.memory`, `env.__indirect_function_table`, the three env base
/// globals, and ALL GOT.* globals into a store-bound linker.
///
/// Everything is created in `store` to satisfy wasmtime's same-store
/// requirement. Must be called with the exact store passed to instantiate.
pub fn wire_env_memory_and_table_in_store(
    store: &mut wasmtime::Store<EmbedderState>,
    linker: &mut Linker<EmbedderState>,
    memory_base: u32,
    table_base: u32,
    stack_base: u32,
) -> Result<()> {
    let mem_ty = MemoryType::new(PYODIDE_MEMORY_INITIAL_PAGES, Some(PYODIDE_MEMORY_MAX_PAGES));
    let memory = wasmtime::Memory::new(&mut *store, mem_ty)
        .map_err(|e| AfterburnerError::Engine(format!("pyodide memory: {e}")))?;
    linker
        .define(
            &mut *store,
            "env",
            "memory",
            wasmtime::Extern::Memory(memory),
        )
        .map_err(|e| AfterburnerError::Engine(format!("define env.memory: {e}")))?;

    let tbl_ty = TableType::new(wasmtime::RefType::FUNCREF, PYODIDE_TABLE_INITIAL_SIZE, None);
    let table = Table::new(&mut *store, tbl_ty, wasmtime::Ref::Func(None))
        .map_err(|e| AfterburnerError::Engine(format!("pyodide table: {e}")))?;
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

    // GOT.func and GOT.mem globals: mutable i32, zero-initialized.
    // Created in the same store so wasmtime's same-store check in
    // linker.instantiate passes. `__wasm_apply_data_relocs` patches them
    // at runtime with the actual symbol indices and memory addresses.
    //
    // vertexia: all GOT entries start at 0; a real dynamic linker patches them
    // at link time. Upgrade path: parse module exports to pre-fill GOTs.
    let got_ty = GlobalType::new(ValType::I32, Mutability::Var);
    for name in GOT_FUNC_NAMES {
        let g = Global::new(&mut *store, got_ty.clone(), Val::I32(0))
            .map_err(|e| AfterburnerError::Engine(format!("GOT.func.{name}: {e}")))?;
        linker
            .define(&mut *store, "GOT.func", name, wasmtime::Extern::Global(g))
            .map_err(|e| AfterburnerError::Engine(format!("define GOT.func.{name}: {e}")))?;
    }
    for name in GOT_MEM_NAMES {
        let g = Global::new(&mut *store, got_ty.clone(), Val::I32(0))
            .map_err(|e| AfterburnerError::Engine(format!("GOT.mem.{name}: {e}")))?;
        linker
            .define(&mut *store, "GOT.mem", name, wasmtime::Extern::Global(g))
            .map_err(|e| AfterburnerError::Engine(format!("define GOT.mem.{name}: {e}")))?;
    }

    Ok(())
}

// ---- GOT.func / GOT.mem global name tables -----------------------------------

const GOT_FUNC_NAMES: &[&str] = &[
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
    let Some(tbl) = caller
        .get_export("__indirect_function_table")
        .and_then(|e| e.into_table())
    else {
        return Err(wasmtime::Trap::UnreachableCodeReached.into());
    };
    let Some(wasmtime::Ref::Func(Some(func))) = tbl.get(&mut caller, idx) else {
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
