// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Mechanical Emscripten env.* imports: syscalls, memory ops, C++ EH, invoke trampolines.

use std::sync::Arc;

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Engine, Linker};

use crate::{
    embedder_vm::EmbedderState,
    emscripten_abi::{VIRTUAL_EPOCH_MS, VIRTUAL_NOW_MS},
    emscripten_invoke::wire_invoke_trampolines,
    emscripten_runtime::{MechCallLog, PYODIDE_MEMORY_MAX_PAGES},
    emscripten_syscall::wire_fs_env_funcs,
};

type WtResult<T> = wasmtime::Result<T>;

/// Read a null-terminated C string from guest memory at `ptr`.
///
/// Uses `EmbedderState::pyodide_memory` (set by `wire_env_memory_and_table_in_store`)
/// because Emscripten modules import rather than export their linear memory.
/// Returns `None` if the memory handle is absent, the pointer is out of bounds,
/// or the string is not valid UTF-8. Silently replaces invalid UTF-8 sequences.
pub(crate) fn read_cstr(caller: &Caller<'_, EmbedderState>, ptr: i32) -> Option<String> {
    let mem = caller.data().pyodide_memory?;
    let data = mem.data(caller);
    let start = ptr as u32 as usize;
    if start >= data.len() {
        return None;
    }
    // Find the null terminator, bounded by memory length.
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|n| start + n)?;
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

/// Wire the pure-i32/i64/f64 env.* imports (syscalls, exceptions, trampolines).
///
/// `mech_log` receives the name (and first 1-2 integer args for syscalls)
/// of every mechanical env.* call; inspect [`MechCallLog::tail`] after a trap
/// to see the call sequence leading into the failure.
pub(crate) fn wire_mechanical_env_funcs(
    engine: &Engine,
    linker: &mut Linker<EmbedderState>,
    mech_log: Arc<MechCallLog>,
) -> Result<()> {
    linker.allow_shadowing(true);

    // def!: wrap a typed closure as an env.* import.
    macro_rules! def {
        ($name:expr, $func:expr) => {
            linker
                .func_wrap("env", $name, $func)
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        };
    }

    // ---- abort ---------------------------------------------------------------

    {
        let _log = mech_log.clone();
        def!(
            "abort",
            move |mut caller: Caller<'_, EmbedderState>| -> WtResult<()> {
                _log.push("abort", 0, 0);
                // Tag stdout so the probe can see the fatal signal even when
                // no prior fd_write has been called.
                caller
                    .data_mut()
                    .wasi_stdout
                    .extend_from_slice(b"[abort reached]\n");
                Err(wasmtime::Trap::UnreachableCodeReached.into())
            }
        );
    }
    {
        let _log = mech_log.clone();
        def!(
            "_abort_js",
            move |mut caller: Caller<'_, EmbedderState>| -> WtResult<()> {
                _log.push("_abort_js", 0, 0);
                caller
                    .data_mut()
                    .wasi_stdout
                    .extend_from_slice(b"[_abort_js reached]\n");
                Err(wasmtime::Trap::UnreachableCodeReached.into())
            }
        );
    }

    // ---- console / output ---------------------------------------------------
    //
    // emscripten_console_* and emscripten_err/out appear in GOT.func.* so they
    // must be wired as env.* imports with the correct signature. The module
    // passes a char* (i32 address) to these; we read the string from guest
    // memory and append it to wasi_stdout.

    {
        let _log = mech_log.clone();
        def!(
            "emscripten_console_log",
            move |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
                _log.push("emscripten_console_log", ptr, 0);
                if let Some(s) = read_cstr(&caller, ptr) {
                    let buf = &mut caller.data_mut().wasi_stdout;
                    buf.extend_from_slice(b"[console] ");
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(b'\n');
                }
            }
        );
    }
    {
        let _log = mech_log.clone();
        def!(
            "emscripten_console_warn",
            move |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
                _log.push("emscripten_console_warn", ptr, 0);
                if let Some(s) = read_cstr(&caller, ptr) {
                    let buf = &mut caller.data_mut().wasi_stdout;
                    buf.extend_from_slice(b"[console] ");
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(b'\n');
                }
            }
        );
    }
    {
        let _log = mech_log.clone();
        def!(
            "emscripten_console_error",
            move |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
                _log.push("emscripten_console_error", ptr, 0);
                if let Some(s) = read_cstr(&caller, ptr) {
                    let buf = &mut caller.data_mut().wasi_stdout;
                    buf.extend_from_slice(b"[console] ");
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(b'\n');
                }
            }
        );
    }
    {
        let _log = mech_log.clone();
        def!(
            "emscripten_err",
            move |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
                _log.push("emscripten_err", ptr, 0);
                if let Some(s) = read_cstr(&caller, ptr) {
                    let buf = &mut caller.data_mut().wasi_stdout;
                    buf.extend_from_slice(b"[console] ");
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(b'\n');
                }
            }
        );
    }
    {
        let _log = mech_log.clone();
        def!(
            "emscripten_out",
            move |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
                _log.push("emscripten_out", ptr, 0);
                if let Some(s) = read_cstr(&caller, ptr) {
                    let buf = &mut caller.data_mut().wasi_stdout;
                    buf.extend_from_slice(b"[console] ");
                    buf.extend_from_slice(s.as_bytes());
                    buf.push(b'\n');
                }
            }
        );
    }

    // ---- time ----------------------------------------------------------------

    def!(
        "emscripten_get_now",
        |_: Caller<'_, EmbedderState>| -> f64 { VIRTUAL_NOW_MS }
    );
    def!(
        "emscripten_date_now",
        |_: Caller<'_, EmbedderState>| -> f64 { VIRTUAL_EPOCH_MS }
    );
    def!(
        "emscripten_get_now_res",
        |_: Caller<'_, EmbedderState>| -> f64 { 1.0 }
    );

    // ---- heap ----------------------------------------------------------------

    {
        let _log = mech_log.clone();
        def!("emscripten_get_heap_max", move |_: Caller<
            '_,
            EmbedderState,
        >|
              -> i32 {
            _log.push("emscripten_get_heap_max", 0, 0);
            (PYODIDE_MEMORY_MAX_PAGES as u64 * 65536u64) as i32
        });
    }
    {
        let _log = mech_log.clone();
        def!("emscripten_resize_heap", move |mut caller: Caller<
            '_,
            EmbedderState,
        >,
                                             requested: i32|
              -> i32 {
            _log.push("emscripten_resize_heap", requested, 0);
            // pyodide.asm.wasm imports (not exports) its linear memory, so
            // caller.get_export("memory") returns None. Read the handle stored
            // in EmbedderState by wire_env_memory_and_table_in_store instead.
            let Some(memory) = caller.data().pyodide_memory else {
                return 0;
            };
            let current = memory.data_size(&caller);
            let wanted = requested as u32 as usize;
            if wanted <= current {
                return 1;
            }
            let pages = (wanted - current).div_ceil(65_536) as u64;
            match memory.grow(&mut caller, pages) {
                Ok(_) => 1,
                Err(_) => 0,
            }
        });
    }
    def!(
        "emscripten_memcpy_js",
        |mut caller: Caller<'_, EmbedderState>, dest: i32, src: i32, num: i32| {
            // Use pyodide_memory (the env.memory import handle) rather than
            // caller.get_export("memory") - Emscripten modules import, not export, memory.
            let Some(memory) = caller.data().pyodide_memory else {
                return;
            };
            let (d, s, n) = (
                dest as u32 as usize,
                src as u32 as usize,
                num as u32 as usize,
            );
            let mem = memory.data_mut(&mut caller);
            if s.checked_add(n).is_some_and(|e| e <= mem.len())
                && d.checked_add(n).is_some_and(|e| e <= mem.len())
            {
                mem.copy_within(s..s + n, d);
            }
        }
    );
    def!(
        "emscripten_memcpy_big",
        |mut caller: Caller<'_, EmbedderState>, dest: i32, src: i32, num: i32| {
            // Same as emscripten_memcpy_js: use pyodide_memory for the same reason.
            let Some(memory) = caller.data().pyodide_memory else {
                return;
            };
            let (d, s, n) = (
                dest as u32 as usize,
                src as u32 as usize,
                num as u32 as usize,
            );
            let mem = memory.data_mut(&mut caller);
            if s.checked_add(n).is_some_and(|e| e <= mem.len())
                && d.checked_add(n).is_some_and(|e| e <= mem.len())
            {
                mem.copy_within(s..s + n, d);
            }
        }
    );

    // ---- C++ exceptions -----------------------------------------------------

    def!("__cxa_begin_catch", |_: Caller<'_, EmbedderState>,
                               ptr: i32|
     -> i32 { ptr });
    def!("__cxa_end_catch", |_: Caller<'_, EmbedderState>| {});
    def!(
        "__cxa_rethrow",
        |_: Caller<'_, EmbedderState>| -> WtResult<()> {
            Err(wasmtime::Trap::UnreachableCodeReached.into())
        }
    );
    def!("__cxa_rethrow_primary_exception", |_: Caller<
        '_,
        EmbedderState,
    >,
                                             _p: i32|
     -> WtResult<()> {
        Err(wasmtime::Trap::UnreachableCodeReached.into())
    });
    def!("__cxa_current_primary_exception", |_: Caller<
        '_,
        EmbedderState,
    >|
     -> i32 { 0 });
    def!("__cxa_uncaught_exceptions", |_: Caller<
        '_,
        EmbedderState,
    >|
     -> i32 { 0 });
    def!("__cxa_throw", |mut caller: Caller<'_, EmbedderState>,
                         _ptr: i32,
                         _tp: i32,
                         _dtor: i32|
     -> WtResult<()> {
        // Store the exception pointer so __cxa_find_matching_catch_* can
        // return it to the landing pad after invoke_dispatch catches the trap.
        caller.data_mut().cxa_thrown_ptr = _ptr;
        Err(wasmtime::Trap::UnreachableCodeReached.into())
    });
    def!("__cxa_find_matching_catch_2", |caller: Caller<
        '_,
        EmbedderState,
    >|
     -> i32 {
        // Return the exception pointer that __cxa_throw stored so the landing
        // pad can inspect the thrown object. 0 = no active exception.
        caller.data().cxa_thrown_ptr
    });
    def!("__cxa_find_matching_catch_3", |caller: Caller<
        '_,
        EmbedderState,
    >,
                                         _a: i32|
     -> i32 {
        caller.data().cxa_thrown_ptr
    });
    def!("__resumeException", |_: Caller<'_, EmbedderState>,
                               _ptr: i32|
     -> WtResult<()> {
        Err(wasmtime::Trap::UnreachableCodeReached.into())
    });
    def!("__assert_fail", |_: Caller<'_, EmbedderState>,
                           _msg: i32,
                           _file: i32,
                           _line: i32,
                           _func: i32| {});
    def!(
        "__call_sighandler",
        |_: Caller<'_, EmbedderState>, _handler: i32, _signo: i32| {}
    );

    // ---- exit / longjmp ------------------------------------------------------

    def!("exit", |_: Caller<'_, EmbedderState>,
                  _c: i32|
     -> WtResult<()> {
        Err(wasmtime::Trap::UnreachableCodeReached.into())
    });
    def!("emscripten_exit_with_live_runtime", |_: Caller<
        '_,
        EmbedderState,
    >|
     -> WtResult<()> {
        Err(wasmtime::Trap::UnreachableCodeReached.into())
    });
    def!("_emscripten_throw_longjmp", |_: Caller<
        '_,
        EmbedderState,
    >|
     -> WtResult<()> {
        Err(wasmtime::Trap::UnreachableCodeReached.into())
    });

    // ---- mmap / munmap (i64 offset - not expressible via def_syscall!) ------

    linker
        .func_wrap(
            "env",
            "_mmap_js",
            |_: Caller<'_, EmbedderState>,
             _l: i32,
             _p: i32,
             _f: i32,
             _fd: i32,
             _o: i64,
             _al: i32,
             _a: i32|
             -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("_mmap_js: {e}")))?;
    linker
        .func_wrap(
            "env",
            "_munmap_js",
            |_: Caller<'_, EmbedderState>,
             _a: i32,
             _l: i32,
             _p: i32,
             _f: i32,
             _fd: i32,
             _o: i64|
             -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("_munmap_js: {e}")))?;
    linker
        .func_wrap(
            "env",
            "_msync_js",
            |_: Caller<'_, EmbedderState>,
             _a: i32,
             _l: i32,
             _p: i32,
             _f: i32,
             _fd: i32,
             _o: i64|
             -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("_msync_js: {e}")))?;

    // ---- time/locale stubs --------------------------------------------------

    def!("_gmtime_js", |_: Caller<'_, EmbedderState>,
                        _t: i64,
                        _tmptr: i32| {});
    def!("_localtime_js", |_: Caller<'_, EmbedderState>,
                           _t: i64,
                           _tmptr: i32| {});
    def!("_mktime_js", |_: Caller<'_, EmbedderState>,
                        _tmptr: i32|
     -> i64 { -1 });
    def!("_timegm_js", |_: Caller<'_, EmbedderState>,
                        _tmptr: i32|
     -> i64 { -1 });
    def!("_tzset_js", |_: Caller<'_, EmbedderState>,
                       _tz: i32,
                       _dl: i32,
                       _std: i32,
                       _dst: i32| {});
    def!("_setitimer_js", |_: Caller<'_, EmbedderState>,
                           _which: i32,
                           _ms: f64|
     -> i32 { -1 });
    def!("strftime", |_: Caller<'_, EmbedderState>,
                      _s: i32,
                      _max: i32,
                      _fmt: i32,
                      _tm: i32|
     -> i32 { 0 });
    def!("strftime_l", |_: Caller<'_, EmbedderState>,
                        _s: i32,
                        _max: i32,
                        _fmt: i32,
                        _tm: i32,
                        _loc: i32|
     -> i32 { 0 });

    // ---- network stubs ------------------------------------------------------

    def!("getaddrinfo", |_: Caller<'_, EmbedderState>,
                         _n: i32,
                         _s: i32,
                         _h: i32,
                         _r: i32|
     -> i32 { 8 });
    def!("getnameinfo", |_: Caller<'_, EmbedderState>,
                         _sa: i32,
                         _sl: i32,
                         _h: i32,
                         _hl: i32,
                         _sv: i32,
                         _svl: i32,
                         _f: i32|
     -> i32 { 1 });
    def!("getprotobyname", |_: Caller<'_, EmbedderState>,
                            _name: i32|
     -> i32 { 0 });
    {
        let _log = mech_log.clone();
        def!("getentropy", move |mut caller: Caller<
            '_,
            EmbedderState,
        >,
                                 buffer: i32,
                                 length: i32|
              -> i32 {
            _log.push("getentropy", buffer, length);
            // Emscripten modules import rather than export their linear memory,
            // so caller.get_export("memory") returns None. Use the pyodide_memory
            // handle set in EmbedderState by wire_env_memory_and_table_in_store.
            //
            // Deterministic fill (0xAB) in sealed mode - determinism is desired
            // so re-execution produces byte-identical results.
            //
            // vertexia: fixed fill; upgrade path is a seeded PRNG in EmbedderState
            // if callers need distinct entropy per instantiation.
            let Some(memory) = caller.data().pyodide_memory else {
                return -1;
            };
            let start = buffer as u32 as usize;
            let len = length as u32 as usize;
            let mem = memory.data_mut(&mut caller);
            if start.checked_add(len).is_some_and(|e| e <= mem.len()) {
                mem[start..start + len].fill(0xAB);
                0
            } else {
                -1
            }
        });
    }

    // ---- dlopen / dlsym stubs -----------------------------------------------

    def!("_dlopen_js", |_: Caller<'_, EmbedderState>,
                        _ptr: i32|
     -> i32 { 0 });
    def!("_dlsym_js", |_: Caller<'_, EmbedderState>,
                       _h: i32,
                       _s: i32,
                       _j: i32|
     -> i32 { 0 });
    def!(
        "_emscripten_dlopen_js",
        |_: Caller<'_, EmbedderState>, _h: i32, _ok: i32, _err: i32, _ud: i32| {}
    );

    // ---- EM_ASM / promise / keepalive stubs ---------------------------------

    def!("emscripten_asm_const_int", |_: Caller<
        '_,
        EmbedderState,
    >,
                                      _c: i32,
                                      _s: i32,
                                      _a: i32|
     -> i32 { 0 });
    def!("emscripten_promise_create", |_: Caller<
        '_,
        EmbedderState,
    >|
     -> i32 { 0 });
    def!(
        "emscripten_promise_destroy",
        |_: Caller<'_, EmbedderState>, _h: i32| {}
    );
    def!(
        "emscripten_promise_resolve",
        |_: Caller<'_, EmbedderState>, _h: i32, _r: i32, _v: i32| {}
    );
    def!("_emscripten_runtime_keepalive_clear", |_: Caller<
        '_,
        EmbedderState,
    >| {});
    def!("_emscripten_get_now_is_monotonic", |_: Caller<
        '_,
        EmbedderState,
    >|
     -> i32 { 1 });

    // ---- progname / system --------------------------------------------------

    {
        let _log = mech_log.clone();
        def!(
            "_emscripten_get_progname",
            move |mut caller: Caller<'_, EmbedderState>, buf: i32, len: i32| {
                _log.push("_emscripten_get_progname", buf, len);
                let name = b"pyodide\0";
                // Use pyodide_memory (the env.memory import handle) rather than
                // caller.get_export("memory") - Emscripten modules import memory.
                let Some(memory) = caller.data().pyodide_memory else {
                    return;
                };
                let (start, cap) = (buf as u32 as usize, len as u32 as usize);
                let n = name.len().min(cap);
                let mem = memory.data_mut(&mut caller);
                if start.checked_add(n).is_some_and(|e| e <= mem.len()) {
                    mem[start..start + n].copy_from_slice(&name[..n]);
                }
            }
        );
    }
    def!("_emscripten_lookup_name", |_: Caller<'_, EmbedderState>,
                                     _a: i32|
     -> i32 { 0 });
    def!("_emscripten_system", |_: Caller<'_, EmbedderState>,
                                _c: i32|
     -> i32 { -1 });

    // ---- Python-specific env shims ------------------------------------------

    {
        let _log = mech_log.clone();
        def!("_Py_emscripten_runtime", move |_: Caller<
            '_,
            EmbedderState,
        >|
              -> i32 {
            _log.push("_Py_emscripten_runtime", 0, 0);
            0
        });
    }
    {
        let _log = mech_log.clone();
        def!("_Py_CheckEmscriptenSignals_Helper", move |_: Caller<
            '_,
            EmbedderState,
        >|
              -> i32 {
            _log.push("_Py_CheckEmscriptenSignals_Helper", 0, 0);
            0
        });
    }
    {
        let _log = mech_log.clone();
        def!("_PyEM_detect_type_reflection", move |_: Caller<
            '_,
            EmbedderState,
        >|
              -> i32 {
            _log.push("_PyEM_detect_type_reflection", 0, 0);
            0
        });
    }
    {
        let _log = mech_log.clone();
        def!("_PyEM_CountFuncParams", move |_: Caller<
            '_,
            EmbedderState,
        >,
                                            f: i32|
              -> i32 {
            _log.push("_PyEM_CountFuncParams", f, 0);
            0
        });
    }
    // ---- test helpers -------------------------------------------------------

    def!("capture_stderr", |_: Caller<'_, EmbedderState>| {});
    def!("fail_test", |_: Caller<'_, EmbedderState>| {});
    def!(
        "throw_no_gil",
        |_: Caller<'_, EmbedderState>| -> WtResult<()> {
            Err(wasmtime::Trap::UnreachableCodeReached.into())
        }
    );
    def!("can_run_sync_js", |_: Caller<'_, EmbedderState>| -> i32 {
        0
    });
    def!(
        "hiwire_invalid_ref",
        |_: Caller<'_, EmbedderState>, _a: i32, _b: i32| {}
    );
    {
        let _log = mech_log.clone();
        def!(
            "jslib_init_js",
            move |_: Caller<'_, EmbedderState>| -> i32 {
                _log.push("jslib_init_js", 0, 0);
                1
            }
        );
    }
    {
        let _log = mech_log.clone();
        def!("jslib_init_buffers_js", move |_: Caller<
            '_,
            EmbedderState,
        >|
              -> i32 {
            _log.push("jslib_init_buffers_js", 0, 0);
            1
        });
    }
    {
        let _log = mech_log.clone();
        def!("pyodide_js_init", move |_: Caller<'_, EmbedderState>| {
            _log.push("pyodide_js_init", 0, 0);
        });
    }

    // ---- libffi JS bridge ---------------------------------------------------

    def!("ffi_call_js", |_: Caller<'_, EmbedderState>,
                         _cif: i32,
                         _fn: i32,
                         _rv: i32,
                         _av: i32| {});
    def!("ffi_closure_alloc_js", |_: Caller<'_, EmbedderState>,
                                  _sz: i32,
                                  _code: i32|
     -> i32 { 0 });
    def!(
        "ffi_closure_free_js",
        |_: Caller<'_, EmbedderState>, _ptr: i32| {}
    );
    def!("ffi_prep_closure_loc_js", |_: Caller<'_, EmbedderState>,
                                     _c: i32,
                                     _cif: i32,
                                     _fun: i32,
                                     _u: i32,
                                     _loc: i32|
     -> i32 { 1 });

    // ---- hiwire / proxy cache (non-externref variants) ----------------------

    def!("__hiwire_deduplicate_new", |_: Caller<
        '_,
        EmbedderState,
    >,
                                      _v: i32|
     -> i32 { 0 });
    def!("__hiwire_deduplicate_get", |_: Caller<
        '_,
        EmbedderState,
    >,
                                      _id: i32|
     -> i32 { 0 });
    def!(
        "__hiwire_deduplicate_set",
        |_: Caller<'_, EmbedderState>, _id: i32, _v: i32| {}
    );
    def!(
        "__hiwire_deduplicate_delete",
        |_: Caller<'_, EmbedderState>, _id: i32| {}
    );
    def!("proxy_cache_get", |_: Caller<'_, EmbedderState>,
                             _k: i32|
     -> i32 { 0 });
    def!("proxy_cache_set", |_: Caller<'_, EmbedderState>,
                             _k: i32,
                             _v: i32| {});

    // ---- syncify stubs ------------------------------------------------------

    def!("JsvPromise_Syncify_handleError", |_: Caller<
        '_,
        EmbedderState,
    >| {});

    // ---- filesystem and POSIX syscalls ---------------------------------------
    //
    // Real in-memory FS implementations plus ENOSYS stubs for all __syscall_*
    // imports live in emscripten_syscall.rs.
    wire_fs_env_funcs(linker, mech_log.clone())?;

    // ---- invoke_* and PyCFunction trampolines --------------------------------
    //
    // All table-dispatch trampolines (invoke_* family plus _PyEM_TrampolineCall_JS
    // and _PyImport_InitFunc_TrampolineCall) live in emscripten_invoke.rs.
    wire_invoke_trampolines(engine, linker)?;

    Ok(())
}
