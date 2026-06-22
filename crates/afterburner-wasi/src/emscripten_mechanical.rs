// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Mechanical Emscripten env.* imports: syscalls, memory ops, C++ EH, invoke trampolines.

use std::sync::Arc;

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Engine, FuncType, Linker, ValType};

use crate::{
    embedder_vm::EmbedderState,
    emscripten_abi::{VIRTUAL_EPOCH_MS, VIRTUAL_NOW_MS},
    emscripten_runtime::{MechCallLog, PYODIDE_MEMORY_MAX_PAGES, caller_memory, invoke_dispatch},
};

type WtResult<T> = wasmtime::Result<T>;

/// Read a null-terminated C string from guest memory at `ptr`.
///
/// Uses `EmbedderState::pyodide_memory` (set by `wire_env_memory_and_table_in_store`)
/// because Emscripten modules import rather than export their linear memory.
/// Returns `None` if the memory handle is absent, the pointer is out of bounds,
/// or the string is not valid UTF-8. Silently replaces invalid UTF-8 sequences.
fn read_cstr(caller: &Caller<'_, EmbedderState>, ptr: i32) -> Option<String> {
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

    // def_syscall!: returns -1 (ENOSYS) with N i32 arguments, recording name + first 2 args.
    macro_rules! def_syscall {
        ($name:expr, 1) => {{
            let _log = mech_log.clone();
            linker
                .func_wrap(
                    "env",
                    $name,
                    move |_: Caller<'_, EmbedderState>, a: i32| -> i32 {
                        _log.push($name, a, 0);
                        -1
                    },
                )
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        }};
        ($name:expr, 2) => {{
            let _log = mech_log.clone();
            linker
                .func_wrap(
                    "env",
                    $name,
                    move |_: Caller<'_, EmbedderState>, a: i32, b: i32| -> i32 {
                        _log.push($name, a, b);
                        -1
                    },
                )
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        }};
        ($name:expr, 3) => {{
            let _log = mech_log.clone();
            linker
                .func_wrap(
                    "env",
                    $name,
                    move |_: Caller<'_, EmbedderState>, a: i32, b: i32, _c: i32| -> i32 {
                        _log.push($name, a, b);
                        -1
                    },
                )
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        }};
        ($name:expr, 4) => {{
            let _log = mech_log.clone();
            linker
                .func_wrap(
                    "env",
                    $name,
                    move |_: Caller<'_, EmbedderState>, a: i32, b: i32, _c: i32, _d: i32| -> i32 {
                        _log.push($name, a, b);
                        -1
                    },
                )
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        }};
        ($name:expr, 5) => {{
            let _log = mech_log.clone();
            linker
                .func_wrap(
                    "env",
                    $name,
                    move |_: Caller<'_, EmbedderState>,
                          a: i32,
                          b: i32,
                          _c: i32,
                          _d: i32,
                          _e: i32|
                          -> i32 {
                        _log.push($name, a, b);
                        -1
                    },
                )
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        }};
        ($name:expr, 6) => {{
            let _log = mech_log.clone();
            linker
                .func_wrap(
                    "env",
                    $name,
                    move |_: Caller<'_, EmbedderState>,
                          a: i32,
                          b: i32,
                          _c: i32,
                          _d: i32,
                          _e: i32,
                          _f: i32|
                          -> i32 {
                        _log.push($name, a, b);
                        -1
                    },
                )
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        }};
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
                    buf.extend_from_slice(b"[warn] ");
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
                    buf.extend_from_slice(b"[error] ");
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
                    buf.extend_from_slice(b"[err] ");
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
            let Some(memory) = caller_memory(&mut caller) else {
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
            let Some(memory) = caller_memory(&mut caller) else {
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
            let Some(memory) = caller_memory(&mut caller) else {
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
    def!("__cxa_throw", |_: Caller<'_, EmbedderState>,
                         _ptr: i32,
                         _tp: i32,
                         _dtor: i32|
     -> WtResult<()> {
        Err(wasmtime::Trap::UnreachableCodeReached.into())
    });
    def!("__cxa_find_matching_catch_2", |_: Caller<
        '_,
        EmbedderState,
    >|
     -> i32 { 0 });
    def!("__cxa_find_matching_catch_3", |_: Caller<
        '_,
        EmbedderState,
    >,
                                         _a: i32|
     -> i32 { 0 });
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
                let Some(memory) = caller_memory(&mut caller) else {
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
    {
        let _log = mech_log.clone();
        def!("_PyEM_TrampolineCall_JS", move |_: Caller<
            '_,
            EmbedderState,
        >,
                                              f: i32,
                                              a: i32,
                                              _b: i32,
                                              _c: i32|
              -> i32 {
            _log.push("_PyEM_TrampolineCall_JS", f, a);
            0
        });
    }
    {
        let _log = mech_log.clone();
        def!("_PyImport_InitFunc_TrampolineCall", move |_: Caller<
            '_,
            EmbedderState,
        >,
                                                        f: i32|
              -> i32 {
            _log.push("_PyImport_InitFunc_TrampolineCall", f, 0);
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

    // ---- syscall stubs ------------------------------------------------------

    def_syscall!("__syscall_openat", 4);
    def_syscall!("__syscall_read", 3);
    def_syscall!("__syscall_close", 1);
    def_syscall!("__syscall_fstat64", 2);
    def_syscall!("__syscall_stat64", 2);
    def_syscall!("__syscall_lstat64", 2);
    def_syscall!("__syscall_newfstatat", 4);
    def_syscall!("__syscall_ioctl", 3);
    def_syscall!("__syscall_getcwd", 2);
    def_syscall!("__syscall_getdents64", 3);
    def_syscall!("__syscall_readlinkat", 4);
    def_syscall!("__syscall_mkdirat", 3);
    def_syscall!("__syscall_mknodat", 4);
    def_syscall!("__syscall_unlinkat", 3);
    def_syscall!("__syscall_rmdir", 1);
    def_syscall!("__syscall_renameat", 4);
    def_syscall!("__syscall_symlink", 2);
    def_syscall!("__syscall_symlinkat", 3);
    def_syscall!("__syscall_chdir", 1);
    def_syscall!("__syscall_chmod", 2);
    def_syscall!("__syscall_fchmod", 2);
    def_syscall!("__syscall_fchmodat2", 4);
    def_syscall!("__syscall_fchown32", 3);
    def_syscall!("__syscall_fchownat", 5);
    def_syscall!("__syscall_fchdir", 1);
    def_syscall!("__syscall_dup", 1);
    def_syscall!("__syscall_dup3", 3);
    def_syscall!("__syscall_fcntl64", 3);
    def_syscall!("__syscall_fdatasync", 1);
    def_syscall!("__syscall_poll", 3);
    def_syscall!("__syscall_pipe", 1);
    def_syscall!("__syscall_utimensat", 4);
    def_syscall!("__syscall_faccessat", 4);
    def_syscall!("__syscall_socket", 6);
    def_syscall!("__syscall_bind", 6);
    def_syscall!("__syscall_connect", 6);
    def_syscall!("__syscall_listen", 6);
    def_syscall!("__syscall_accept4", 6);
    def_syscall!("__syscall_sendmsg", 6);
    def_syscall!("__syscall_recvmsg", 6);
    def_syscall!("__syscall_getsockopt", 6);
    def_syscall!("__syscall_getsockname", 6);
    def_syscall!("__syscall_getpeername", 6);

    // Syscalls with i64 params (not expressible via def_syscall!).
    linker
        .func_wrap(
            "env",
            "__syscall_fadvise64",
            |_: Caller<'_, EmbedderState>, _fd: i32, _off: i64, _len: i64, _adv: i32| -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_fadvise64: {e}")))?;
    linker
        .func_wrap(
            "env",
            "__syscall_fallocate",
            |_: Caller<'_, EmbedderState>, _fd: i32, _mode: i32, _off: i64, _len: i64| -> i32 {
                -1
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_fallocate: {e}")))?;
    linker
        .func_wrap(
            "env",
            "__syscall_ftruncate64",
            |_: Caller<'_, EmbedderState>, _fd: i32, _len: i64| -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_ftruncate64: {e}")))?;
    linker
        .func_wrap(
            "env",
            "__syscall_truncate64",
            |_: Caller<'_, EmbedderState>, _path: i32, _len: i64| -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_truncate64: {e}")))?;
    linker
        .func_wrap(
            "env",
            "__syscall_sendto",
            |_: Caller<'_, EmbedderState>,
             _fd: i32,
             _buf: i32,
             _len: i32,
             _f: i32,
             _addr: i32,
             _al: i32|
             -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_sendto: {e}")))?;
    linker
        .func_wrap(
            "env",
            "__syscall_recvfrom",
            |_: Caller<'_, EmbedderState>,
             _fd: i32,
             _buf: i32,
             _len: i32,
             _f: i32,
             _addr: i32,
             _al: i32|
             -> i32 { -1 },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_recvfrom: {e}")))?;

    def!("__syscall_fstatfs64", |_: Caller<'_, EmbedderState>,
                                 _fd: i32,
                                 _sz: i32,
                                 _buf: i32|
     -> i32 { -1 });
    def!("__syscall_statfs64", |_: Caller<'_, EmbedderState>,
                                _p: i32,
                                _sz: i32,
                                _buf: i32|
     -> i32 { -1 });
    def!("__syscall__newselect", |_: Caller<'_, EmbedderState>,
                                  _n: i32,
                                  _r: i32,
                                  _w: i32,
                                  _e: i32,
                                  _t: i32|
     -> i32 { 0 });

    // ---- invoke_* trampolines (data-driven via invoke_dispatch) --------------
    //
    // All invoke_* functions use the same generic `invoke_dispatch` closure:
    // params[0] is the table index, params[1..] are forwarded to the funcref.
    // FuncTypes are built from the signature implied by each name.
    {
        use ValType::{F32, F64, I32, I64};
        // (name, param_types_including_i32_index, result_types)
        let sigs: &[(&str, &[ValType], &[ValType])] = &[
            ("invoke_v", &[I32], &[]),
            ("invoke_i", &[I32], &[I32]),
            ("invoke_j", &[I32], &[I64]),
            ("invoke_vi", &[I32, I32], &[]),
            ("invoke_ii", &[I32, I32], &[I32]),
            ("invoke_ji", &[I32, I32], &[I64]),
            ("invoke_vii", &[I32, I32, I32], &[]),
            ("invoke_iii", &[I32, I32, I32], &[I32]),
            ("invoke_jii", &[I32, I32, I32], &[I64]),
            ("invoke_viii", &[I32, I32, I32, I32], &[]),
            ("invoke_iiii", &[I32, I32, I32, I32], &[I32]),
            ("invoke_jiii", &[I32, I32, I32, I32], &[I64]),
            ("invoke_fiii", &[I32, I32, I32, I32], &[F32]),
            ("invoke_diii", &[I32, I32, I32, I32], &[F64]),
            ("invoke_viiii", &[I32, I32, I32, I32, I32], &[]),
            ("invoke_iiiii", &[I32, I32, I32, I32, I32], &[I32]),
            ("invoke_jiiii", &[I32, I32, I32, I32, I32], &[I64]),
            ("invoke_viiiii", &[I32, I32, I32, I32, I32, I32], &[]),
            ("invoke_iiiiii", &[I32, I32, I32, I32, I32, I32], &[I32]),
            ("invoke_viiiiii", &[I32, I32, I32, I32, I32, I32, I32], &[]),
            (
                "invoke_iiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_viiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32],
                &[],
            ),
            (
                "invoke_iiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_viiiiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32],
                &[],
            ),
            (
                "invoke_iiiiiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_iiiiiiiiiiii",
                &[I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32],
                &[I32],
            ),
            (
                "invoke_iiiiiiiiiiiii",
                &[
                    I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32,
                ],
                &[I32],
            ),
            (
                "invoke_viiiiiiiiiiiiiii",
                &[
                    I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32, I32,
                ],
                &[],
            ),
            ("invoke_iiji", &[I32, I32, I64, I32], &[I32]),
            ("invoke_iiiiij", &[I32, I32, I32, I32, I32, I64], &[I32]),
            (
                "invoke_iiiiijj",
                &[I32, I32, I32, I32, I32, I64, I64],
                &[I32],
            ),
            ("invoke_viid", &[I32, I32, I32, F64], &[]),
            ("invoke_viif", &[I32, I32, I32, F32], &[]),
            ("invoke_viiidi", &[I32, I32, I32, I32, F64, I32], &[]),
            ("invoke_viiifi", &[I32, I32, I32, I32, F32, I32], &[]),
            ("invoke_viijii", &[I32, I32, I32, I64, I32, I32], &[]),
            ("invoke_viijj", &[I32, I32, I32, I64, I64], &[]),
            ("invoke_iiiiid", &[I32, I32, I32, I32, I32, F64], &[I32]),
        ];
        for &(name, params, results) in sigs {
            let ft = FuncType::new(engine, params.iter().cloned(), results.iter().cloned());
            linker
                .func_new("env", name, ft, invoke_dispatch)
                .map_err(|e| AfterburnerError::Engine(format!("{name}: {e}")))?;
        }
    }

    Ok(())
}
