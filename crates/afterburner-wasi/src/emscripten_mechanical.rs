// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Mechanical Emscripten env.* imports: syscalls, memory ops, C++ EH, invoke trampolines.
// vertexia: file was 1010 lines before Section 3 work (pre-existing); ceiling = split into
// emscripten_mechanical/{core,invoke,memory,wire}.rs once the file exceeds steady growth.

use std::sync::Arc;

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Engine, FuncType, Linker, Val, ValType};

use crate::{
    embedder_vm::EmbedderState,
    emscripten_abi::{VIRTUAL_EPOCH_MS, VIRTUAL_NOW_MS},
    emscripten_invoke::wire_invoke_trampolines,
    emscripten_runtime::MechCallLog,
    emscripten_runtime::wasm_memory_config,
    emscripten_syscall::wire_fs_env_funcs,
    pyo_trace,
};

type WtResult<T> = wasmtime::Result<T>;

/// Return the configured maximum heap size in bytes as an i32 for Emscripten's
/// `emscripten_get_heap_max` ABI. Reads the env-driven config at call time so
/// the value tracks `BURN_WASM_MEMORY_MAX_BYTES` if set.
fn heap_max_bytes() -> i32 {
    // On parse failure fall back to the wasm32 ceiling (4 GiB).
    let cfg = wasm_memory_config().unwrap_or(crate::emscripten_runtime::WasmMemoryConfig {
        initial_pages: 480,
        max_pages: 65_536,
        stack_size_bytes: 10 * 1024 * 1024,
    });
    let max_bytes = cfg.max_pages as u64 * 65_536u64;
    // Stay one wasm page short of 4 GiB. A full 4 GiB byte count is 0x1_0000_0000,
    // which truncates to 0 in this i32 ABI - and 0 breaks every consumer that
    // treats the heap max as a size. This mirrors the runtime's own getHeapMax,
    // which caps at `min(max, FOUR_GB - WASM_PAGE_SIZE)` for exactly this reason.
    const FOUR_GB_MINUS_PAGE: u64 = 4_294_967_296 - 65_536; // 0xFFFF_0000
    (max_bytes.min(FOUR_GB_MINUS_PAGE) as u32) as i32
}

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

/// Deterministic civil-time breakdown for the clock host functions.
mod civil_time;

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
            heap_max_bytes()
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
        // Read the mangled type name from the std::type_info layout in
        // guest memory. On wasm32: [vtable_ptr @0][name_ptr @4].
        // Read i32 at type_info_ptr+4 -> pointer to NUL-terminated mangled name.
        let type_name: String = if let Some(mem) = caller.data().pyodide_memory {
            let data = mem.data(&caller);
            let tp_base = _tp as u32 as usize;
            let name_ptr: usize = if tp_base + 8 <= data.len() {
                u32::from_le_bytes(data[tp_base + 4..tp_base + 8].try_into().unwrap_or([0; 4]))
                    as usize
            } else {
                0
            };
            if name_ptr != 0 && name_ptr < data.len() {
                let end = data[name_ptr..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|n| name_ptr + n)
                    .unwrap_or(name_ptr);
                String::from_utf8_lossy(&data[name_ptr..end]).into_owned()
            } else {
                format!("<name_ptr=0x{name_ptr:x} out of bounds>")
            }
        } else {
            "<no memory>".to_owned()
        };
        // Increment counter; record up to 64 entries.
        let st = caller.data_mut();
        st.cxa_throw_count += 1;
        let count = st.cxa_throw_count;
        pyo_trace!("[__cxa_throw #{count}] ptr=0x{_ptr:x} tp=0x{_tp:x} name={type_name:?}");
        if st.cxa_throw_log.len() >= 64 {
            st.cxa_throw_log.remove(0);
        }
        st.cxa_throw_log.push((count, type_name));
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
    def!("__resumeException", |caller: Caller<'_, EmbedderState>,
                               _ptr: i32|
     -> WtResult<()> {
        // This is the uncaught-exception path: the exception survived all
        // invoke_ catch boundaries and reached the top-level re-thrower.
        // Log the last __cxa_throw entry as the escaping exception.
        let st = caller.data();
        let last = st.cxa_throw_log.last().cloned();
        let total = st.cxa_throw_count;
        let fs_ctx: Vec<String> = st.fs_path_log.iter().cloned().collect();
        pyo_trace!(
            "[__resumeException] ptr=0x{_ptr:x} total_throws={total} \
             last_throw={last:?} last_fs_paths={fs_ctx:?}"
        );
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

    // ---- libffi (ctypes) + mmap host functions ------------------------------
    //
    // `_mmap_js` / `_munmap_js` / `_msync_js` (i64 offset, not expressible via
    // def_syscall!) and the five `ffi_*` imports share ONE implementation in
    // `emscripten_ffi`. Wiring here keeps this bring-up path (used by the import
    // probes) in sync with the production `pyodide_runner` boot path, which calls
    // `wire_emscripten_ffi` directly. One canonical libffi/mmap host bridge.
    crate::emscripten_ffi::wire_emscripten_ffi(engine, linker)?;

    // ---- time/locale --------------------------------------------------------

    // `_gmtime_js(t, tmPtr)` / `_localtime_js(t, tmPtr)` break a Unix timestamp
    // (seconds since the epoch) into a `struct tm` at `tmPtr`. A no-op leaves the
    // struct uninitialized, so CPython's `time.localtime()` / `datetime.now()`
    // read garbage and raise "month out of range" - which blocks importing every
    // package that touches the clock at import (scikit-learn, statsmodels, ipython,
    // sqlalchemy, ...). The runtime's virtual clock is UTC, so gmtime == localtime;
    // both fill the struct from the same civil-time breakdown.
    def!("_gmtime_js", |mut caller: Caller<'_, EmbedderState>,
                        t: i64,
                        tmptr: i32| {
        civil_time::write_tm(&mut caller, t, tmptr);
    });
    def!("_localtime_js", |mut caller: Caller<'_, EmbedderState>,
                           t: i64,
                           tmptr: i32| {
        civil_time::write_tm(&mut caller, t, tmptr);
    });
    // `_mktime_js(tmPtr)` / `_timegm_js(tmPtr)`: the inverse, returning the Unix
    // timestamp for the `struct tm` at `tmPtr`. UTC-deterministic, so both are the
    // same (no local-zone offset). Returning -1 (the no-op) makes `time.mktime`
    // raise OverflowError; the real value lets it round-trip.
    def!("_mktime_js", |caller: Caller<'_, EmbedderState>,
                        tmptr: i32|
     -> i64 {
        civil_time::read_tm_to_unix(&caller, tmptr)
    });
    def!("_timegm_js", |caller: Caller<'_, EmbedderState>,
                        tmptr: i32|
     -> i64 {
        civil_time::read_tm_to_unix(&caller, tmptr)
    });
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

    // ---- DNS / network functions -------------------------------------------
    //
    // `getaddrinfo`: when `daemon` feature + manifold are available, resolve
    // the hostname via the existing host resolver (`dns_host::lookup`) and
    // write one IPv4 `addrinfo` + `sockaddr_in` result into a fixed scratch
    // page at the top of the guest linear memory (last 512 bytes), which is
    // outside the usable Emscripten heap. Without the feature, or when no
    // manifold is set, return EAI_FAIL (8) so the caller handles it gracefully.
    //
    // `addrinfo` wasm32 layout (total 32 bytes):
    //   [0]  ai_flags    i32
    //   [4]  ai_family   i32 (AF_INET=2)
    //   [8]  ai_socktype i32 (SOCK_STREAM=1)
    //   [12] ai_protocol i32 (IPPROTO_TCP=6)
    //   [16] ai_addrlen  i32 (16)
    //   [20] ai_addr     i32 (pointer to sockaddr_in)
    //   [24] ai_canonname i32 (0 = null)
    //   [28] ai_next     i32 (0 = null)
    //
    // `sockaddr_in` follows immediately at offset 32 (16 bytes).
    // Total scratch: 48 bytes. We write them at `mem_len - 512` and
    // write `mem_len - 512` into `*res`.

    #[cfg(feature = "daemon")]
    wire_getaddrinfo(linker)?;

    #[cfg(not(feature = "daemon"))]
    def!("getaddrinfo", |_: Caller<'_, EmbedderState>,
                         _n: i32,
                         _s: i32,
                         _h: i32,
                         _r: i32|
     -> i32 { 8 }); // EAI_FAIL (no network in sealed mode)

    def!("getnameinfo", |_: Caller<'_, EmbedderState>,
                         _sa: i32,
                         _sl: i32,
                         _h: i32,
                         _hl: i32,
                         _sv: i32,
                         _svl: i32,
                         _f: i32|
     -> i32 { 1 }); // EAI_NONAME - not needed for outbound client use

    def!("getprotobyname", |_: Caller<'_, EmbedderState>,
                            _name: i32|
     -> i32 { 0 }); // null - getprotobyname returning NULL means unknown protocol
    def!("freeaddrinfo", |_: Caller<'_, EmbedderState>,
                          _ai: i32|
     -> i32 {
        // No-op: the addrinfo lives in the wasm scratch page, not on the wasm heap.
        // No guest malloc was called, so no guest free is needed.
        0
    });
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
            // Deterministic fill (0xAB): sealed runs; the fixed fill makes two
            // re-executions of the same source byte-identical (honesty fence).
            //
            // RealOs: live-net runs where TLS needs real cryptographic randomness.
            // The sealed path is BYTE-IDENTICAL to before; only the RealOs branch
            // is new. Both Copy fields are read before the mutable memory borrow.
            let entropy = caller.data().entropy;
            let Some(memory) = caller.data().pyodide_memory else {
                return -1;
            };
            let start = buffer as u32 as usize;
            let len = length as u32 as usize;
            let mem = memory.data_mut(&mut caller);
            if start.checked_add(len).is_some_and(|e| e <= mem.len()) {
                match entropy {
                    crate::embedder_vm::EntropySource::Deterministic => {
                        mem[start..start + len].fill(0xAB);
                    }
                    crate::embedder_vm::EntropySource::RealOs => {
                        // getrandom fills the slice from the OS CSPRNG.
                        // On error return -1 so TLS fails visibly rather than
                        // silently proceeding with uninitialized bytes.
                        let mut tmp = vec![0u8; len];
                        if getrandom::getrandom(&mut tmp).is_err() {
                            return -1;
                        }
                        mem[start..start + len].copy_from_slice(&tmp);
                    }
                }
                0
            } else {
                -1
            }
        });
    }

    // ---- dlopen / dlsym - backed by the pre-loaded SideModuleRegistry ----------
    // Implementations live in emscripten_sidemodule::wire_dlopen_dlsym to keep
    // this file under 1000 lines.
    crate::emscripten_sidemodule::wire_dlopen_dlsym(linker)?;

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

    // ---- libffi JS bridge: wired above via emscripten_ffi -------------------

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

    // ---- pthread / futex surface (Section 4: real threads) ------------------
    //
    // Wire pthread_create / pthread_join / pthread_detach and the
    // emscripten_futex_wait / emscripten_futex_wake shims onto the existing
    // DaemonWorkers + DaemonSab coordinators. Available under the `daemon`
    // feature only; without it the functions are caught by the catch-all
    // no-op stubs installed by fill_unknown_imports_as_noops.
    #[cfg(feature = "daemon")]
    crate::emscripten_pthread::wire_pthread_imports(linker)?;

    // ---- process / pipe surface (Section 5: real multiprocessing) -----------
    //
    // Wire __syscall_pipe / __syscall_pipe2 / __syscall_fork / __syscall_clone /
    // __syscall_waitid / __syscall_wait4 / posix_spawn / posix_spawnp onto
    // DaemonWorkers (spawn + length-prefixed pipe IPC). fork is emulated as
    // spawn + explicit state hand-off (decision D2). Available under the
    // `daemon` feature only.
    #[cfg(feature = "daemon")]
    crate::emscripten_multiprocessing::wire_process_imports(linker)?;

    Ok(())
}

/// Wire the Pyodide 0.28 output-capture and PyCFunction-trampoline helper stubs.
///
/// Must be called BEFORE [`fill_got_table_slots`][crate::emscripten_dylink::fill_got_table_slots]
/// so that Path 3 (linker host export) can place `emscripten_out` and
/// `emscripten_err` into the GOT.func table slots, making `print` and other
/// Python output land in `EmbedderState::wasi_stdout`.
///
/// Also wires the three PyCFunction-trampoline helpers that Pyodide 0.28 imports
/// and that `fill_unknown_imports_as_noops` would otherwise auto-fill with
/// silent zero-returning stubs (no behavioral difference, but explicit is better):
///
/// - `_PyEM_InitTrampoline_js` `() -> ()`: called once during `__wasm_call_ctors`
///   to initialize the trampoline dispatch table. Our host does not need JS-side
///   trampoline setup because `_PyEM_TrampolineCall_JS` is wired directly to
///   `invoke_dispatch` (table dispatch). Safe to no-op.
///
/// - `_PyEM_GetCountArgsPtr` `() -> i32`: returns a guest-memory pointer to the
///   per-function arg-count array used by `_PyEM_TrampolineCall_JS` when Wasm type
///   reflection is unavailable. Returning 0 selects the fallback path (direct
///   `call_indirect` via the table index), which is correct here.
///
/// - `__hiwire_deduplicate_new` `() -> externref`: allocates a new hiwire
///   deduplication map on the JS side, returned as an opaque externref handle.
///   Returning `null externref` is safe: the deduplication map is a JS-side
///   optimization for repeated Python<->JS object round-trips; without it
///   round-trips still work (they just do not share identity).
///
/// `emscripten_out(i32)` and `emscripten_err(i32)` are resolved through the
/// GOT.func mechanism (not direct env.* imports) in Pyodide 0.28. Wiring them
/// here ensures [`fill_got_table_slots`][crate::emscripten_dylink::fill_got_table_slots]
/// Path 3 places the capturing stub into the function table, so CPython's
/// `print` (which routes through `emscripten_out` via GOT dispatch) writes
/// to `EmbedderState::wasi_stdout`.
pub fn wire_pyodide028_env_stubs(
    engine: &Engine,
    linker: &mut Linker<EmbedderState>,
) -> Result<()> {
    linker.allow_shadowing(true);

    macro_rules! def {
        ($name:expr, $func:expr) => {
            linker
                .func_wrap("env", $name, $func)
                .map_err(|e| AfterburnerError::Engine(format!("{}: {e}", $name)))?
        };
    }

    // ---- heap resize / heap max -----------------------------------------------
    //
    // emscripten_resize_heap and emscripten_get_heap_max have pure i32 types
    // (no externref involvement), so they are safe to wire here even for the
    // exnref-translated Pyodide 0.28 binary. They must NOT live in
    // wire_mechanical_env_funcs for the exnref path because that function also
    // wires JS-FFI stubs with the old i32 signatures, which conflict with the
    // externref signatures in the exnref-translated binary.
    //
    // emscripten_resize_heap(requested_size: i32) -> i32
    //   Grows linear memory to at least `requested_size` bytes. Returns 1 on
    //   success, 0 if the grow is refused. Uses EmbedderState::pyodide_memory
    //   because Emscripten modules import (not export) their memory.
    fn emscripten_resize_heap(mut caller: Caller<'_, EmbedderState>, requested: i32) -> i32 {
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
    }
    def!("emscripten_resize_heap", emscripten_resize_heap);
    // emscripten_get_heap_max() -> i32
    //   Returns the maximum byte size the heap may grow to. Used by the
    //   Emscripten allocator to decide whether to attempt a grow.
    fn get_heap_max_stub(_: Caller<'_, EmbedderState>) -> i32 {
        heap_max_bytes()
    }
    def!("emscripten_get_heap_max", get_heap_max_stub);

    // ---- output capture: emscripten_out / emscripten_err ---------------------
    //
    // In Pyodide 0.28 these are imported as GOT.func globals, not as env.*
    // function imports. fill_got_table_slots resolves them via Path 3 (linker
    // host export): it calls linker.get("env", "emscripten_out") and places the
    // returned host func into the pre-assigned GOT.func stub table slot. The GOT
    // global then points to that slot, so every indirect call through GOT.func
    // dispatches to this capturing stub and bytes reach wasi_stdout.
    def!("emscripten_out", |mut caller: Caller<'_, EmbedderState>,
                            ptr: i32| {
        pyo_trace!("[emscripten_out] ptr={ptr:#x}");
        if let Some(s) = read_cstr(&caller, ptr) {
            pyo_trace!("[emscripten_out] text={s:?}");
            let buf = &mut caller.data_mut().wasi_stdout;
            buf.extend_from_slice(s.as_bytes());
            buf.push(b'\n');
        }
    });
    def!("emscripten_err", |mut caller: Caller<'_, EmbedderState>,
                            ptr: i32| {
        pyo_trace!("[emscripten_err] ptr={ptr:#x}");
        if let Some(s) = read_cstr(&caller, ptr) {
            pyo_trace!("[emscripten_err] text={s:?}");
            let buf = &mut caller.data_mut().wasi_stdout;
            buf.extend_from_slice(s.as_bytes());
            buf.push(b'\n');
        }
    });
    // emscripten_console_* may also be called via GOT.func; same capture path.
    def!(
        "emscripten_console_log",
        |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
            pyo_trace!("[emscripten_console_log] ptr={ptr:#x}");
            if let Some(s) = read_cstr(&caller, ptr) {
                pyo_trace!("[emscripten_console_log] text={s:?}");
                let buf = &mut caller.data_mut().wasi_stdout;
                buf.extend_from_slice(s.as_bytes());
                buf.push(b'\n');
            }
        }
    );
    def!(
        "emscripten_console_warn",
        |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
            if let Some(s) = read_cstr(&caller, ptr) {
                let buf = &mut caller.data_mut().wasi_stdout;
                buf.extend_from_slice(s.as_bytes());
                buf.push(b'\n');
            }
        }
    );
    def!(
        "emscripten_console_error",
        |mut caller: Caller<'_, EmbedderState>, ptr: i32| {
            if let Some(s) = read_cstr(&caller, ptr) {
                let buf = &mut caller.data_mut().wasi_stdout;
                buf.extend_from_slice(s.as_bytes());
                buf.push(b'\n');
            }
        }
    );

    // ---- _PyEM_InitTrampoline_js: () -> () -----------------------------------
    //
    // Called once during __wasm_call_ctors to initialize the PyCFunction
    // trampoline dispatch table on the JS side. We use invoke_dispatch directly
    // for _PyEM_TrampolineCall_JS so no JS-side init is needed.
    def!("_PyEM_InitTrampoline_js", |_: Caller<'_, EmbedderState>| {});

    // ---- _PyEM_GetCountArgsPtr: () -> i32 ------------------------------------
    //
    // Returns a guest-memory pointer to the per-function arg-count array.
    // Returning 0 (null) selects the fallback path in the generated
    // _PyEM_TrampolineCall_JS wrapper: it calls the external trampoline
    // (our invoke_dispatch) directly, which is correct.
    def!(
        "_PyEM_GetCountArgsPtr",
        |_: Caller<'_, EmbedderState>| -> i32 { 0 }
    );

    // ---- time / clock --------------------------------------------------------
    //
    // The exnref Pyodide path does not go through wire_mechanical_env_funcs, so
    // these would otherwise fall to the noop fill and leave the `struct tm`
    // uninitialized: CPython's time.localtime() / datetime.now() then read garbage
    // and raise "month out of range", blocking the import of every package that
    // touches the clock at import (scikit-learn, statsmodels, ipython, sqlalchemy,
    // ...). Wire them to the real, deterministic civil-time breakdown. All times
    // are the virtual UTC epoch, so gmtime == localtime and there is no zone
    // offset. (i32/i64/f64 only, so no externref-signature conflict on this path.)
    def!(
        "emscripten_date_now",
        |_: Caller<'_, EmbedderState>| -> f64 { crate::emscripten_abi::VIRTUAL_EPOCH_MS }
    );
    def!("_gmtime_js", |mut caller: Caller<'_, EmbedderState>,
                        t: i64,
                        tmptr: i32| {
        civil_time::write_tm(&mut caller, t, tmptr);
    });
    def!("_localtime_js", |mut caller: Caller<'_, EmbedderState>,
                           t: i64,
                           tmptr: i32| {
        civil_time::write_tm(&mut caller, t, tmptr);
    });
    def!("_mktime_js", |caller: Caller<'_, EmbedderState>,
                        tmptr: i32|
     -> i64 {
        civil_time::read_tm_to_unix(&caller, tmptr)
    });
    def!("_timegm_js", |caller: Caller<'_, EmbedderState>,
                        tmptr: i32|
     -> i64 {
        civil_time::read_tm_to_unix(&caller, tmptr)
    });
    // tzset writes the four libc zone globals (timezone, daylight, tzname[0/1]).
    // UTC with no DST: timezone=0, daylight=0, both names "UTC". The args are the
    // out-pointers Emscripten passes for those globals.
    def!("_tzset_js", |mut caller: Caller<'_, EmbedderState>,
                       timezone_ptr: i32,
                       daylight_ptr: i32,
                       std_name_ptr: i32,
                       dst_name_ptr: i32| {
        civil_time::write_tzset(
            &mut caller,
            timezone_ptr,
            daylight_ptr,
            std_name_ptr,
            dst_name_ptr,
        );
    });

    // ---- __hiwire_deduplicate_new: () -> externref ---------------------------
    //
    // Allocates a new JS-side hiwire deduplication map. With no JS runtime,
    // returning null externref disables the dedup optimization; hiwire handles
    // remain functional, just without object-identity sharing between calls.
    // Must be registered via func_new because func_wrap cannot express
    // externref return types.
    {
        let ft = FuncType::new(engine, [], [ValType::EXTERNREF]);
        linker
            .func_new("env", "__hiwire_deduplicate_new", ft, |_, _, results| {
                results[0] = Val::ExternRef(None);
                Ok(())
            })
            .map_err(|e| AfterburnerError::Engine(format!("__hiwire_deduplicate_new: {e}")))?;
    }

    Ok(())
}

/// Wire a real `getaddrinfo` that resolves via the host DNS resolver.
/// Only compiled when the `daemon` feature is active.
///
/// Writes one IPv4 `addrinfo` + `sockaddr_in` into a fixed 512-byte scratch
/// page at the TOP of the guest linear memory (last 512 bytes). This region
/// is outside the Emscripten heap (`__heap_base` + dynamic allocations are
/// well below the memory limit), so writing there is safe as long as the
/// guest memory is at least 512 bytes (it is always multiple MB).
///
/// `addrinfo` wasm32 layout (32 bytes):
///   [0]  ai_flags     i32 = 0
///   [4]  ai_family    i32 = AF_INET (2)
///   [8]  ai_socktype  i32 = SOCK_STREAM (1)
///   [12] ai_protocol  i32 = IPPROTO_TCP (6)
///   [16] ai_addrlen   i32 = 16
///   [20] ai_addr      i32 = pointer to sockaddr_in below
///   [24] ai_canonname i32 = 0 (null)
///   [28] ai_next      i32 = 0 (null)
/// `sockaddr_in` follows at offset +32 (16 bytes).
#[cfg(feature = "daemon")]
fn wire_getaddrinfo(linker: &mut Linker<EmbedderState>) -> Result<()> {
    linker
        .func_wrap(
            "env",
            "getaddrinfo",
            |mut caller: Caller<'_, EmbedderState>,
             node: i32,
             _service: i32,
             _hints: i32,
             res: i32|
             -> i32 {
                const EAI_FAIL: i32 = 8;
                let manifold = match caller.data().manifold.clone() {
                    Some(m) => m,
                    None => return EAI_FAIL,
                };
                let mem_handle = match caller.data().pyodide_memory {
                    Some(m) => m,
                    None => return EAI_FAIL,
                };
                let hostname: String = {
                    let mem = mem_handle.data(&caller);
                    let ptr = node as u32 as usize;
                    if ptr >= mem.len() {
                        return EAI_FAIL;
                    }
                    let end = mem[ptr..].iter().position(|&b| b == 0).unwrap_or(255);
                    match std::str::from_utf8(&mem[ptr..ptr + end]) {
                        Ok(s) => s.to_string(),
                        Err(_) => return EAI_FAIL,
                    }
                };
                if hostname.is_empty() {
                    return EAI_FAIL;
                }
                let ip = match afterburner_node_compat::dns_host::lookup(&hostname, &manifold) {
                    Ok(ip) => ip,
                    Err(_) => return EAI_FAIL,
                };
                let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
                if parts.len() != 4 {
                    return EAI_FAIL;
                }
                let mem = mem_handle.data_mut(&mut caller);
                let mem_len = mem.len();
                if mem_len < 512 {
                    return EAI_FAIL;
                }
                let ai_off = mem_len - 512;
                let sa_off = ai_off + 32;
                let sa_ptr = sa_off as i32;
                // addrinfo:
                mem[ai_off..ai_off + 4].copy_from_slice(&0i32.to_le_bytes()); // ai_flags
                mem[ai_off + 4..ai_off + 8].copy_from_slice(&2i32.to_le_bytes()); // ai_family
                mem[ai_off + 8..ai_off + 12].copy_from_slice(&1i32.to_le_bytes()); // ai_socktype
                mem[ai_off + 12..ai_off + 16].copy_from_slice(&6i32.to_le_bytes()); // ai_protocol
                mem[ai_off + 16..ai_off + 20].copy_from_slice(&16i32.to_le_bytes()); // ai_addrlen
                mem[ai_off + 20..ai_off + 24].copy_from_slice(&sa_ptr.to_le_bytes()); // ai_addr
                mem[ai_off + 24..ai_off + 28].copy_from_slice(&0i32.to_le_bytes()); // ai_canonname
                mem[ai_off + 28..ai_off + 32].copy_from_slice(&0i32.to_le_bytes()); // ai_next
                // sockaddr_in:
                let family: u16 = 2;
                mem[sa_off..sa_off + 2].copy_from_slice(&family.to_le_bytes());
                mem[sa_off + 2..sa_off + 4].copy_from_slice(&0u16.to_be_bytes());
                mem[sa_off + 4] = parts[0];
                mem[sa_off + 5] = parts[1];
                mem[sa_off + 6] = parts[2];
                mem[sa_off + 7] = parts[3];
                for i in 8..16 {
                    mem[sa_off + i] = 0;
                }
                // Write *res = &addrinfo:
                let ai_ptr = ai_off as i32;
                let res_ptr = res as u32 as usize;
                if res_ptr + 4 <= mem.len() {
                    mem[res_ptr..res_ptr + 4].copy_from_slice(&ai_ptr.to_le_bytes());
                }
                0
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("getaddrinfo: {e}")))?;
    Ok(())
}

#[cfg(test)]
#[path = "emscripten_mechanical/tests.rs"]
mod tests;
