// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Custom `wasi_snapshot_preview1` host functions for Emscripten-compiled
//! modules (e.g. `pyodide.asm.wasm`).
//!
//! ## Why not wasmtime-wasi preview-1?
//!
//! The standard `wasmtime_wasi::p1::add_to_linker_sync` implementation
//! accesses guest memory via `caller.get_export("memory")`. Emscripten modules
//! IMPORT their linear memory as `env.memory` and do NOT export it, so the
//! standard accessor fails with "missing required memory export" at the first
//! WASI call.
//!
//! These shims read and write guest memory via
//! `caller.data().pyodide_memory`, which is set to the `env.memory` handle
//! after `wire_env_memory_and_table_in_store` creates and registers it.
//!
//! ## What is implemented
//!
//! Only what CPython static init (`__wasm_call_ctors`) actually calls:
//!
//! - `environ_sizes_get` / `environ_get` - empty environment (0 vars).
//! - `fd_write` - iovec-based write to fd 1/2; bytes appended to
//!   `EmbedderState::wasi_stdout`.
//! - `fd_read` / `fd_pread` - return 0 bytes read (stdin is empty).
//! - `fd_seek` / `fd_close` / `fd_fdstat_get` / `fd_pwrite` - minimal
//!   valid returns (0 / EBADF as appropriate).
//! - `clock_time_get` - deterministic constant (virtual epoch).
//! - `proc_exit` - traps with an exit-coded error.
//! - `args_sizes_get` / `args_get` - no arguments.
//! - `fd_prestat_get` - EBADF (no preopened dirs).
//!
//! ## Determinism
//!
//! All functions are deterministic: no real clock, no real I/O, no locks
//! on the hot path (the write to `wasi_stdout` is via `&mut` through
//! `Caller::data_mut`, which is single-threaded wasmtime execution).

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Linker};

use crate::{embedder_vm::EmbedderState, emscripten_abi::VIRTUAL_EPOCH_NS};

// ---- WASI errno constants (wasi_snapshot_preview1 values) -------------------

/// WASI errno: bad file descriptor.
const EBADF: i32 = 8;

// ---- memory helper ----------------------------------------------------------

/// Read `len` bytes from guest linear memory at `ptr` (u32 address space).
/// Returns `None` when the memory handle is absent or the range is out of bounds.
fn read_bytes(caller: &Caller<'_, EmbedderState>, ptr: i32, len: usize) -> Option<Vec<u8>> {
    let mem = caller.data().pyodide_memory?;
    let data = mem.data(caller);
    let start = ptr as u32 as usize;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(data[start..end].to_vec())
}

/// Write `bytes` into guest linear memory at `ptr` (u32 address space).
/// Returns `false` when the memory handle is absent or the range is out of bounds.
fn write_bytes(caller: &mut Caller<'_, EmbedderState>, ptr: i32, bytes: &[u8]) -> bool {
    let mem = match caller.data().pyodide_memory {
        Some(m) => m,
        None => return false,
    };
    let data = mem.data_mut(caller);
    let start = ptr as u32 as usize;
    let end = match start.checked_add(bytes.len()) {
        Some(e) => e,
        None => return false,
    };
    if end > data.len() {
        return false;
    }
    data[start..end].copy_from_slice(bytes);
    true
}

/// Write a little-endian u32 into guest linear memory at `ptr`.
fn write_u32(caller: &mut Caller<'_, EmbedderState>, ptr: i32, val: u32) -> bool {
    write_bytes(caller, ptr, &val.to_le_bytes())
}

/// Write a little-endian u64 into guest linear memory at `ptr`.
fn write_u64(caller: &mut Caller<'_, EmbedderState>, ptr: i32, val: u64) -> bool {
    write_bytes(caller, ptr, &val.to_le_bytes())
}

// ---- register all shims -----------------------------------------------------

/// Wire all `wasi_snapshot_preview1.*` functions into `linker`.
///
/// Must be called before instantiating an Emscripten module. The store data
/// type must be [`EmbedderState`]; the caller is responsible for setting
/// `store.data_mut().pyodide_memory = Some(mem)` after creating the memory
/// with `wire_env_memory_and_table_in_store`.
pub(crate) fn wire_wasi_snapshot_preview1(linker: &mut Linker<EmbedderState>) -> Result<()> {
    // def!: register a typed closure under wasi_snapshot_preview1.
    macro_rules! def {
        ($name:expr, $func:expr) => {
            linker
                .func_wrap("wasi_snapshot_preview1", $name, $func)
                .map_err(|e| {
                    AfterburnerError::Engine(format!("wasi_snapshot_preview1::{}: {e}", $name))
                })?
        };
    }

    // ---- environ ------------------------------------------------------------

    // environ_sizes_get(count_ptr: i32, buf_size_ptr: i32) -> i32
    // Empty environment: write 0 count + 0 buf size, return 0 (success).
    def!("environ_sizes_get", |mut caller: Caller<
        '_,
        EmbedderState,
    >,
                               count_ptr: i32,
                               buf_size_ptr: i32|
     -> i32 {
        if !write_u32(&mut caller, count_ptr, 0) {
            return 1;
        }
        if !write_u32(&mut caller, buf_size_ptr, 0) {
            return 1;
        }
        0
    });

    // environ_get(environ_ptr: i32, buf_ptr: i32) -> i32
    // No environment vars - nothing to write.
    def!("environ_get", |_: Caller<'_, EmbedderState>,
                         _environ_ptr: i32,
                         _buf_ptr: i32|
     -> i32 { 0 });

    // ---- args ---------------------------------------------------------------

    // args_sizes_get(argc_ptr: i32, argv_buf_size_ptr: i32) -> i32
    def!("args_sizes_get", |mut caller: Caller<'_, EmbedderState>,
                            argc_ptr: i32,
                            argv_buf_size_ptr: i32|
     -> i32 {
        if !write_u32(&mut caller, argc_ptr, 0) {
            return 1;
        }
        if !write_u32(&mut caller, argv_buf_size_ptr, 0) {
            return 1;
        }
        0
    });

    // args_get(argv_ptr: i32, buf_ptr: i32) -> i32
    def!("args_get", |_: Caller<'_, EmbedderState>,
                      _argv_ptr: i32,
                      _buf_ptr: i32|
     -> i32 { 0 });

    // ---- fd_write -----------------------------------------------------------

    // fd_write(fd: i32, iovs_ptr: i32, iovs_len: i32, nwritten_ptr: i32) -> i32
    //
    // Iovec layout (wasi_snapshot_preview1, little-endian):
    //   offset +0: u32 buf_ptr
    //   offset +4: u32 buf_len
    // Each iovec is 8 bytes. For fd 1/2, bytes are appended to wasi_stdout.
    def!("fd_write", |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      iovs_ptr: i32,
                      iovs_len: i32,
                      nwritten_ptr: i32|
     -> i32 {
        let iovs_len = iovs_len as u32 as usize;
        // Read the entire iovec array (8 bytes * iovs_len).
        let iov_bytes = match read_bytes(&caller, iovs_ptr, iovs_len * 8) {
            Some(b) => b,
            None => return EBADF,
        };
        let mut total: u32 = 0;
        for i in 0..iovs_len {
            let base = i * 8;
            let buf_ptr = u32::from_le_bytes(iov_bytes[base..base + 4].try_into().unwrap()) as i32;
            let buf_len =
                u32::from_le_bytes(iov_bytes[base + 4..base + 8].try_into().unwrap()) as usize;
            if buf_len == 0 {
                continue;
            }
            let chunk = match read_bytes(&caller, buf_ptr, buf_len) {
                Some(c) => c,
                None => return EBADF,
            };
            if fd == 1 || fd == 2 {
                caller.data_mut().wasi_stdout.extend_from_slice(&chunk);
            }
            total += buf_len as u32;
        }
        if !write_u32(&mut caller, nwritten_ptr, total) {
            return EBADF;
        }
        0
    });

    // ---- fd_read ------------------------------------------------------------

    // fd_read(fd: i32, iovs_ptr: i32, iovs_len: i32, nread_ptr: i32) -> i32
    // Stdin is empty - write 0 bytes read and return 0.
    def!("fd_read", |mut caller: Caller<'_, EmbedderState>,
                     _fd: i32,
                     _iovs_ptr: i32,
                     _iovs_len: i32,
                     nread_ptr: i32|
     -> i32 {
        if !write_u32(&mut caller, nread_ptr, 0) {
            return EBADF;
        }
        0
    });

    // fd_pread(fd, iovs_ptr, iovs_len, offset, nread_ptr) -> i32
    def!("fd_pread", |mut caller: Caller<'_, EmbedderState>,
                      _fd: i32,
                      _iovs_ptr: i32,
                      _iovs_len: i32,
                      _offset: i64,
                      nread_ptr: i32|
     -> i32 {
        if !write_u32(&mut caller, nread_ptr, 0) {
            return EBADF;
        }
        0
    });

    // fd_pwrite(fd, iovs_ptr, iovs_len, offset, nwritten_ptr) -> i32
    def!("fd_pwrite", |mut caller: Caller<'_, EmbedderState>,
                       _fd: i32,
                       _iovs_ptr: i32,
                       _iovs_len: i32,
                       _offset: i64,
                       nwritten_ptr: i32|
     -> i32 {
        if !write_u32(&mut caller, nwritten_ptr, 0) {
            return EBADF;
        }
        0
    });

    // ---- fd_seek / fd_close / fd_fdstat_get ---------------------------------

    // fd_seek(fd, offset, whence, newoffset_ptr) -> i32
    def!("fd_seek", |mut caller: Caller<'_, EmbedderState>,
                     _fd: i32,
                     _offset: i64,
                     _whence: i32,
                     newoffset_ptr: i32|
     -> i32 {
        if !write_u64(&mut caller, newoffset_ptr, 0) {
            return EBADF;
        }
        0
    });

    // fd_close(fd) -> i32
    def!("fd_close", |_: Caller<'_, EmbedderState>,
                      _fd: i32|
     -> i32 { 0 });

    // fd_fdstat_get(fd, stat_ptr) -> i32
    // Write a zeroed fdstat (24 bytes) so callers see a valid struct.
    def!("fd_fdstat_get", |mut caller: Caller<'_, EmbedderState>,
                           _fd: i32,
                           stat_ptr: i32|
     -> i32 {
        // wasi fdstat is 24 bytes; zero-fill for a minimal valid response.
        let zeros = [0u8; 24];
        if !write_bytes(&mut caller, stat_ptr, &zeros) {
            return EBADF;
        }
        0
    });

    // fd_prestat_get(fd, buf_ptr) -> i32
    // No preopened directories - return EBADF so callers stop iterating.
    def!("fd_prestat_get", |_: Caller<'_, EmbedderState>,
                            _fd: i32,
                            _buf_ptr: i32|
     -> i32 { EBADF });

    // fd_fdstat_set_flags(fd, flags) -> i32
    def!("fd_fdstat_set_flags", |_: Caller<'_, EmbedderState>,
                                 _fd: i32,
                                 _flags: i32|
     -> i32 { 0 });

    // fd_sync(fd) -> i32
    def!("fd_sync", |_: Caller<'_, EmbedderState>, _fd: i32| -> i32 {
        0
    });

    // ---- clock_time_get -----------------------------------------------------

    // clock_time_get(id, precision, time_ptr) -> i32
    // Return a deterministic constant (virtual epoch) in nanoseconds.
    def!("clock_time_get", |mut caller: Caller<'_, EmbedderState>,
                            _id: i32,
                            _precision: i64,
                            time_ptr: i32|
     -> i32 {
        if !write_u64(&mut caller, time_ptr, VIRTUAL_EPOCH_NS) {
            return 1;
        }
        0
    });

    // clock_res_get(id, resolution_ptr) -> i32
    def!("clock_res_get", |mut caller: Caller<'_, EmbedderState>,
                           _id: i32,
                           resolution_ptr: i32|
     -> i32 {
        // 1 ns resolution (deterministic; any positive value is valid).
        if !write_u64(&mut caller, resolution_ptr, 1) {
            return 1;
        }
        0
    });

    // ---- proc_exit ----------------------------------------------------------

    // proc_exit(code: i32) -> !
    // Trap with a structured error so the caller can extract the exit code.
    def!("proc_exit", |_: Caller<'_, EmbedderState>,
                       code: i32|
     -> wasmtime::Result<()> {
        Err(wasmtime::Error::msg(format!("proc_exit({code})")))
    });

    // ---- sched_yield ---------------------------------------------------------

    def!("sched_yield", |_: Caller<'_, EmbedderState>| -> i32 { 0 });

    // ---- poll_oneoff ---------------------------------------------------------

    // poll_oneoff(in_ptr, out_ptr, nsubscriptions, nevents_ptr) -> i32
    // No events ready - write 0 events.
    def!("poll_oneoff", |mut caller: Caller<'_, EmbedderState>,
                         _in_ptr: i32,
                         _out_ptr: i32,
                         _nsubscriptions: i32,
                         nevents_ptr: i32|
     -> i32 {
        if !write_u32(&mut caller, nevents_ptr, 0) {
            return 1;
        }
        0
    });

    Ok(())
}
