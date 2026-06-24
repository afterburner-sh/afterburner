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
//! - `fd_read` - for fds 0/1/2 returns 0 (EOF/stdin empty); for MEMFS fds
//!   reads via iovec from `EmbedderState::fs` and advances the fd offset.
//! - `fd_pread` - positional read from MEMFS fds without advancing offset.
//! - `fd_seek` - for MEMFS fds: seek via `InMemFs::lseek`; for 0/1/2: no-op.
//! - `fd_close` - for MEMFS fds: closes via `InMemFs::close`.
//! - `fd_fdstat_get` - returns regular-file fdstat for MEMFS fds; zero-fill
//!   for 0/1/2 (character device type is acceptable for those).
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

use crate::{embedder_vm::EmbedderState, emscripten_abi::VIRTUAL_EPOCH_NS, pyo_trace};

#[cfg(test)]
mod tests;

// ---- WASI errno constants (wasi_snapshot_preview1 values) -------------------
//
// WASI errno values are POSITIVE integers (unlike Linux -errno).
// These match the wasi_snapshot_preview1 specification.

/// WASI errno: bad file descriptor.
const EBADF: i32 = 8;
/// WASI errno: invalid argument.
const EINVAL: i32 = 28;

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
    // Returns one env var: PYTHONUNBUFFERED=1.
    // This forces CPython to use unbuffered stdout (no buffering layer between
    // print() and the underlying write syscall), ensuring output reaches fd_write
    // even if Python's stdout buffering would otherwise hold bytes in the buffer.
    def!("environ_sizes_get", |mut caller: Caller<
        '_,
        EmbedderState,
    >,
                               count_ptr: i32,
                               buf_size_ptr: i32|
     -> i32 {
        // "PYTHONUNBUFFERED=1\0" = 20 bytes
        pyo_trace!("[environ_sizes_get] returning 1 var, 20 bytes (PYTHONUNBUFFERED=1)");
        if !write_u32(&mut caller, count_ptr, 1) {
            return 1;
        }
        if !write_u32(&mut caller, buf_size_ptr, 20) {
            return 1;
        }
        0
    });

    // environ_get(environ_ptr: i32, buf_ptr: i32) -> i32
    // Write PYTHONUNBUFFERED=1 into the environ buffer.
    // environ_ptr: pointer to char* array (one entry: pointer to the env string).
    // buf_ptr: pointer to the string storage ("PYTHONUNBUFFERED=1\0").
    def!("environ_get", |mut caller: Caller<'_, EmbedderState>,
                         environ_ptr: i32,
                         buf_ptr: i32|
     -> i32 {
        pyo_trace!("[environ_get] writing PYTHONUNBUFFERED=1 at buf_ptr={buf_ptr:#x}");
        // Write the env string "PYTHONUNBUFFERED=1\0" at buf_ptr.
        let env_str = b"PYTHONUNBUFFERED=1\0";
        if !write_bytes(&mut caller, buf_ptr, env_str) {
            return 1;
        }
        // Write the pointer to the env string at environ_ptr.
        if !write_u32(&mut caller, environ_ptr, buf_ptr as u32) {
            return 1;
        }
        0
    });

    // ---- args ---------------------------------------------------------------

    // args_sizes_get(argc_ptr: i32, argv_buf_size_ptr: i32) -> i32
    def!("args_sizes_get", |mut caller: Caller<'_, EmbedderState>,
                            argc_ptr: i32,
                            argv_buf_size_ptr: i32|
     -> i32 {
        pyo_trace!("[args_sizes_get] called - returning 0 args");
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
     -> i32 {
        pyo_trace!("[args_get] called");
        0
    });

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
        pyo_trace!(
            "[fd_write] fd={fd} iovs_ptr={iovs_ptr:#x} iovs_len={iovs_len} nwritten_ptr={nwritten_ptr:#x} mem={}",
            caller.data().pyodide_memory.is_some()
        );
        let iovs_len = iovs_len as u32 as usize;
        // Read the entire iovec array (8 bytes * iovs_len).
        let iov_bytes = match read_bytes(&caller, iovs_ptr, iovs_len * 8) {
            Some(b) => b,
            None => {
                pyo_trace!("[fd_write] EBADF on iov_bytes read");
                return EBADF;
            }
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
            pyo_trace!("[fd_write] fd={fd} iov[{i}] buf_ptr={buf_ptr:#x} buf_len={buf_len}");
            if fd == 1 || fd == 2 {
                caller.data_mut().wasi_stdout.extend_from_slice(&chunk);
            } else if caller.data().fs.is_fs_fd(fd) {
                // Write to the MEMFS file opened by __syscall_openat.
                // This path is used by Python's os.write() for non-stdout fds.
                let n = caller.data_mut().fs.write(fd, &chunk);
                if n < 0 {
                    return -n; // WASI error codes are positive
                }
            }
            total += buf_len as u32;
        }
        pyo_trace!("[fd_write] fd={fd} total_bytes={total}");
        if !write_u32(&mut caller, nwritten_ptr, total) {
            return EBADF;
        }
        0
    });

    // ---- fd_read ------------------------------------------------------------

    // fd_read(fd: i32, iovs_ptr: i32, iovs_len: i32, nread_ptr: i32) -> i32
    //
    // For fds 0/1/2: stdin is empty (EOF), return 0 bytes read.
    // For MEMFS fds (>=3): scatter-read via iovecs from EmbedderState::fs,
    // advancing the fd offset after each iovec.
    def!("fd_read", |mut caller: Caller<'_, EmbedderState>,
                     fd: i32,
                     iovs_ptr: i32,
                     iovs_len: i32,
                     nread_ptr: i32|
     -> i32 {
        // stdin/stdout/stderr: return EOF (0 bytes).
        if fd < 3 {
            if !write_u32(&mut caller, nread_ptr, 0) {
                return EBADF;
            }
            return 0;
        }
        if !caller.data().fs.is_fs_fd(fd) {
            return EBADF;
        }
        let iovs_len = iovs_len as u32 as usize;
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
            // Read into a host-side temp buffer, then copy into guest memory.
            let mut tmp = vec![0u8; buf_len];
            let n = caller.data_mut().fs.read(fd, &mut tmp);
            if n < 0 {
                // Translate negative errno to WASI positive errno.
                return EBADF;
            }
            if n == 0 {
                break; // EOF
            }
            if !write_bytes(&mut caller, buf_ptr, &tmp[..n as usize]) {
                return EBADF;
            }
            total += n as u32;
        }
        if !write_u32(&mut caller, nread_ptr, total) {
            return EBADF;
        }
        0
    });

    // fd_pread(fd, iovs_ptr, iovs_len, offset, nread_ptr) -> i32
    //
    // Positional read: read at `offset` without advancing the fd offset.
    // For fds 0/1/2: return 0 bytes (no stdin data).
    def!("fd_pread", |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      iovs_ptr: i32,
                      iovs_len: i32,
                      offset: i64,
                      nread_ptr: i32|
     -> i32 {
        if fd < 3 {
            if !write_u32(&mut caller, nread_ptr, 0) {
                return EBADF;
            }
            return 0;
        }
        if !caller.data().fs.is_fs_fd(fd) {
            return EBADF;
        }
        let iovs_len = iovs_len as u32 as usize;
        let iov_bytes = match read_bytes(&caller, iovs_ptr, iovs_len * 8) {
            Some(b) => b,
            None => return EBADF,
        };
        let mut total: u32 = 0;
        let mut cur_offset = offset as u64;
        for i in 0..iovs_len {
            let base = i * 8;
            let buf_ptr = u32::from_le_bytes(iov_bytes[base..base + 4].try_into().unwrap()) as i32;
            let buf_len =
                u32::from_le_bytes(iov_bytes[base + 4..base + 8].try_into().unwrap()) as usize;
            if buf_len == 0 {
                continue;
            }
            let mut tmp = vec![0u8; buf_len];
            let n = caller.data_mut().fs.pread(fd, &mut tmp, cur_offset);
            if n < 0 {
                return EBADF;
            }
            if n == 0 {
                break;
            }
            if !write_bytes(&mut caller, buf_ptr, &tmp[..n as usize]) {
                return EBADF;
            }
            total += n as u32;
            cur_offset += n as u64;
        }
        if !write_u32(&mut caller, nread_ptr, total) {
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
        pyo_trace!("[fd_pwrite] fd={_fd} iovs_len={_iovs_len} offset={_offset}");
        if !write_u32(&mut caller, nwritten_ptr, 0) {
            return EBADF;
        }
        0
    });

    // ---- fd_seek / fd_close / fd_fdstat_get ---------------------------------

    // fd_seek(fd, offset, whence, newoffset_ptr) -> i32
    //
    // For MEMFS fds: delegate to InMemFs::lseek, write new offset.
    // For 0/1/2: stdin/stdout/stderr at position 0; whence SET/CUR/END all map
    // to 0 so callers that seek to tell() still see a consistent 0.
    def!("fd_seek", |mut caller: Caller<'_, EmbedderState>,
                     fd: i32,
                     offset: i64,
                     whence: i32,
                     newoffset_ptr: i32|
     -> i32 {
        let new_off: i64 = if fd >= 3 && caller.data().fs.is_fs_fd(fd) {
            let r = caller.data_mut().fs.lseek(fd, offset, whence);
            if r < 0 {
                // Translate to WASI EINVAL for invalid argument errors.
                return EINVAL;
            }
            r
        } else if fd < 3 {
            0i64
        } else {
            return EBADF;
        };
        if !write_u64(&mut caller, newoffset_ptr, new_off as u64) {
            return EBADF;
        }
        0
    });

    // fd_close(fd) -> i32
    //
    // For MEMFS fds: close via InMemFs. For 0/1/2: no-op (success).
    def!("fd_close", |mut caller: Caller<'_, EmbedderState>,
                      fd: i32|
     -> i32 {
        if fd >= 3 {
            let rc = caller.data_mut().fs.close(fd);
            if rc < 0 {
                return EBADF;
            }
        }
        0
    });

    // fd_fdstat_get(fd, stat_ptr) -> i32
    //
    // WASI fdstat layout (24 bytes):
    //   offset 0  u8  fs_filetype (0=unknown, 1=block, 2=char, 3=dir, 4=regular, 5=socket_dgram, 6=socket_stream, 7=symbolic_link)
    //   offset 1  u8  padding
    //   offset 2  u16 fs_flags
    //   offset 4  u32 padding
    //   offset 8  u64 fs_rights_base
    //   offset 16 u64 fs_rights_inheriting
    //
    // For MEMFS fds: return filetype=4 (regular file) with no flags and all rights.
    // For 0/1/2: return filetype=2 (character device) - acceptable for stdio.
    def!("fd_fdstat_get", |mut caller: Caller<'_, EmbedderState>,
                           fd: i32,
                           stat_ptr: i32|
     -> i32 {
        let filetype: u8 = if fd >= 3 {
            if !caller.data().fs.is_fs_fd(fd) {
                return EBADF;
            }
            4 // regular file
        } else {
            2 // character device (stdio)
        };
        let mut buf = [0u8; 24];
        buf[0] = filetype;
        // fs_rights_base and fs_rights_inheriting: all bits set (no restrictions).
        buf[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        buf[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        if !write_bytes(&mut caller, stat_ptr, &buf) {
            return EBADF;
        }
        0
    });

    // fd_prestat_get(fd, buf_ptr) -> i32
    //
    // Returns a preopened-directory descriptor for fd 3 (root "/").
    // For any fd > 3 (or one that is not a preopen) returns EBADF so the
    // guest stops iterating preopens.
    //
    // WASI prestat layout (8 bytes):
    //   offset 0  u8  tag: 0 = preopen_dir
    //   offset 1  u8  padding[3]
    //   offset 4  u32 pr_name_len (length of the dir name, without NUL)
    def!("fd_prestat_get", |mut caller: Caller<'_, EmbedderState>,
                            fd: i32,
                            buf_ptr: i32|
     -> i32 {
        match caller.data().fs.preopen_name(fd) {
            None => EBADF,
            Some(name) => {
                let name_len = name.len() as u32;
                let mut buf = [0u8; 8];
                // tag = 0 (preopen_dir), 3 bytes padding
                buf[0] = 0;
                // pr_name_len at offset 4
                buf[4..8].copy_from_slice(&name_len.to_le_bytes());
                if !write_bytes(&mut caller, buf_ptr, &buf) {
                    return EBADF;
                }
                0
            }
        }
    });

    // fd_prestat_dir_name(fd, path_ptr, path_len) -> i32
    //
    // Write the preopened directory name into guest memory at path_ptr.
    // Called after fd_prestat_get to get the actual name string.
    def!("fd_prestat_dir_name", |mut caller: Caller<
        '_,
        EmbedderState,
    >,
                                 fd: i32,
                                 path_ptr: i32,
                                 path_len: i32|
     -> i32 {
        let name = match caller.data().fs.preopen_name(fd) {
            None => return EBADF,
            Some(n) => n.to_owned(),
        };
        let len = name.len().min(path_len as u32 as usize);
        if !write_bytes(&mut caller, path_ptr, &name.as_bytes()[..len]) {
            return EBADF;
        }
        0
    });

    // path_open(dirfd, dirflags, path_ptr, path_len, oflags, fs_rights_base,
    //           fs_rights_inheriting, fdflags, opened_fd_ptr) -> i32
    //
    // Open a path relative to preopened dir `dirfd` (fd 3 = "/").
    // Returns 0 on success with the new fd written to opened_fd_ptr.
    // Returns EBADF/ENOENT on failure.
    //
    // WASI oflags bits:
    //   bit 0 = O_CREAT (create if absent)
    //   bit 1 = O_DIRECTORY (must be dir)
    //   bit 2 = O_EXCL (exclusive create)
    //   bit 3 = O_TRUNC (truncate on open)
    //
    // WASI fs_rights_base: bit 6 = FD_WRITE. If set, translate to O_WRONLY.
    def!("path_open", |mut caller: Caller<'_, EmbedderState>,
                       dirfd: i32,
                       _dirflags: i32,
                       path_ptr: i32,
                       path_len: i32,
                       oflags: i32,
                       fs_rights_base: i64,
                       _fs_rights_inheriting: i64,
                       _fdflags: i32,
                       opened_fd_ptr: i32|
     -> i32 {
        // Read the path bytes from guest memory.
        let len = path_len as u32 as usize;
        let path_bytes = match read_bytes(&caller, path_ptr, len) {
            Some(b) => b,
            None => return EBADF,
        };
        let path_str = match std::str::from_utf8(&path_bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => return EBADF,
        };
        // Resolve relative to the base dir (dirfd 3 = "/").
        let base = match caller.data().fs.preopen_name(dirfd) {
            Some(b) => b.to_owned(),
            None => {
                if caller.data().fs.is_fs_fd(dirfd) {
                    // Opened regular dir fd - get its path.
                    match caller.data().fs.fd_path(dirfd) {
                        Some(p) => p.to_owned(),
                        None => return EBADF,
                    }
                } else {
                    return EBADF;
                }
            }
        };
        let abs = caller.data().fs.resolve(&base, &path_str);
        // Translate WASI oflags + rights to Linux-style open flags for InMemFs.
        // WASI bit 6 of fs_rights_base = FD_WRITE; map to O_WRONLY.
        let fd_write_right: i64 = 1 << 6;
        let mut linux_flags: i32 = 0;
        if fs_rights_base & fd_write_right != 0 {
            linux_flags |= 1; // O_WRONLY
        }
        if oflags & 1 != 0 {
            linux_flags |= 64; // O_CREAT
        }
        if oflags & 8 != 0 {
            linux_flags |= 512; // O_TRUNC
        }
        let new_fd = caller.data_mut().fs.open(abs.clone(), linux_flags);
        pyo_trace!(
            "[path_open] dirfd={dirfd} {:?} oflags={oflags:#x} rights={fs_rights_base:#x} linux_flags={linux_flags:#x} -> new_fd={new_fd}",
            abs
        );
        if new_fd < 0 {
            // Translate to WASI ENOENT (errno 44) or EBADF (8).
            return if new_fd == -2 { 44 } else { EBADF };
        }
        if !write_u32(&mut caller, opened_fd_ptr, new_fd as u32) {
            // Close the just-opened fd to avoid leaking it.
            let _ = caller.data_mut().fs.close(new_fd);
            return EBADF;
        }
        0
    });

    // path_filestat_get(fd, flags, path_ptr, path_len, filestat_ptr) -> i32
    //
    // WASI equivalent of stat(). Returns an 8-field 64-byte filestat struct.
    // WASI wasi_filestat layout (64 bytes, all u64/i64 LE):
    //   0   dev u64
    //   8   ino u64
    //   16  filetype u8 (0=unknown,1=block,2=char,3=dir,4=regular,...)
    //   17  padding[7]
    //   24  nlink u64
    //   32  size u64
    //   40  atim u64 (ns)
    //   48  mtim u64 (ns)
    //   56  ctim u64 (ns)
    def!("path_filestat_get", |mut caller: Caller<
        '_,
        EmbedderState,
    >,
                               dirfd: i32,
                               _flags: i32,
                               path_ptr: i32,
                               path_len: i32,
                               filestat_ptr: i32|
     -> i32 {
        let len = path_len as u32 as usize;
        let path_bytes = match read_bytes(&caller, path_ptr, len) {
            Some(b) => b,
            None => return EBADF,
        };
        let path_str = match std::str::from_utf8(&path_bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => return EBADF,
        };
        let base = if path_str.starts_with('/') {
            "/".to_owned()
        } else {
            match caller.data().fs.preopen_name(dirfd) {
                Some(b) => b.to_owned(),
                None => match caller.data().fs.fd_path(dirfd) {
                    Some(p) => p.to_owned(),
                    None => return EBADF,
                },
            }
        };
        let abs = caller.data().fs.resolve(&base, &path_str);
        // Use the emscripten_fs stat path to get size info.
        let node_info = match caller.data_mut().fs.node_info(&abs) {
            None => return 44, // WASI ENOENT=44
            Some(info) => info,
        };
        let mut buf = [0u8; 64];
        buf[0..8].copy_from_slice(&1u64.to_le_bytes()); // dev=1
        buf[8..16].copy_from_slice(&node_info.ino.to_le_bytes()); // ino
        buf[16] = node_info.filetype; // filetype (3=dir, 4=regular)
        buf[24..32].copy_from_slice(&1u64.to_le_bytes()); // nlink=1
        buf[32..40].copy_from_slice(&node_info.size.to_le_bytes()); // size
        if !write_bytes(&mut caller, filestat_ptr, &buf) {
            return EBADF;
        }
        0
    });

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

    // ---- random_get ----------------------------------------------------------

    // random_get(buf_ptr: i32, buf_len: i32) -> i32
    //
    // CPython calls this (via _Py_HashRandomization_Init) to seed its internal
    // hash randomization. Returning an error or 0 bytes produces the fatal:
    // "Fatal Python error: _Py_HashRandomization_Init: failed to get random
    // numbers to initialize Python".
    //
    // Determinism is DESIRED here: a sealed engine with a fixed seed produces
    // byte-identical output across runs, making re-execution exact.
    //
    // Implementation: SplitMix64 with a fixed seed. Each call re-seeds from
    // the same constant so buf_ptr/buf_len combinations are stable across runs.
    //
    // vertexia: fixed seed; upgrade path is a per-store seed in EmbedderState
    // if callers need distinct entropy per instantiation.
    def!("random_get", |mut caller: Caller<'_, EmbedderState>,
                        buf_ptr: i32,
                        buf_len: i32|
     -> i32 {
        let len = buf_len as u32 as usize;
        if len == 0 {
            return 0;
        }
        // SplitMix64 generator with a fixed deterministic seed.
        // Each call starts from the same seed so output is stable across runs.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut buf = Vec::with_capacity(len);
        while buf.len() < len {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            buf.extend_from_slice(&z.to_le_bytes());
        }
        buf.truncate(len);
        if write_bytes(&mut caller, buf_ptr, &buf) {
            0
        } else {
            1
        }
    });

    Ok(())
}
