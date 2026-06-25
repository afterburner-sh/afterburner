// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Filesystem and POSIX syscall implementations for the Emscripten env.* layer.
//!
//! Wires the real in-memory FS-backed `__syscall_*` imports (getcwd, openat,
//! read, writev, pread64, close, lseek, fstat64, stat64, lstat64, newfstatat,
//! ioctl, getdents64, faccessat, fcntl64, readlinkat) plus real socket syscalls
//! (`socket`, `connect`, `bind`, `listen`, `accept4`, `sendmsg`, `recvmsg`,
//! `sendto`, `recvfrom`) backed by the existing `DaemonNet` coordinator when
//! `EmbedderState::daemon_net` is `Some`.

use std::sync::Arc;

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Linker};

use crate::{
    embedder_vm::EmbedderState,
    emscripten_fs::{EBADF, EINVAL, ENOENT, ENOTDIR, ENOTTY, InMemFs},
    emscripten_mechanical::read_cstr,
    emscripten_runtime::MechCallLog,
    pyo_trace,
};

/// Socket state types and syscall helpers.
pub mod socket;

/// Daemon-feature socket registration (wire_socket_syscalls / wire_sendto_recvfrom).
#[cfg(feature = "daemon")]
pub mod wire;

#[cfg(test)]
mod tests;

/// Size in bytes of the Emscripten wasm32 `struct stat` the guest allocates and
/// passes to the `*stat*` syscalls.
///
/// This is the authoritative `__size__` from Emscripten's
/// `struct_info_generated.json` (st_ino is the last field, at offset 88, an
/// i64, so the struct ends at 96). The guest's stat buffer is exactly this
/// many bytes; the syscall shims must write EXACTLY this many. Writing more
/// (e.g. the 112-byte `sizeof` of the musl C `struct stat`, whose timespec
/// layout differs) overruns the guest buffer and silently corrupts whatever the
/// guest placed immediately after it - on CPython 3.14 that overflow zeroes a
/// live PyObject header (refcnt + ob_type), which later double-frees with an
/// `IndirectCallToNull` in `_Py_Dealloc`. See [`crate::emscripten_fs`]
/// `write_stat_buf` for the field layout.
pub(crate) const EM_STAT_STRUCT_BYTES: usize = 96;

/// Log a stat syscall result: path, rc, and (if found) st_mode + st_size.
#[inline]
fn log_stat(tag: &str, abs: &str, rc: i32, mode_size: Option<(u32, u64)>) {
    match mode_size {
        Some((mode, size)) => pyo_trace!(
            "[{tag}] {:?} -> rc={rc} st_mode=0o{mode:o} st_size={size}",
            abs
        ),
        None => pyo_trace!("[{tag}] {:?} -> rc={rc}", abs),
    }
}

/// Wire all `__syscall_*` filesystem and POSIX imports into `linker`.
///
/// Real in-memory FS implementations are provided for the syscalls that CPython
/// needs to initialize and run (getcwd, openat, read, writev, pread64, close,
/// lseek, fstat64, stat64, lstat64, newfstatat, ioctl, getdents64, faccessat,
/// fcntl64, readlinkat). All other syscalls return -1 (ENOSYS).
pub fn wire_fs_env_funcs(
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

    // ---- filesystem syscall implementations ---------------------------------
    //
    // These replace the returning-(-1) stubs with real in-memory FS calls
    // backed by EmbedderState::fs (an InMemFs). Guest memory is accessed via
    // EmbedderState::pyodide_memory (the env.memory import handle).

    // __syscall_getcwd(buf: i32, size: i32) -> i32
    // Writes "/" into guest memory at buf, returns bytes written (2 incl. NUL).
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_getcwd",
                move |mut caller: Caller<'_, EmbedderState>, buf: i32, size: i32| -> i32 {
                    _log.push("__syscall_getcwd", buf, size);
                    if size < 2 {
                        return EINVAL;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let cwd = b"/\0";
                    let start = buf as u32 as usize;
                    let mem = memory.data_mut(&mut caller);
                    if start + 2 > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + 2].copy_from_slice(cwd);
                    2
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_getcwd: {e}")))?;
    }

    // __syscall_openat(dirfd: i32, pathptr: i32, flags: i32, mode: i32) -> i32
    // AT_FDCWD = -100; resolves relative paths from "/".
    // Paths under a declared rw-preopen go to the real host filesystem;
    // everything else stays in InMemFs (deny-by-default).
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_openat",
                move |mut caller: Caller<'_, EmbedderState>,
                      dirfd: i32,
                      pathptr: i32,
                      flags: i32,
                      _mode: i32|
                      -> i32 {
                    _log.push("__syscall_openat", dirfd, pathptr);
                    let path_str = match read_cstr(&caller, pathptr) {
                        Some(s) => s,
                        None => return ENOENT,
                    };
                    // Resolve the base: AT_FDCWD (-100) means "/" in our sealed env.
                    let base = if path_str.starts_with('/') || dirfd == -100 {
                        "/".to_owned()
                    } else {
                        match caller.data().fs.fd_path(dirfd) {
                            Some(p) => p.to_owned(),
                            None => return EBADF,
                        }
                    };
                    let abs = caller.data().fs.resolve(&base, &path_str);
                    // Track up to 200 paths for full import trace.
                    {
                        let log = &mut caller.data_mut().fs_path_log;
                        if log.len() >= 200 {
                            log.pop_front();
                        }
                        log.push_back(format!("openat:{abs}"));
                    }
                    // Route to host FS if path is under a rw-preopen.
                    let host_path = InMemFs::resolve_to_host_path(&abs, &caller.data().rw_preopens);
                    let fd = if let Some(hp) = host_path {
                        caller.data_mut().fs.open_host(abs.clone(), hp, flags)
                    } else {
                        caller.data_mut().fs.open(abs.clone(), flags)
                    };
                    // Extra log for .so / C-extension paths.
                    if abs.ends_with(".so") || abs.contains("_speedups") {
                        pyo_trace!("[openat-SO] {:?} flags={flags} -> fd={fd}", abs);
                    }
                    pyo_trace!("[openat] {:?} flags={flags} -> fd={fd}", abs);
                    fd
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_openat: {e}")))?;
    }

    // __syscall_mkdirat(dirfd: i32, pathptr: i32, mode: i32) -> i32
    // Create the directory (and any missing parents) in MEMFS. A no-op stub
    // returning -1 makes every os.mkdir/makedirs fail, which blocks any package
    // that creates a cache or config directory under HOME or /tmp at import
    // (matplotlib and its dependents, Cartopy's tempdir probe). Resolves the
    // dirfd-relative path exactly like __syscall_openat. Returns 0 on success.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_mkdirat",
                move |mut caller: Caller<'_, EmbedderState>,
                      dirfd: i32,
                      pathptr: i32,
                      _mode: i32|
                      -> i32 {
                    _log.push("__syscall_mkdirat", dirfd, pathptr);
                    let path_str = match read_cstr(&caller, pathptr) {
                        Some(s) => s,
                        None => return ENOENT,
                    };
                    let base = if path_str.starts_with('/') || dirfd == -100 {
                        "/".to_owned()
                    } else {
                        match caller.data().fs.fd_path(dirfd) {
                            Some(p) => p.to_owned(),
                            None => return EBADF,
                        }
                    };
                    let abs = caller.data().fs.resolve(&base, &path_str);
                    let host_path = InMemFs::resolve_to_host_path(&abs, &caller.data().rw_preopens);
                    if let Some(hp) = host_path {
                        let rc = InMemFs::mkdir_host(&hp);
                        pyo_trace!("[mkdirat-host] {abs:?} -> rc={rc}");
                        rc
                    } else {
                        caller.data_mut().fs.mkdir_p(&abs);
                        pyo_trace!("[mkdirat] {abs:?} -> 0");
                        0
                    }
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_mkdirat: {e}")))?;
    }

    // __syscall_read(fd: i32, buf: i32, count: i32) -> i32
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_read",
                move |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      buf: i32,
                      count: i32|
                      -> i32 {
                    _log.push("__syscall_read", fd, buf);
                    let len = count as u32 as usize;
                    if len == 0 {
                        return 0;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let mem_len = memory.data_size(&caller);
                    let start = buf as u32 as usize;
                    if start + len > mem_len {
                        return EINVAL;
                    }
                    // Pipe fds (Section 5: multiprocessing) are checked first.
                    #[cfg(feature = "daemon")]
                    {
                        let is_pipe = caller
                            .data()
                            .process_state
                            .as_ref()
                            .map(|s| s.is_pipe_fd(fd))
                            .unwrap_or(false);
                        if is_pipe {
                            let mut tmp = vec![0u8; len];
                            let n = caller
                                .data_mut()
                                .process_state
                                .as_mut()
                                .map(|s| s.pipe_read(fd, &mut tmp))
                                .unwrap_or(EBADF);
                            if n < 0 {
                                return n;
                            }
                            let mem = memory.data_mut(&mut caller);
                            mem[start..start + n as usize].copy_from_slice(&tmp[..n as usize]);
                            return n;
                        }
                    }
                    // Read from FS into a temp buffer, then write to guest memory.
                    // Host-backed fds are checked first.
                    let mut tmp = vec![0u8; len];
                    let n = if let Some(n) = caller.data_mut().fs.read_host(fd, &mut tmp) {
                        n
                    } else {
                        caller.data_mut().fs.read(fd, &mut tmp)
                    };
                    if n < 0 {
                        return n;
                    }
                    let mem = memory.data_mut(&mut caller);
                    mem[start..start + n as usize].copy_from_slice(&tmp[..n as usize]);
                    n
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_read: {e}")))?;
    }

    // __syscall_writev(fd: i32, iov: i32, iovcnt: i32) -> i32
    //
    // Linux iovec layout (wasm32, little-endian):
    //   offset +0: u32 iov_base
    //   offset +4: u32 iov_len
    // Each iovec is 8 bytes. For fd 1/2, bytes are appended to wasi_stdout
    // (which is the same capture buffer the WASI fd_write shim uses).
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_writev",
                move |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      iov: i32,
                      iovcnt: i32|
                      -> i32 {
                    _log.push("__syscall_writev", fd, iov);
                    let iovcnt = iovcnt as u32 as usize;
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let iov_array_len = iovcnt * 8;
                    let iov_start = iov as u32 as usize;
                    let mem_len = memory.data_size(&caller);
                    if iov_start + iov_array_len > mem_len {
                        return EINVAL;
                    }
                    // Read the entire iovec array first (avoids borrow overlap with data_mut).
                    let iov_bytes: Vec<u8> =
                        memory.data(&caller)[iov_start..iov_start + iov_array_len].to_vec();
                    let mut total: i32 = 0;
                    for i in 0..iovcnt {
                        let base = i * 8;
                        let buf_ptr =
                            u32::from_le_bytes(iov_bytes[base..base + 4].try_into().unwrap())
                                as usize;
                        let buf_len =
                            u32::from_le_bytes(iov_bytes[base + 4..base + 8].try_into().unwrap())
                                as usize;
                        if buf_len == 0 {
                            continue;
                        }
                        if buf_ptr + buf_len > mem_len {
                            return EINVAL;
                        }
                        let chunk: Vec<u8> =
                            memory.data(&caller)[buf_ptr..buf_ptr + buf_len].to_vec();
                        pyo_trace!("[__syscall_writev] fd={fd} iov[{i}] buf_ptr={buf_ptr:#x} buf_len={buf_len}");
                        if fd == 1 || fd == 2 {
                            caller.data_mut().wasi_stdout.extend_from_slice(&chunk);
                        } else {
                            // Pipe fds (Section 5: multiprocessing) checked before FS.
                            #[cfg(feature = "daemon")]
                            {
                                let is_pipe = caller
                                    .data()
                                    .process_state
                                    .as_ref()
                                    .map(|s| s.is_pipe_fd(fd))
                                    .unwrap_or(false);
                                if is_pipe {
                                    let n = caller
                                        .data_mut()
                                        .process_state
                                        .as_mut()
                                        .map(|s| s.pipe_write(fd, &chunk))
                                        .unwrap_or(EBADF);
                                    if n < 0 {
                                        return n;
                                    }
                                    total += n;
                                    continue;
                                }
                            }
                            if caller.data().fs.is_fs_fd(fd) {
                                // Host-backed fds are checked first.
                                let n = if let Some(n) =
                                    caller.data_mut().fs.write_host(fd, &chunk)
                                {
                                    n
                                } else {
                                    caller.data_mut().fs.write(fd, &chunk)
                                };
                                if n < 0 {
                                    return n;
                                }
                            }
                        }
                        total += buf_len as i32;
                    }
                    pyo_trace!("[__syscall_writev] fd={fd} total_bytes={total}");
                    total
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_writev: {e}")))?;
    }

    // __syscall_write(fd: i32, buf: i32, count: i32) -> i32
    // Plain write(2) - used by CPython buffered IO (PyFileIO_Type / PyTextIOWrapper)
    // when writing to a file fd opened via open(path, 'w'). For fd 1/2 bytes go
    // to wasi_stdout; for file fds they are appended to the MEMFS node.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_write",
                move |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      buf: i32,
                      count: i32|
                      -> i32 {
                    _log.push("__syscall_write", fd, buf);
                    let len = count as u32 as usize;
                    if len == 0 {
                        return 0;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let start = buf as u32 as usize;
                    let mem_len = memory.data_size(&caller);
                    if start + len > mem_len {
                        return EINVAL;
                    }
                    let chunk: Vec<u8> = memory.data(&caller)[start..start + len].to_vec();
                    pyo_trace!("[__syscall_write] fd={fd} buf={buf:#x} count={len}");
                    if fd == 1 || fd == 2 {
                        caller.data_mut().wasi_stdout.extend_from_slice(&chunk);
                    } else {
                        // Pipe fds (Section 5: multiprocessing) are checked before FS.
                        #[cfg(feature = "daemon")]
                        {
                            let is_pipe = caller
                                .data()
                                .process_state
                                .as_ref()
                                .map(|s| s.is_pipe_fd(fd))
                                .unwrap_or(false);
                            if is_pipe {
                                let n = caller
                                    .data_mut()
                                    .process_state
                                    .as_mut()
                                    .map(|s| s.pipe_write(fd, &chunk))
                                    .unwrap_or(EBADF);
                                if n < 0 {
                                    return n;
                                }
                                return n;
                            }
                        }
                        if caller.data().fs.is_fs_fd(fd) {
                            // Host-backed fds are checked first.
                            let n = if let Some(n) = caller.data_mut().fs.write_host(fd, &chunk) {
                                n
                            } else {
                                caller.data_mut().fs.write(fd, &chunk)
                            };
                            if n < 0 {
                                return n;
                            }
                        } else {
                            return EBADF;
                        }
                    }
                    len as i32
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_write: {e}")))?;
    }

    // __syscall_pread64(fd: i32, buf: i32, count: i32, offset: i64) -> i32
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_pread64",
                move |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      buf: i32,
                      count: i32,
                      offset: i64|
                      -> i32 {
                    _log.push("__syscall_pread64", fd, buf);
                    let len = count as u32 as usize;
                    if len == 0 {
                        return 0;
                    }
                    // Save current offset, seek to `offset`, read, restore.
                    // Host-backed fds use lseek_host; in-memory fds use InMemFs::lseek.
                    let saved = if caller.data().fs.is_fs_fd(fd) {
                        if let Some(s) = caller.data_mut().fs.lseek_host(fd, 0, 1) {
                            s
                        } else {
                            caller.data_mut().fs.lseek(fd, 0, 1)
                        }
                    } else {
                        return EBADF;
                    };
                    if saved < 0 {
                        return saved as i32;
                    }
                    let new_off = if let Some(o) = caller.data_mut().fs.lseek_host(fd, offset, 0) {
                        o
                    } else {
                        caller.data_mut().fs.lseek(fd, offset, 0)
                    };
                    if new_off < 0 {
                        return new_off as i32;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let mem_len = memory.data_size(&caller);
                    let start = buf as u32 as usize;
                    if start + len > mem_len {
                        let _ = if let Some(s) = caller.data_mut().fs.lseek_host(fd, saved, 0) {
                            s
                        } else {
                            caller.data_mut().fs.lseek(fd, saved, 0)
                        };
                        return EINVAL;
                    }
                    let mut tmp = vec![0u8; len];
                    let n = if let Some(n) = caller.data_mut().fs.read_host(fd, &mut tmp) {
                        n
                    } else {
                        caller.data_mut().fs.read(fd, &mut tmp)
                    };
                    // Restore offset.
                    let _ = if let Some(s) = caller.data_mut().fs.lseek_host(fd, saved, 0) {
                        s
                    } else {
                        caller.data_mut().fs.lseek(fd, saved, 0)
                    };
                    if n < 0 {
                        return n;
                    }
                    let mem = memory.data_mut(&mut caller);
                    mem[start..start + n as usize].copy_from_slice(&tmp[..n as usize]);
                    n
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_pread64: {e}")))?;
    }

    // __syscall_close(fd: i32) -> i32
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_close",
                move |mut caller: Caller<'_, EmbedderState>, fd: i32| -> i32 {
                    _log.push("__syscall_close", fd, 0);
                    // Host-backed fds are closed first; otherwise delegate to InMemFs.
                    if let Some(rc) = caller.data_mut().fs.close_host(fd) {
                        rc
                    } else {
                        caller.data_mut().fs.close(fd)
                    }
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_close: {e}")))?;
    }

    // __syscall_lseek(fd, offset, whence) -> i32
    // Emscripten's musl uses this for 64-bit seeks; offset is an i64 word.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_lseek",
                move |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      offset: i64,
                      whence: i32|
                      -> i32 {
                    _log.push("__syscall_lseek", fd, whence);
                    // Host-backed fds are checked first.
                    let new_off =
                        if let Some(o) = caller.data_mut().fs.lseek_host(fd, offset, whence) {
                            o
                        } else {
                            caller.data_mut().fs.lseek(fd, offset, whence)
                        };
                    if new_off < 0 {
                        new_off as i32
                    } else {
                        0 // success; offset is the return value itself
                    }
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_lseek: {e}")))?;
    }

    // __syscall_fstat64(fd: i32, stat_ptr: i32) -> i32
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_fstat64",
                move |mut caller: Caller<'_, EmbedderState>, fd: i32, stat_ptr: i32| -> i32 {
                    _log.push("__syscall_fstat64", fd, stat_ptr);
                    let path_for_log = caller.data().fs.fd_path(fd).map(str::to_owned);
                    let mut buf = [0u8; EM_STAT_STRUCT_BYTES];
                    // Try host-backed stat first; fall back to InMemFs for in-memory fds.
                    // For host directory fds (no File in host_fds) we fall through to the
                    // path-based stat below.
                    let rc = if let Some(rc) = caller.data_mut().fs.fstat_host(fd, &mut buf) {
                        rc
                    } else {
                        // Check if this is a host dir fd by looking up the guest path and
                        // resolving to a host path.
                        let host_path = path_for_log.as_deref().and_then(|p| {
                            InMemFs::resolve_to_host_path(p, &caller.data().rw_preopens)
                        });
                        if let Some(hp) = host_path {
                            caller.data_mut().fs.stat_host_path(&hp, &mut buf)
                        } else {
                            caller.data_mut().fs.fstat_into(fd, &mut buf)
                        }
                    };
                    let mode_size = path_for_log
                        .as_deref()
                        .and_then(|p| caller.data().fs.stat_mode_size(p));
                    log_stat(
                        "fstat64",
                        path_for_log.as_deref().unwrap_or("<unknown fd>"),
                        rc,
                        mode_size,
                    );
                    if rc != 0 {
                        return rc;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let start = stat_ptr as u32 as usize;
                    let mem = memory.data_mut(&mut caller);
                    if start + EM_STAT_STRUCT_BYTES > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + EM_STAT_STRUCT_BYTES].copy_from_slice(&buf);
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_fstat64: {e}")))?;
    }

    // __syscall_stat64(pathptr: i32, stat_ptr: i32) -> i32
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_stat64",
                move |mut caller: Caller<'_, EmbedderState>, pathptr: i32, stat_ptr: i32| -> i32 {
                    _log.push("__syscall_stat64", pathptr, stat_ptr);
                    let path_str = match read_cstr(&caller, pathptr) {
                        Some(s) => s,
                        None => return ENOENT,
                    };
                    let abs = caller.data().fs.resolve("/", &path_str);
                    // Track up to 200 paths for full import trace.
                    {
                        let log = &mut caller.data_mut().fs_path_log;
                        if log.len() >= 200 {
                            log.pop_front();
                        }
                        log.push_back(format!("stat64:{abs}"));
                    }
                    let mut buf = [0u8; EM_STAT_STRUCT_BYTES];
                    // Route to host if path is under a rw-preopen.
                    let host_path = InMemFs::resolve_to_host_path(&abs, &caller.data().rw_preopens);
                    let rc = if let Some(hp) = host_path {
                        caller.data_mut().fs.stat_host_path(&hp, &mut buf)
                    } else {
                        caller.data_mut().fs.stat_into(&abs, &mut buf)
                    };
                    let mode_size = caller.data().fs.stat_mode_size(&abs);
                    log_stat("stat64", &abs, rc, mode_size);
                    if rc != 0 {
                        return rc;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let start = stat_ptr as u32 as usize;
                    let mem = memory.data_mut(&mut caller);
                    if start + EM_STAT_STRUCT_BYTES > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + EM_STAT_STRUCT_BYTES].copy_from_slice(&buf);
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_stat64: {e}")))?;
    }

    // __syscall_lstat64(pathptr: i32, stat_ptr: i32) -> i32
    // No symlinks in our FS, so identical to stat64 (with host passthrough too).
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_lstat64",
                move |mut caller: Caller<'_, EmbedderState>, pathptr: i32, stat_ptr: i32| -> i32 {
                    _log.push("__syscall_lstat64", pathptr, stat_ptr);
                    let path_str = match read_cstr(&caller, pathptr) {
                        Some(s) => s,
                        None => return ENOENT,
                    };
                    let abs = caller.data().fs.resolve("/", &path_str);
                    let mut buf = [0u8; EM_STAT_STRUCT_BYTES];
                    let host_path = InMemFs::resolve_to_host_path(&abs, &caller.data().rw_preopens);
                    let rc = if let Some(hp) = host_path {
                        caller.data_mut().fs.stat_host_path(&hp, &mut buf)
                    } else {
                        caller.data_mut().fs.stat_into(&abs, &mut buf)
                    };
                    let mode_size = caller.data().fs.stat_mode_size(&abs);
                    log_stat("lstat64", &abs, rc, mode_size);
                    if rc != 0 {
                        return rc;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let start = stat_ptr as u32 as usize;
                    let mem = memory.data_mut(&mut caller);
                    if start + EM_STAT_STRUCT_BYTES > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + EM_STAT_STRUCT_BYTES].copy_from_slice(&buf);
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_lstat64: {e}")))?;
    }

    // __syscall_newfstatat(dirfd: i32, pathptr: i32, stat_ptr: i32, flags: i32) -> i32
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_newfstatat",
                move |mut caller: Caller<'_, EmbedderState>,
                      dirfd: i32,
                      pathptr: i32,
                      stat_ptr: i32,
                      _flags: i32|
                      -> i32 {
                    _log.push("__syscall_newfstatat", dirfd, pathptr);
                    let path_str = match read_cstr(&caller, pathptr) {
                        Some(s) => s,
                        None => return ENOENT,
                    };
                    let base = if path_str.starts_with('/') || dirfd == -100 {
                        "/".to_owned()
                    } else {
                        match caller.data().fs.fd_path(dirfd) {
                            Some(p) => p.to_owned(),
                            None => return EBADF,
                        }
                    };
                    let abs = caller.data().fs.resolve(&base, &path_str);
                    let mut buf = [0u8; EM_STAT_STRUCT_BYTES];
                    let host_path = InMemFs::resolve_to_host_path(&abs, &caller.data().rw_preopens);
                    let rc = if let Some(hp) = host_path {
                        caller.data_mut().fs.stat_host_path(&hp, &mut buf)
                    } else {
                        caller.data_mut().fs.stat_into(&abs, &mut buf)
                    };
                    let mode_size = caller.data().fs.stat_mode_size(&abs);
                    log_stat("newfstatat", &abs, rc, mode_size);
                    if rc != 0 {
                        return rc;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let start = stat_ptr as u32 as usize;
                    let mem = memory.data_mut(&mut caller);
                    if start + EM_STAT_STRUCT_BYTES > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + EM_STAT_STRUCT_BYTES].copy_from_slice(&buf);
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_newfstatat: {e}")))?;
    }

    // __syscall_ioctl(fd: i32, request: i32, ...) -> i32
    // In a sealed env with no real TTY, return ENOTTY for all ioctl requests.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_ioctl",
                move |_caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      request: i32,
                      _arg: i32|
                      -> i32 {
                    _log.push("__syscall_ioctl", fd, request);
                    ENOTTY
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_ioctl: {e}")))?;
    }

    // __syscall_getdents64(fd: i32, dirp: i32, count: i32) -> i32
    // Serialize directory entries as `struct linux_dirent64` into guest memory,
    // advancing the per-fd directory cursor. Returns 0 at end-of-directory so
    // callers (CPython's readdir loop) terminate correctly.
    // Host-backed directories (path under a rw-preopen) use std::fs::read_dir.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_getdents64",
                move |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      dirp: i32,
                      count: i32|
                      -> i32 {
                    _log.push("__syscall_getdents64", fd, dirp);
                    let buf_cap = count as u32 as usize;

                    // Detect whether the fd's guest path resolves to a host dir.
                    let host_path =
                        caller.data().fs.fd_path(fd).and_then(|p| {
                            InMemFs::resolve_to_host_path(p, &caller.data().rw_preopens)
                        });

                    // Produce the serialized dirent bytes into `tmp`.
                    let tmp: Vec<u8> = if let Some(hp) = host_path {
                        let entries = match InMemFs::list_dir_host(&hp) {
                            Some(e) => e,
                            None => return ENOTDIR,
                        };
                        let cursor = caller.data().fs.fd_dir_cursor(fd);
                        let total = 2 + entries.len();
                        if cursor >= total {
                            return 0;
                        }
                        let mut out = vec![0u8; buf_cap];
                        let mut pos = 0usize;
                        let mut written = 0usize;
                        for (i, idx) in (cursor..total).enumerate() {
                            let ino = 200u64 + cursor as u64 + i as u64;
                            let (name, is_dir): (&str, bool) = if idx == 0 {
                                (".", true)
                            } else if idx == 1 {
                                ("..", true)
                            } else {
                                let (ref n, d) = entries[idx - 2];
                                (n.as_str(), d)
                            };
                            let off = (idx + 1) as u64;
                            let w = crate::emscripten_fs::write_dirent64(
                                &mut out, pos, ino, off, name, is_dir,
                            );
                            if w == 0 {
                                break;
                            }
                            pos += w;
                            written += 1;
                        }
                        caller.data_mut().fs.advance_fd_dir_cursor(fd, written);
                        pyo_trace!("[getdents64-host] fd={fd} count={count} -> n={pos}");
                        out[..pos].to_vec()
                    } else {
                        let mut out = vec![0u8; buf_cap];
                        let n = caller.data_mut().fs.getdents64_into(fd, &mut out);
                        pyo_trace!("[getdents64] fd={fd} count={count} -> n={n}");
                        if n <= 0 {
                            return n;
                        }
                        out[..n as usize].to_vec()
                    };

                    let n = tmp.len() as i32;
                    if n == 0 {
                        return 0;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let start = dirp as u32 as usize;
                    let mem = memory.data_mut(&mut caller);
                    if start + n as usize > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + n as usize].copy_from_slice(&tmp);
                    n
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_getdents64: {e}")))?;
    }

    // __syscall_faccessat(dirfd: i32, pathptr: i32, mode: i32, flags: i32) -> i32
    // Returns 0 if the path exists in the FS, ENOENT otherwise.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_faccessat",
                move |mut caller: Caller<'_, EmbedderState>,
                      dirfd: i32,
                      pathptr: i32,
                      _mode: i32,
                      _flags: i32|
                      -> i32 {
                    _log.push("__syscall_faccessat", dirfd, pathptr);
                    let path_str = match read_cstr(&caller, pathptr) {
                        Some(s) => s,
                        None => return ENOENT,
                    };
                    let base = if path_str.starts_with('/') || dirfd == -100 {
                        "/".to_owned()
                    } else {
                        match caller.data().fs.fd_path(dirfd) {
                            Some(p) => p.to_owned(),
                            None => return EBADF,
                        }
                    };
                    let abs = caller.data().fs.resolve(&base, &path_str);
                    // Check host FS first for paths under a rw-preopen.
                    let host_path = InMemFs::resolve_to_host_path(&abs, &caller.data().rw_preopens);
                    let exists = if let Some(hp) = host_path {
                        InMemFs::exists_host(&hp)
                    } else {
                        caller.data_mut().fs.exists(&abs)
                    };
                    if exists { 0 } else { ENOENT }
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_faccessat: {e}")))?;
    }

    // __syscall_fcntl64(fd: i32, cmd: i32, arg: i32) -> i32
    // F_GETFL=3 returns O_RDONLY=0; everything else returns 0 (no-op).
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_fcntl64",
                move |_caller: Caller<'_, EmbedderState>, fd: i32, cmd: i32, _arg: i32| -> i32 {
                    _log.push("__syscall_fcntl64", fd, cmd);
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_fcntl64: {e}")))?;
    }

    // __syscall_readlinkat(dirfd: i32, pathptr: i32, buf: i32, bufsiz: i32) -> i32
    // No symlinks in our FS; always returns EINVAL.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_readlinkat",
                move |_caller: Caller<'_, EmbedderState>,
                      dirfd: i32,
                      pathptr: i32,
                      _buf: i32,
                      _bufsiz: i32|
                      -> i32 {
                    _log.push("__syscall_readlinkat", dirfd, pathptr);
                    EINVAL
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_readlinkat: {e}")))?;
    }

    // __syscall_mkdirat has a real handler above (creates the directory in
    // MEMFS); omit it from the stub list so the real handler is not shadowed.
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
    // __syscall_fcntl64 and __syscall_faccessat have real implementations above;
    // omit them from the stub list so the real handlers are not shadowed.
    def_syscall!("__syscall_fdatasync", 1);
    def_syscall!("__syscall_poll", 3);
    def_syscall!("__syscall_pipe", 1);
    def_syscall!("__syscall_utimensat", 4);
    // ---- socket syscalls -------------------------------------------------------
    //
    // When the `daemon` feature is active, real implementations route to
    // `DaemonNet`. Without the feature, sealed stubs return EPERM (-1).
    // The two blocks are kept separate so each compiles without unused-mut
    // or unused-variable warnings.

    #[cfg(feature = "daemon")]
    wire::wire_socket_syscalls(linker)?;

    #[cfg(not(feature = "daemon"))]
    {
        def_syscall!("__syscall_socket", 3);
        def_syscall!("__syscall_connect", 3);
        def_syscall!("__syscall_bind", 3);
        def_syscall!("__syscall_listen", 2);
        def_syscall!("__syscall_accept4", 4);
        def_syscall!("__syscall_sendmsg", 3);
        def_syscall!("__syscall_recvmsg", 3);
    }

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
    #[cfg(feature = "daemon")]
    wire::wire_sendto_recvfrom(linker)?;

    #[cfg(not(feature = "daemon"))]
    {
        linker
            .func_wrap(
                "env",
                "__syscall_sendto",
                |_: Caller<'_, EmbedderState>,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32|
                 -> i32 { -1 },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_sendto: {e}")))?;
        linker
            .func_wrap(
                "env",
                "__syscall_recvfrom",
                |_: Caller<'_, EmbedderState>,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32,
                 _: i32|
                 -> i32 { -1 },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_recvfrom: {e}")))?;
    }

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

    Ok(())
}
