// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Filesystem and POSIX syscall implementations for the Emscripten env.* layer.
//!
//! Wires the real in-memory FS-backed `__syscall_*` imports (getcwd, openat,
//! read, writev, pread64, pwrite64, close, lseek, fstat64, stat64, lstat64,
//! newfstatat, ioctl, getdents64, faccessat, fcntl64, readlinkat) plus real
//! socket syscalls (`socket`, `connect`, `bind`, `listen`, `accept4`,
//! `sendmsg`, `recvmsg`, `sendto`, `recvfrom`) backed by the existing
//! `DaemonNet` coordinator when `EmbedderState::daemon_net` is `Some`.
//!
//! ## Advisory record locking (`_try_fcntl64`)
//!
//! SQLite's default (delete) journal mode uses POSIX advisory record locks
//! (F_SETLK / F_SETLKW / F_GETLK) on the database file and its rollback
//! journal to serialize concurrent writers. The runtime is a single OS process
//! with a single SQLite connection per invocation, so no real inter-process
//! locking is needed; instead a process-wide in-memory lock table tracks held
//! locks. `ADVISORY_LOCKS` is a `Mutex<HashMap>` (not a kovan lock-free map)
//! because the read-check-then-insert sequence for F_GETLK / F_SETLK must be
//! atomic across the check and the mutation.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Linker};

// ---- process-wide advisory lock table ----------------------------------------

/// Key for an advisory lock entry: (host_path_string, byte_range_start, byte_range_len).
///
/// SQLite locks specific byte ranges (e.g. bytes 1073741824..1073741824+510
/// for the SHARED lock range, byte 1073741826 for RESERVED, etc.) on the db
/// file and on the rollback journal. We key on the guest absolute path (which
/// is unique per file in the single-connection scenario) and the lock range.
/// l_len == 0 means "to EOF"; we store it as-is and treat 0 as a wildcard
/// only for conflict detection (conservative: never conflicts in single-conn).
type LockKey = (String, i64, i64);

/// F_RDLCK / F_WRLCK / F_UNLCK values stored in the table.
type LockType = i16;

/// Process-wide advisory lock table.
/// vertexia: Mutex<HashMap> for atomic check-and-set; upgrade to per-path
/// fine-grained locking if multi-connection contention ever matters.
static ADVISORY_LOCKS: LazyLock<Mutex<HashMap<LockKey, LockType>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

use crate::{
    embedder_vm::EmbedderState,
    emscripten_fs::{EBADF, EINVAL, ENOENT, ENOTDIR, ENOTTY, InMemFs, io_err_to_errno},
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
/// needs to initialize and run (getcwd, openat, read, writev, pread64, pwrite64,
/// close, lseek, fstat64, stat64, lstat64, newfstatat, ioctl, getdents64,
/// faccessat, fcntl64, readlinkat). All other syscalls return -1 (ENOSYS).
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
                    pyo_trace!("[openat-ENTER] dirfd={dirfd} pathptr={pathptr:#x} flags={flags}");
                    let path_str = match read_cstr(&caller, pathptr) {
                        Some(s) => s,
                        None => {
                            pyo_trace!(
                                "[openat] dirfd={dirfd} pathptr={pathptr:#x} -> ENOENT (bad ptr)"
                            );
                            return ENOENT;
                        }
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
                            if caller.data().fs.is_host_fd(fd) {
                                let n = match caller.data_mut().fs.write_host(fd, &chunk) {
                                    Some(n) => n,
                                    None => return EBADF,
                                };
                                if n < 0 {
                                    return -n;
                                }
                            } else if caller.data().fs.is_fs_fd(fd) {
                                let n = caller.data_mut().fs.write(fd, &chunk);
                                if n < 0 {
                                    return n;
                                }
                            } else {
                                return EBADF;
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
                        if caller.data().fs.is_host_fd(fd) {
                            let n = match caller.data_mut().fs.write_host(fd, &chunk) {
                                Some(n) => n,
                                None => return EBADF,
                            };
                            if n < 0 {
                                return -n;
                            }
                        } else if caller.data().fs.is_fs_fd(fd) {
                            let n = caller.data_mut().fs.write(fd, &chunk);
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
                    let saved = if caller.data().fs.is_host_fd(fd) {
                        match caller.data_mut().fs.lseek_host(fd, 0, 1) {
                            Some(s) => s,
                            None => return EBADF,
                        }
                    } else if caller.data().fs.is_fs_fd(fd) {
                        caller.data_mut().fs.lseek(fd, 0, 1)
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

    // __syscall_pwrite64(fd: i32, buf: i32, count: i32, offset: i64) -> i32
    // Positional write without advancing the fd's current offset.
    // SQLite's delete-journal mode uses this to write journal pages.
    // Host-backed fds use pwrite_host (write_at); in-memory fds use InMemFs::pwrite.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_pwrite64",
                move |mut caller: Caller<'_, EmbedderState>,
                      fd: i32,
                      buf: i32,
                      count: i32,
                      offset: i64|
                      -> i32 {
                    _log.push("__syscall_pwrite64", fd, buf);
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
                    let off = offset.max(0) as u64;
                    let is_host = caller.data().fs.is_host_fd(fd);
                    pyo_trace!("[pwrite64] fd={fd} len={len} off={off} is_host={is_host}");
                    if is_host {
                        let rc = match caller.data_mut().fs.pwrite_host(fd, &chunk, off) {
                            Some(n) if n >= 0 => n,
                            Some(_) => EBADF,
                            None => EBADF,
                        };
                        pyo_trace!("[pwrite64] fd={fd} -> rc={rc}");
                        rc
                    } else if caller.data().fs.is_fs_fd(fd) {
                        caller.data_mut().fs.pwrite(fd, &chunk, off)
                    } else {
                        EBADF
                    }
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_pwrite64: {e}")))?;
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
                    pyo_trace!("[__syscall_close] fd={fd}");
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
                    pyo_trace!("[stat64] pathptr={pathptr:#x} stat_ptr={stat_ptr:#x} preopens={:?} abs={:?} host_path={:?}", caller.data().rw_preopens, abs, host_path);
                    let rc = if let Some(hp) = host_path {
                        let r = caller.data_mut().fs.stat_host_path(&hp, &mut buf);
                        pyo_trace!("[stat64-host] hp={hp:?} -> rc={r}");
                        r
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
    //
    // For paths under a rw-preopen whose parent directory exists but the file
    // itself does not yet exist on the host, we return a fake "empty regular
    // file" stat instead of ENOENT. This lets musl's realpath() succeed for
    // to-be-created files (musl realpath fails on ENOENT for the last component,
    // unlike glibc which succeeds). sqlite3's unixFullPathname calls realpath
    // and would return SQLITE_CANTOPEN if realpath fails here.
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
                        caller.data_mut().fs.stat_host_path_for_lstat(&hp, &mut buf)
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
                    let rc = if exists { 0 } else { ENOENT };
                    pyo_trace!("[faccessat] {:?} mode={_mode} -> rc={rc}", abs);
                    rc
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_faccessat: {e}")))?;
    }

    // __syscall_fcntl64(fd: i32, cmd: i32, arg: i32) -> i32
    // F_GETFL=3: return O_RDWR(2) for host-backed fds (they are always opened
    // read-write), O_RDONLY(0) for MEMFS fds.
    // F_GETLK(5) / F_GETLK64(12): write F_UNLCK into the flock64 struct at arg
    // so SQLite's conflict check always reports no existing lock.
    // F_SETLK(6) / F_SETLKW(7) / F_SETLK64(13) / F_SETLKW64(14): always
    // succeed (single-connection; no real inter-process locking needed).
    // All other commands return 0.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_fcntl64",
                move |mut caller: Caller<'_, EmbedderState>, fd: i32, cmd: i32, arg: i32| -> i32 {
                    _log.push("__syscall_fcntl64", fd, cmd);
                    const F_GETFL: i32 = 3;
                    const F_GETLK: i32 = 5;
                    const F_SETLK: i32 = 6;
                    const F_SETLKW: i32 = 7;
                    const F_GETLK64: i32 = 12;
                    const F_SETLK64: i32 = 13;
                    const F_SETLKW64: i32 = 14;
                    const O_RDWR: i32 = 2;
                    const F_UNLCK: i16 = 2;
                    pyo_trace!("[__syscall_fcntl64] fd={fd} cmd={cmd} arg={arg}");
                    if cmd == F_GETFL && caller.data().fs.is_host_fd(fd) {
                        // Host-backed files are always opened O_RDWR.
                        return O_RDWR;
                    }
                    if (cmd == F_GETLK || cmd == F_GETLK64)
                        && arg != 0
                        && let Some(mem) = caller.data().pyodide_memory
                    {
                        // Write l_type=F_UNLCK so SQLite sees no conflicting lock.
                        let p = arg as u32 as usize;
                        let data = mem.data_mut(&mut caller);
                        if p + 2 <= data.len() {
                            let bytes = (F_UNLCK as u16).to_le_bytes();
                            data[p] = bytes[0];
                            data[p + 1] = bytes[1];
                        }
                    }
                    // F_SETLK / F_SETLKW and all other commands: succeed silently.
                    let _ = (F_SETLK, F_SETLKW, F_SETLK64, F_SETLKW64);
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

    // __syscall_unlinkat(dirfd, pathptr, flags) -> i32
    // Delete a file. For host-backed paths (rw-preopens) this removes the
    // actual host file. sqlite3 uses this to delete the rollback journal when
    // committing a transaction; without it, no transaction can commit.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_unlinkat",
                move |mut caller: Caller<'_, EmbedderState>,
                      dirfd: i32,
                      pathptr: i32,
                      _flags: i32|
                      -> i32 {
                    _log.push("__syscall_unlinkat", dirfd, pathptr);
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
                    pyo_trace!("[unlinkat] abs={abs:?}");
                    // Route host-backed paths to the real filesystem.
                    if let Some(host_path) =
                        InMemFs::resolve_to_host_path(&abs, &caller.data().rw_preopens)
                    {
                        // On Linux, deleting an open file unlinks the directory
                        // entry; the data persists until the last fd is closed.
                        // We do not need to close open handles here.
                        pyo_trace!("[unlinkat-host] host_path={host_path:?}");
                        match std::fs::remove_file(&host_path) {
                            Ok(()) => 0,
                            Err(e) => io_err_to_errno(&e),
                        }
                    } else {
                        // MEMFS unlink.
                        caller.data_mut().fs.unlink(&abs)
                    }
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_unlinkat: {e}")))?;
    }
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
    // fdatasync: flush journal pages to disk. Return success (0) to allow
    // sqlite3 to proceed; real data is written to host files, no kernel
    // flush is needed inside the sandbox.
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_fdatasync",
                move |_: Caller<'_, EmbedderState>, fd: i32| -> i32 {
                    _log.push("__syscall_fdatasync", fd, 0);
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_fdatasync: {e}")))?;
    }
    // __syscall_poll(fds_ptr: i32, nfds: i32, timeout_ms: i32) -> i32
    // struct pollfd { fd: i32, events: i16, revents: i16 } = 8 bytes
    // POLLIN = 1; return count of ready fds, -1 on error.
    //
    // When the daemon net is present, we wait for incoming connections
    // (POLLIN on a server fd) or buffered data (POLLIN on a conn fd).
    // Without daemon net the wasm program cannot do socket I/O, so
    // poll returns -1 (ENOSYS) to surface the error early.
    {
        linker
            .func_wrap(
                "env",
                "__syscall_poll",
                |mut caller: Caller<'_, EmbedderState>,
                 fds_ptr: i32,
                 nfds: i32,
                 timeout_ms: i32|
                 -> i32 {
                    let net = match caller.data().daemon_net.clone() {
                        Some(n) => n,
                        None => return -1,
                    };
                    let n = nfds as usize;
                    let struct_size = 8usize; // sizeof(struct pollfd) on wasm32
                    let bytes_needed = n * struct_size;
                    let mem_handle = match caller.data().pyodide_memory {
                        Some(m) => m,
                        None => return EINVAL,
                    };
                    let fds_bytes = {
                        let data = mem_handle.data(&caller);
                        let off = fds_ptr as usize;
                        if off + bytes_needed > data.len() {
                            return EINVAL;
                        }
                        data[off..off + bytes_needed].to_vec()
                    };
                    const POLLIN: u16 = 1;
                    // Determine which fds are server (listener) vs conn (data),
                    // and separate those with immediate readiness from those that need blocking.
                    let mut server_fds_asked: Vec<(usize, i32, u16)> = Vec::new();
                    let mut conn_fds_waiting: Vec<(usize, i32)> = Vec::new(); // (slot, conn_id)
                    let mut revents_ready: Vec<(usize, u16)> = Vec::new();
                    for i in 0..n {
                        let base = i * struct_size;
                        let fd = i32::from_le_bytes(fds_bytes[base..base + 4].try_into().unwrap());
                        let events =
                            u16::from_le_bytes(fds_bytes[base + 4..base + 6].try_into().unwrap());
                        if fd < 0 {
                            continue;
                        }
                        let server_id_opt = caller
                            .data()
                            .socket_state
                            .as_ref()
                            .and_then(|s| s.server_fds.get(&fd).copied());
                        let conn_id_opt = caller
                            .data()
                            .socket_state
                            .as_ref()
                            .and_then(|s| s.conn_fds.get(&fd).copied());
                        if let Some(server_id) = server_id_opt {
                            if events & POLLIN != 0 {
                                let queued = caller
                                    .data_mut()
                                    .socket_state
                                    .as_deref_mut()
                                    .map(|s| {
                                        !s.accept_queues.entry(server_id).or_default().is_empty()
                                    })
                                    .unwrap_or(false);
                                if queued {
                                    revents_ready.push((i, POLLIN));
                                } else {
                                    server_fds_asked.push((i, fd, events));
                                }
                            }
                        } else if let Some(conn_id) = conn_id_opt
                            && events & POLLIN != 0
                        {
                            let has_data = caller
                                .data()
                                .socket_state
                                .as_ref()
                                .map(|s| s.has_buffered(conn_id))
                                .unwrap_or(false);
                            if has_data {
                                revents_ready.push((i, POLLIN));
                            } else {
                                conn_fds_waiting.push((i, conn_id));
                            }
                        }
                    }
                    // Write revents for immediately ready fds and return.
                    if !revents_ready.is_empty() {
                        let mem = match caller.data().pyodide_memory {
                            Some(m) => m,
                            None => return revents_ready.len() as i32,
                        };
                        let data = mem.data_mut(&mut caller);
                        for (slot, rev) in &revents_ready {
                            let off = fds_ptr as usize + slot * struct_size + 6;
                            if off + 2 <= data.len() {
                                data[off..off + 2].copy_from_slice(&rev.to_le_bytes());
                            }
                        }
                        return revents_ready.len() as i32;
                    }
                    // Nothing immediately ready. Decide what to block on.
                    let has_server_wait = !server_fds_asked.is_empty();
                    let has_conn_wait = !conn_fds_waiting.is_empty();
                    if !has_server_wait && !has_conn_wait {
                        return 0;
                    }
                    let timeout_dur = if timeout_ms < 0 {
                        std::time::Duration::from_secs(3600)
                    } else {
                        std::time::Duration::from_millis(timeout_ms as u64)
                    };
                    // If there are connection fds waiting for data (no server fds), block on data.
                    if !has_server_wait {
                        // Block waiting for a Data event on any of the conn_fds_waiting.
                        let waiting_conn_ids: Vec<i32> =
                            conn_fds_waiting.iter().map(|(_, cid)| *cid).collect();
                        let net2 = Arc::clone(&net);
                        let maybe_data = net.runtime().block_on(async move {
                            tokio::time::timeout(timeout_dur, async move {
                                loop {
                                    if let Some(crate::daemon_net::NetEvent::Data {
                                        conn_id,
                                        payload_b64,
                                    }) = net2.try_recv_event()
                                        && waiting_conn_ids.contains(&conn_id)
                                    {
                                        return Some((conn_id, payload_b64));
                                    }
                                    tokio::task::yield_now().await;
                                }
                            })
                            .await
                            .ok()
                            .flatten()
                        });
                        match maybe_data {
                            None => return 0,
                            Some((cid, payload_b64)) => {
                                // Push data to recv_bufs for recvmsg to consume.
                                use base64::{Engine as _, engine::general_purpose::STANDARD};
                                if let Ok(bytes) = STANDARD.decode(&payload_b64)
                                    && let Some(s) = caller.data_mut().socket_state.as_deref_mut()
                                {
                                    s.push_data(cid, bytes);
                                }
                                // Find slot for this conn_id and set revents.
                                let slot = conn_fds_waiting
                                    .iter()
                                    .find(|(_, c)| *c == cid)
                                    .map(|(s, _)| *s);
                                let mem = match caller.data().pyodide_memory {
                                    Some(m) => m,
                                    None => return 1,
                                };
                                let data = mem.data_mut(&mut caller);
                                if let Some(slot_idx) = slot {
                                    let off = fds_ptr as usize + slot_idx * struct_size + 6;
                                    if off + 2 <= data.len() {
                                        data[off..off + 2].copy_from_slice(&POLLIN.to_le_bytes());
                                    }
                                }
                                return 1;
                            }
                        }
                    }
                    // Block waiting for a server connection event, skipping non-connection
                    // events (like Listening) that DaemonNet fires first.
                    let (slot_idx, server_virt_fd, _) = server_fds_asked[0];
                    let server_id = caller
                        .data()
                        .socket_state
                        .as_ref()
                        .and_then(|s| s.server_fds.get(&server_virt_fd).copied())
                        .unwrap_or(-1);
                    if server_id < 0 {
                        return -1;
                    }
                    let net2 = Arc::clone(&net);
                    // Also route Data events to conn recv_bufs while waiting for a new connection.
                    let maybe_conn = net.runtime().block_on(async move {
                        tokio::time::timeout(timeout_dur, async move {
                            loop {
                                if let Some(ev) = net2.try_recv_event() {
                                    match ev {
                                        crate::daemon_net::NetEvent::Connection {
                                            server_id,
                                            conn_id,
                                            ..
                                        } => {
                                            return Some((server_id, conn_id));
                                        }
                                        crate::daemon_net::NetEvent::Data {
                                            conn_id,
                                            payload_b64,
                                        } => {
                                            // Discard buffered data - will come via recvmsg.
                                            drop((conn_id, payload_b64));
                                        }
                                        _ => {} // Listening and other events skipped.
                                    }
                                }
                                tokio::task::yield_now().await;
                            }
                        })
                        .await
                        .ok()
                        .flatten()
                    });
                    match maybe_conn {
                        None => 0,
                        Some((sid, conn_id)) => {
                            // Queue the connection for accept4 to pick up.
                            let state = caller.data_mut().socket_state.as_deref_mut().unwrap();
                            state
                                .accept_queues
                                .entry(sid)
                                .or_default()
                                .push_back(conn_id);
                            // Set revents = POLLIN for this server fd.
                            let mem = match caller.data().pyodide_memory {
                                Some(m) => m,
                                None => return 1,
                            };
                            let data = mem.data_mut(&mut caller);
                            let off = fds_ptr as usize + slot_idx * struct_size + 6;
                            if off + 2 <= data.len() {
                                data[off..off + 2].copy_from_slice(&POLLIN.to_le_bytes());
                            }
                            1
                        }
                    }
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_poll: {e}")))?;
    }
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
        // All socket syscalls are typed (i32 i32 i32 i32 i32 i32) -> i32 in both
        // the 0.28.3 and 3.14 runtimes (emscripten type 10). Use the 6-param stub.
        def_syscall!("__syscall_socket", 6);
        def_syscall!("__syscall_connect", 6);
        def_syscall!("__syscall_bind", 6);
        def_syscall!("__syscall_listen", 6);
        def_syscall!("__syscall_accept4", 6);
        def_syscall!("__syscall_sendmsg", 6);
        def_syscall!("__syscall_recvmsg", 6);
    }

    def_syscall!("__syscall_getsockopt", 6);
    {
        let _log = mech_log.clone();
        linker
            .func_wrap(
                "env",
                "__syscall_getsockname",
                move |mut caller: Caller<'_, EmbedderState>,
                      sockfd: i32,
                      addr_ptr: i32,
                      addrlen_ptr: i32,
                      _c: i32,
                      _d: i32,
                      _e: i32|
                      -> i32 {
                    _log.push("__syscall_getsockname", sockfd, addr_ptr);
                    // Resolve port: for server fds use the bound port; for
                    // connection fds (accepted) return port 0 as local port.
                    let port: u16 = {
                        let placeholder = {
                            let state = caller
                                .data_mut()
                                .socket_state
                                .get_or_insert_with(socket::SocketState::new);
                            state.server_fds.get(&sockfd).copied()
                        };
                        if let Some(p) = placeholder {
                            if p < 0 { (-p) as u16 } else { p as u16 }
                        } else {
                            // Check if it's a connection fd (accepted socket).
                            let is_conn = caller
                                .data()
                                .socket_state
                                .as_ref()
                                .and_then(|s| s.conn_fds.get(&sockfd).copied())
                                .is_some();
                            if !is_conn {
                                return socket::EBADF;
                            }
                            0 // local port for accepted connections
                        }
                    };
                    // Write sockaddr_in (16 bytes): family(2 LE), port(2 BE), addr(4 BE), pad(8)
                    let mut sa = [0u8; 16];
                    sa[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
                    sa[2..4].copy_from_slice(&port.to_be_bytes()); // port big-endian
                    sa[4..8].copy_from_slice(&0x7f000001u32.to_be_bytes()); // 127.0.0.1
                    let mem = match caller.data().pyodide_memory {
                        Some(m) => m,
                        None => return EINVAL,
                    };
                    let data = mem.data_mut(&mut caller);
                    let addr_off = addr_ptr as usize;
                    if addr_off + 16 > data.len() {
                        return EINVAL;
                    }
                    data[addr_off..addr_off + 16].copy_from_slice(&sa);
                    // Write addrlen = 16
                    let al_off = addrlen_ptr as usize;
                    if al_off + 4 <= data.len() {
                        data[al_off..al_off + 4].copy_from_slice(&16i32.to_le_bytes());
                    }
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_getsockname: {e}")))?;
    }
    def_syscall!("__syscall_getpeername", 6);
    // __syscall_shutdown is imported by the 3.14 runtime (not the 0.28.3 one).
    // In daemon mode wire.rs registers a real implementation; without daemon,
    // a sealed stub returning -1 is sufficient.
    #[cfg(not(feature = "daemon"))]
    def_syscall!("__syscall_shutdown", 6);

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
    // _try_fcntl64(fd, cmd, arg, lock_ptr) - Emscripten file-locking wrapper.
    // SQLite's delete-journal mode calls F_SETLK64 (cmd=13) / F_SETLKW64 (14)
    // to acquire advisory locks and F_GETLK64 (cmd=12) to check for conflicts.
    // `arg` is a pointer to struct flock64 in guest memory (wasm32 layout):
    //   offset 0:  l_type  (i16) - F_RDLCK=0, F_WRLCK=1, F_UNLCK=2
    //   offset 2:  l_whence (i16)
    //   offset 4:  padding  (4 bytes, wasm32 i64 alignment)
    //   offset 8:  l_start  (i64)
    //   offset 16: l_len    (i64)
    //   offset 24: l_pid    (i32)
    // Single-connection guarantee: F_SETLK always succeeds; F_GETLK always
    // reports F_UNLCK (no conflict). We track the held locks in ADVISORY_LOCKS
    // so F_UNLCK correctly removes them and the table stays consistent.
    linker
        .func_wrap(
            "env",
            "_try_fcntl64",
            |mut caller: Caller<'_, EmbedderState>,
             fd: i32,
             cmd: i32,
             arg: i32,
             _lock_ptr: i32|
             -> i32 {
                // Linux cmd values (both 32- and 64-bit variants).
                const F_GETLK: i32 = 5;
                const F_SETLK: i32 = 6;
                const F_SETLKW: i32 = 7;
                const F_GETLK64: i32 = 12;
                const F_SETLK64: i32 = 13;
                const F_SETLKW64: i32 = 14;
                const F_RDLCK: i16 = 0;
                const F_WRLCK: i16 = 1;
                const F_UNLCK: i16 = 2;

                let is_getlk = cmd == F_GETLK || cmd == F_GETLK64;
                let is_setlk =
                    cmd == F_SETLK || cmd == F_SETLKW || cmd == F_SETLK64 || cmd == F_SETLKW64;

                if !is_getlk && !is_setlk {
                    return 0;
                }

                // Read the flock64 struct from guest memory.
                // `_try_fcntl64(fd, cmd, arg, lock_ptr)` where:
                // - `arg` = the varargs area pointer (stack slot holding the flock64
                //   struct pointer, passed as the third argument to fcntl()).
                //   The actual flock64 is at `*arg` (the i32 at that address).
                // - `lock_ptr` = an Emscripten-internal copy area; NOT the user pointer.
                // Dereference: struct_ptr = *((i32*)(wasm_mem + arg))
                let struct_ptr: i32 = if arg != 0 {
                    caller.data().pyodide_memory.and_then(|mem| {
                        let p = arg as u32 as usize;
                        let data = mem.data(&caller);
                        if p + 4 <= data.len() {
                            Some(i32::from_le_bytes(data[p..p+4].try_into().ok()?))
                        } else {
                            None
                        }
                    }).unwrap_or(0)
                } else {
                    0
                };
                let flock = if struct_ptr != 0 {
                    caller.data().pyodide_memory.and_then(|mem| {
                        let p = struct_ptr as u32 as usize;
                        let data = mem.data(&caller);
                        if p + 28 > data.len() {
                            return None;
                        }
                        let l_type = i16::from_le_bytes(data[p..p + 2].try_into().ok()?);
                        // l_whence at p+2, skip padding at p+4..p+8
                        let l_start = i64::from_le_bytes(data[p + 8..p + 16].try_into().ok()?);
                        let l_len = i64::from_le_bytes(data[p + 16..p + 24].try_into().ok()?);
                        Some((l_type, l_start, l_len))
                    })
                } else {
                    None
                };

                let (l_type, l_start, l_len) = match flock {
                    Some(f) => f,
                    None => return 0, // no struct pointer: succeed silently
                };
                pyo_trace!("[_try_fcntl64] fd={fd} cmd={cmd} l_type={l_type} l_start={l_start} l_len={l_len}");

                // Resolve the host path string for the lock key.
                let path_key: String = caller
                    .data()
                    .fs
                    .fd_path(fd)
                    .map(|p| p.to_owned())
                    .unwrap_or_else(|| format!("fd:{fd}"));

                let key: LockKey = (path_key, l_start, l_len);

                if is_getlk {
                    // F_GETLK: report no conflict (single-connection; table is
                    // always consistent with our own locks). Write F_UNLCK back.
                    if struct_ptr != 0
                        && let Some(mem) = caller.data().pyodide_memory
                    {
                        let p = struct_ptr as u32 as usize;
                        let data = mem.data_mut(&mut caller);
                        if p + 2 <= data.len() {
                            let bytes = (F_UNLCK as u16).to_le_bytes();
                            data[p] = bytes[0];
                            data[p + 1] = bytes[1];
                        }
                    }
                    return 0;
                }

                // F_SETLK / F_SETLKW: update the lock table.
                if let Ok(mut table) = ADVISORY_LOCKS.lock() {
                    if l_type == F_UNLCK {
                        table.remove(&key);
                    } else if l_type == F_RDLCK || l_type == F_WRLCK {
                        table.insert(key, l_type);
                    }
                }
                0
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("_try_fcntl64: {e}")))?;
    linker
        .func_wrap(
            "env",
            "__syscall_ftruncate64",
            |mut caller: Caller<'_, EmbedderState>, fd: i32, len: i64| -> i32 {
                let len_u64 = len.max(0) as u64;
                pyo_trace!("[ftruncate64] fd={fd} len={len}");
                if caller.data().fs.is_host_fd(fd) {
                    return match caller.data_mut().fs.truncate_host(fd, len_u64) {
                        Some(0) => 0,
                        Some(e) => e,
                        None => -9, // EBADF
                    };
                }
                0
            },
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
    def!("__syscall_statfs64", |caller: Caller<'_, EmbedderState>,
                                p: i32,
                                _sz: i32,
                                _buf: i32|
     -> i32 {
        let path = read_cstr(&caller, p).unwrap_or_else(|| format!("ptr={p:#x}"));
        pyo_trace!("[statfs64] {:?} -> -1", path);
        -1
    });
    def!("__syscall__newselect", |_: Caller<'_, EmbedderState>,
                                  _n: i32,
                                  _r: i32,
                                  _w: i32,
                                  _e: i32,
                                  _t: i32|
     -> i32 { 0 });

    Ok(())
}
