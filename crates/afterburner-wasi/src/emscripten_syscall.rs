// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Filesystem and POSIX syscall implementations for the Emscripten env.* layer.
//!
//! Wires the real in-memory FS-backed `__syscall_*` imports (getcwd, openat,
//! read, pread64, close, lseek, fstat64, stat64, lstat64, newfstatat, ioctl,
//! getdents64, faccessat, fcntl64, readlinkat) plus the returning-(-1) stubs
//! for syscalls that are not needed in a sealed environment.

use std::sync::Arc;

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Linker};

use crate::{
    embedder_vm::EmbedderState,
    emscripten_fs::{EBADF, EINVAL, ENOENT, ENOTTY},
    emscripten_mechanical::read_cstr,
    emscripten_runtime::MechCallLog,
};

/// Log a stat syscall result: path, rc, and (if found) st_mode + st_size.
#[inline]
fn log_stat(tag: &str, abs: &str, rc: i32, mode_size: Option<(u32, u64)>) {
    match mode_size {
        Some((mode, size)) => eprintln!(
            "[{tag}] {:?} -> rc={rc} st_mode=0o{mode:o} st_size={size}",
            abs
        ),
        None => eprintln!("[{tag}] {:?} -> rc={rc}", abs),
    }
}

/// Wire all `__syscall_*` filesystem and POSIX imports into `linker`.
///
/// Real in-memory FS implementations are provided for the syscalls that CPython
/// needs to initialize (getcwd, openat, read, pread64, close, lseek, fstat64,
/// stat64, lstat64, newfstatat, ioctl, getdents64, faccessat, fcntl64,
/// readlinkat). All other syscalls return -1 (ENOSYS).
pub(crate) fn wire_fs_env_funcs(
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
                    // Track last 12 paths for exception context.
                    {
                        let log = &mut caller.data_mut().fs_path_log;
                        if log.len() >= 12 {
                            log.pop_front();
                        }
                        log.push_back(format!("openat:{abs}"));
                    }
                    let fd = caller.data_mut().fs.open(abs.clone(), flags);
                    eprintln!("[openat] {:?} flags={flags} -> fd={fd}", abs);
                    fd
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_openat: {e}")))?;
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
                    // Read from FS into a temp buffer, then write to guest memory.
                    let mut tmp = vec![0u8; len];
                    let n = caller.data_mut().fs.read(fd, &mut tmp);
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
                    let saved = caller.data_mut().fs.lseek(fd, 0, 1);
                    if saved < 0 {
                        return saved as i32;
                    }
                    let new_off = caller.data_mut().fs.lseek(fd, offset, 0);
                    if new_off < 0 {
                        return new_off as i32;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let mem_len = memory.data_size(&caller);
                    let start = buf as u32 as usize;
                    if start + len > mem_len {
                        let _ = caller.data_mut().fs.lseek(fd, saved, 0);
                        return EINVAL;
                    }
                    let mut tmp = vec![0u8; len];
                    let n = caller.data_mut().fs.read(fd, &mut tmp);
                    // Restore offset.
                    let _ = caller.data_mut().fs.lseek(fd, saved, 0);
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
                    caller.data_mut().fs.close(fd)
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
                    let new_off = caller.data_mut().fs.lseek(fd, offset, whence);
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
                    // Resolve path for logging before the mutable borrow.
                    let path_for_log = caller.data().fs.fd_path(fd).map(str::to_owned);
                    let mut buf = [0u8; 112];
                    let rc = caller.data_mut().fs.fstat_into(fd, &mut buf);
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
                    if start + 112 > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + 112].copy_from_slice(&buf);
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
                    // Track last 12 paths for exception context.
                    {
                        let log = &mut caller.data_mut().fs_path_log;
                        if log.len() >= 12 {
                            log.pop_front();
                        }
                        log.push_back(format!("stat64:{abs}"));
                    }
                    let mut buf = [0u8; 112];
                    let rc = caller.data_mut().fs.stat_into(&abs, &mut buf);
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
                    if start + 112 > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + 112].copy_from_slice(&buf);
                    0
                },
            )
            .map_err(|e| AfterburnerError::Engine(format!("__syscall_stat64: {e}")))?;
    }

    // __syscall_lstat64(pathptr: i32, stat_ptr: i32) -> i32
    // No symlinks in our FS, so identical to stat64.
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
                    let mut buf = [0u8; 112];
                    let rc = caller.data_mut().fs.stat_into(&abs, &mut buf);
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
                    if start + 112 > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + 112].copy_from_slice(&buf);
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
                    let mut buf = [0u8; 112];
                    let rc = caller.data_mut().fs.stat_into(&abs, &mut buf);
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
                    if start + 112 > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + 112].copy_from_slice(&buf);
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
                    let mut tmp = vec![0u8; buf_cap];
                    let n = caller.data_mut().fs.getdents64_into(fd, &mut tmp);
                    eprintln!("[getdents64] fd={fd} count={count} -> n={n}");
                    if n <= 0 {
                        // 0 = end-of-directory (correct termination), negative = error.
                        return n;
                    }
                    let Some(memory) = caller.data().pyodide_memory else {
                        return EBADF;
                    };
                    let start = dirp as u32 as usize;
                    let mem = memory.data_mut(&mut caller);
                    if start + n as usize > mem.len() {
                        return EINVAL;
                    }
                    mem[start..start + n as usize].copy_from_slice(&tmp[..n as usize]);
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
                    if caller.data_mut().fs.exists(&abs) {
                        0
                    } else {
                        ENOENT
                    }
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
    // __syscall_fcntl64 and __syscall_faccessat have real implementations above;
    // omit them from the stub list so the real handlers are not shadowed.
    def_syscall!("__syscall_fdatasync", 1);
    def_syscall!("__syscall_poll", 3);
    def_syscall!("__syscall_pipe", 1);
    def_syscall!("__syscall_utimensat", 4);
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

    Ok(())
}
