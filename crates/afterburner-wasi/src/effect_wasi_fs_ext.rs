// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Additional effect-wrapped `wasi_snapshot_preview1` filesystem imports a real
//! CRuby boot needs, beyond the 13 core ones in [`crate::effect_wasi_fs`].
//!
//! This is a sibling of [`crate::effect_wasi_fs`] (split only to keep both files
//! under the size limit); it shares the same fd table
//! ([`EmbedderState::fs`](crate::embedder_vm::EmbedderState)), the same
//! host-backed switch ([`resolve_host_backed`]), and the same record/serve
//! [`FsSeam`](crate::emscripten_syscall). It is wired by
//! [`crate::effect_wasi_fs::wire_effect_wrapped_wasi_fs`].
//!
//! # What is here and why
//!
//! - `fd_fdstat_get` / `fd_fdstat_set_flags`: wasi-libc's `isatty` (stdout
//!   buffering) and `fcntl(F_SETFL)` at CRuby boot. Pure bookkeeping, no effect.
//! - `path_readlink`: CRuby's `gem_prelude` resolves the load-path roots up to
//!   `/usr` with `realpath`, which reads each component. Our mounts carry no
//!   symlinks, so an existing component returns `EINVAL` (realpath uses it
//!   verbatim) and a missing one `ENOENT`.
//! - `fd_readdir`: `gem_prelude` may enumerate the gems / specifications dirs.
//!   Record-only [`FileOp::List`] (a directory cursor makes byte-substitution
//!   replay unsafe, like `getdents64`).
//! - `fd_tell` / `fd_sync` / `fd_datasync` / `fd_advise`: defensive no-ops so an
//!   unshadowed call cannot hit stock and `EBADF`-trap boot on an owned fd.
//!
//! [`resolve_host_backed`]: crate::embedder_vm::EmbedderState::resolve_host_backed

use afterburner_core::{FileOp, Result};
use wasmtime::Caller;

use crate::effect_wasi_abi::{
    ERRNO_BADF, ERRNO_FAULT, ERRNO_INVAL, ERRNO_NOENT, ERRNO_NOTDIR, ERRNO_SUCCESS, read_bytes,
    write_bytes, write_u32, write_u64,
};
use crate::effect_wasi_fs::em2wasi;
use crate::embedder_vm::{EmbedderLinker, EmbedderState};
use crate::emscripten_fs::{EBADF, FsNode, InMemFs};
use crate::emscripten_syscall::FsSeam;

// ---- wasip1 filetype constants ----------------------------------------------

/// wasip1 `filetype`: a character device (stdin/stdout/stderr).
const FILETYPE_CHARACTER_DEVICE: u8 = 2;
/// wasip1 `filetype`: a directory.
const FILETYPE_DIRECTORY: u8 = 3;
/// wasip1 `filetype`: a regular file.
const FILETYPE_REGULAR_FILE: u8 = 4;

/// The wasip1 `rights` mask covering every defined right (bits 0..=28). Granted
/// generously to every owned fd: the runtime is a single trusted process and the
/// real access control is the per-preopen writable flag enforced in `path_open`,
/// not the advertised rights.
const GENEROUS_RIGHTS: u64 = (1u64 << 29) - 1;

/// Size of the wasip1 `fdstat` struct the guest allocates for `fd_fdstat_get`.
const FDSTAT_BYTES: usize = 24;

// ---- shared fd helpers ------------------------------------------------------

/// The wasip1 `filetype` for `fd`, or `None` when the fd is not open.
///
/// fd 0/1/2 are character devices; a host-backed regular-file fd (an open
/// `std::fs::File`) is a regular file; any other open fd resolves its guest path
/// to a host directory / file or an in-memory node.
fn fd_filetype(caller: &Caller<'_, EmbedderState>, fd: i32) -> Option<u8> {
    if (0..=2).contains(&fd) {
        return Some(FILETYPE_CHARACTER_DEVICE);
    }
    if caller.data().fs.is_host_fd(fd) {
        return Some(FILETYPE_REGULAR_FILE);
    }
    let abs = caller.data().fs.fd_path(fd)?.to_owned();
    if let Some((host_path, _)) = caller.data().resolve_host_backed(&abs) {
        return Some(if host_path.is_dir() {
            FILETYPE_DIRECTORY
        } else {
            FILETYPE_REGULAR_FILE
        });
    }
    Some(match caller.data().fs.get(&abs) {
        Some(FsNode::Dir) => FILETYPE_DIRECTORY,
        // An open fd whose node vanished is still a valid open fd; treat as file.
        _ => FILETYPE_REGULAR_FILE,
    })
}

/// True when `fd` is a valid open fd (stdio, a host-backed fd, or an fd-table
/// entry). Used by the defensive no-op shims to reject a truly-bad fd.
fn fd_valid(caller: &Caller<'_, EmbedderState>, fd: i32) -> bool {
    (0..=2).contains(&fd)
        || caller.data().fs.is_host_fd(fd)
        || caller.data().fs.fd_path(fd).is_some()
}

// ---- fdstat -----------------------------------------------------------------

/// `fd_fdstat_get(fd, retptr) -> errno`. Writes the 24-byte `fdstat`
/// (`fs_filetype u8 @0`, `fs_flags u16 @2`, `fs_rights_base u64 @8`,
/// `fs_rights_inheriting u64 @16`). Pure bookkeeping, no effect.
fn fd_fdstat_get(mut caller: Caller<'_, EmbedderState>, fd: i32, retptr: i32) -> i32 {
    let Some(filetype) = fd_filetype(&caller, fd) else {
        return ERRNO_BADF;
    };
    let mut buf = [0u8; FDSTAT_BYTES];
    buf[0] = filetype; // fs_filetype @ 0 (fs_flags @ 2 left 0)
    buf[8..16].copy_from_slice(&GENEROUS_RIGHTS.to_le_bytes()); // fs_rights_base
    buf[16..24].copy_from_slice(&GENEROUS_RIGHTS.to_le_bytes()); // fs_rights_inheriting
    if write_bytes(&mut caller, retptr, &buf) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// `fd_fdstat_set_flags(fd, flags) -> errno`. Bookkeeping no-op (the O_APPEND /
/// O_NONBLOCK a guest may set is irrelevant to the in-memory / host backing);
/// success for a valid owned fd, `EBADF` otherwise.
fn fd_fdstat_set_flags(caller: Caller<'_, EmbedderState>, fd: i32, _flags: i32) -> i32 {
    if fd_valid(&caller, fd) {
        ERRNO_SUCCESS
    } else {
        ERRNO_BADF
    }
}

// ---- readlink ---------------------------------------------------------------

/// `path_readlink(dirfd, path, path_len, buf, buf_len, retptr) -> errno`.
///
/// Our mounts carry no symlinks, so an existing component is not a link:
/// `EINVAL` (musl `realpath` then uses it verbatim). A missing component is
/// `ENOENT`. The output buffer is never written (no link target exists).
#[allow(clippy::too_many_arguments)]
fn path_readlink(
    mut caller: Caller<'_, EmbedderState>,
    dirfd: i32,
    path_ptr: i32,
    path_len: i32,
    _buf: i32,
    _buf_len: i32,
    _retptr: i32,
) -> i32 {
    let Some(raw) = read_bytes(&mut caller, path_ptr, path_len as u32 as usize) else {
        return ERRNO_FAULT;
    };
    let path = String::from_utf8_lossy(&raw).into_owned();
    let base = caller.data().fs.fd_path(dirfd).unwrap_or("/").to_owned();
    let abs = caller.data().fs.resolve(&base, &path);
    let exists = if let Some((host_path, _)) = caller.data().resolve_host_backed(&abs) {
        host_path.exists()
    } else {
        caller.data().fs.exists(&abs)
    };
    if exists { ERRNO_INVAL } else { ERRNO_NOENT }
}

// ---- readdir ----------------------------------------------------------------

/// Serialize one wasip1 `dirent` (`d_next u64 @0`, `d_ino u64 @8`,
/// `d_namlen u32 @16`, `d_type u8 @20`) followed by the (non-terminated) name.
fn serialize_dirent(d_next: u64, d_ino: u64, name: &str, is_dir: bool) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut e = vec![0u8; 24 + name_bytes.len()];
    e[0..8].copy_from_slice(&d_next.to_le_bytes());
    e[8..16].copy_from_slice(&d_ino.to_le_bytes());
    e[16..20].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    e[20] = if is_dir {
        FILETYPE_DIRECTORY
    } else {
        FILETYPE_REGULAR_FILE
    };
    e[24..].copy_from_slice(name_bytes);
    e
}

/// `fd_readdir(fd, buf, buf_len, cookie, retptr) -> errno`.
///
/// Emits `"."`, `".."`, then the sorted directory children as wasip1 dirents,
/// resuming at `cookie` (the `d_next` of the last complete entry the guest
/// consumed). The final entry is truncated to fill `buf` exactly when it does
/// not fit, so the guest sees `bytes_used == buf_len` and grows its buffer.
/// Record-only [`FileOp::List`]: the directory cursor makes replay-by-byte
/// substitution unsafe (as with `getdents64`).
fn fd_readdir(
    mut caller: Caller<'_, EmbedderState>,
    fd: i32,
    buf_ptr: i32,
    buf_len: i32,
    cookie: i64,
    retptr: i32,
) -> i32 {
    let Some(abs) = caller.data().fs.fd_path(fd).map(str::to_owned) else {
        return ERRNO_BADF;
    };
    let children = if let Some((host_path, _)) = caller.data().resolve_host_backed(&abs) {
        InMemFs::list_dir_host(&host_path)
    } else {
        caller.data().fs.list_dir(&abs)
    };
    let Some(children) = children else {
        return ERRNO_NOTDIR;
    };

    let seam = FsSeam::record_fd(&caller, FileOp::List, fd);

    // Full ordered entry list: ".", "..", then the sorted children.
    let mut entries: Vec<(String, bool)> = Vec::with_capacity(children.len() + 2);
    entries.push((".".to_owned(), true));
    entries.push(("..".to_owned(), true));
    entries.extend(children);

    let start = cookie as u64 as usize;
    let cap = buf_len as u32 as usize;
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(4096));
    for (i, (name, is_dir)) in entries.iter().enumerate().skip(start) {
        let d_next = (i + 1) as u64;
        let d_ino = 100u64 + i as u64;
        let e = serialize_dirent(d_next, d_ino, name, *is_dir);
        let remaining = cap - out.len();
        if e.len() <= remaining {
            out.extend_from_slice(&e);
            if out.len() == cap {
                break;
            }
        } else {
            // Truncate the final entry to fill the buffer; the guest re-reads
            // it from `cookie` with a larger buffer.
            out.extend_from_slice(&e[..remaining]);
            break;
        }
    }

    if !write_bytes(&mut caller, buf_ptr, &out) {
        return ERRNO_FAULT;
    }
    let used = out.len() as i64;
    seam.finish(out, used);
    if write_u32(&mut caller, retptr, used as u32) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

// ---- defensive no-ops -------------------------------------------------------

/// `fd_tell(fd, retptr) -> errno`. The current offset (`lseek(fd, 0, CUR)`).
fn fd_tell(mut caller: Caller<'_, EmbedderState>, fd: i32, retptr: i32) -> i32 {
    let r = if caller.data().fs.is_host_fd(fd) {
        caller
            .data_mut()
            .fs
            .lseek_host(fd, 0, 1)
            .unwrap_or(EBADF as i64)
    } else {
        caller.data_mut().fs.lseek(fd, 0, 1)
    };
    if r < 0 {
        return em2wasi(r as i32);
    }
    if write_u64(&mut caller, retptr, r as u64) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// `fd_sync(fd) -> errno`. No-op success for a valid fd: the `InMemFs` is memory
/// and host writes are already flushed by `write_host`.
fn fd_sync(caller: Caller<'_, EmbedderState>, fd: i32) -> i32 {
    if fd_valid(&caller, fd) {
        ERRNO_SUCCESS
    } else {
        ERRNO_BADF
    }
}

/// `fd_datasync(fd) -> errno`. Same as [`fd_sync`] (no metadata to flush).
fn fd_datasync(caller: Caller<'_, EmbedderState>, fd: i32) -> i32 {
    if fd_valid(&caller, fd) {
        ERRNO_SUCCESS
    } else {
        ERRNO_BADF
    }
}

/// `fd_advise(fd, offset, len, advice) -> errno`. A read-ahead hint; ignored.
fn fd_advise(
    _caller: Caller<'_, EmbedderState>,
    _fd: i32,
    _offset: i64,
    _len: i64,
    _advice: i32,
) -> i32 {
    ERRNO_SUCCESS
}

// ---- linker wiring -----------------------------------------------------------

/// Register the additional wasip1 fs shadows over the stock `wasmtime-wasi`
/// ones. Called from
/// [`crate::effect_wasi_fs::wire_effect_wrapped_wasi_fs`] (after the core fs
/// imports), so `allow_shadowing` is already enabled.
pub(crate) fn wire_effect_wrapped_wasi_fs_ext(linker: &mut EmbedderLinker<'_>) -> Result<()> {
    let m = "wasi_snapshot_preview1";
    linker.func_wrap(m, "fd_fdstat_get", fd_fdstat_get)?;
    linker.func_wrap(m, "fd_fdstat_set_flags", fd_fdstat_set_flags)?;
    linker.func_wrap(m, "path_readlink", path_readlink)?;
    linker.func_wrap(m, "fd_readdir", fd_readdir)?;
    linker.func_wrap(m, "fd_tell", fd_tell)?;
    linker.func_wrap(m, "fd_sync", fd_sync)?;
    linker.func_wrap(m, "fd_datasync", fd_datasync)?;
    linker.func_wrap(m, "fd_advise", fd_advise)?;
    Ok(())
}
