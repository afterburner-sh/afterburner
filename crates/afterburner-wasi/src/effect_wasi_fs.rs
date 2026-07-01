// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Effect-wrapped `wasi_snapshot_preview1` **filesystem** imports for the
//! WASI-command substrate (Ruby / Rust / Go / C / C++).
//!
//! The clock + random shadows in [`crate::effect_wasi`] observed that a wrapped
//! `fd_read` / `fd_write` could not delegate to stock `wasmtime-wasi` (its
//! preview1 impl is private and its wrappers resolve guest memory through the
//! calling instance). This module takes the other road the design left open:
//! it owns the whole fd table itself, backed by the same
//! [`InMemFs`](crate::emscripten_fs::InMemFs) the Pyodide substrate already
//! uses, and routes every op through the shared record/replay
//! [`FsSeam`](crate::emscripten_syscall). One in-memory FS serves both
//! substrates (DRY); the record/serve decision, the `/.afb` skip, and the
//! content-addressing are all single-sourced through `FsSeam`.
//!
//! # The backing: a sealed [`InMemFs`](crate::emscripten_fs::InMemFs)
//!
//! Engaged **only** when a recording host is attached; the stock
//! `wasmtime-wasi` host-FS preopen path stays the default for every
//! non-capturing run (see [`wire_effect_wrapped_wasi_fs`] for why this is a
//! second compile variant, not a mutation of the sealed one). The in-memory FS
//! is deterministic (a monotonic inode counter, no wall clock, times pinned to
//! [`VIRTUAL_EPOCH_NS`]), so two record
//! runs of the same guest produce byte-identical effect logs. A host-backed fd
//! table (a real `std::fs::File` per fd) would coexist with today's preopen
//! semantics for a real interpreter boot, but at the cost of real disk I/O and
//! FS non-determinism on the record run; it is the likely backing for the
//! deferred real-interpreter-boot step, not this increment.
//!
//! # Coexistence with stock stdio / args / env
//!
//! Only the `fd_*` / `path_*` imports are shadowed. `fd_write` / `fd_read`
//! dispatch on the fd number: fd 1/2 append to / read from
//! [`EmbedderState::wasi_stdout`](crate::embedder_vm::EmbedderState::wasi_stdout),
//! fd 0 is sealed EOF, fd >= 3 goes to the `InMemFs`. `args_get`,
//! `environ_get`, `proc_exit`, `sched_yield`, and `poll_oneoff` are left stock,
//! so argv / env keep flowing from the stock `WasiCtx`. The shadowed
//! `fd_prestat_get` / `fd_prestat_dir_name` advertise only the `InMemFs` root
//! at fd 3, so the guest never discovers a stock preopen and there is no
//! fd-number collision between the two fd tables.

use afterburner_core::{EffectStatus, FileOp, Result};
use wasmtime::Caller;

use crate::effect_wasi::wire_effect_wrapped_wasi;
use crate::effect_wasi_abi::{
    ERRNO_ACCES, ERRNO_BADF, ERRNO_FAULT, ERRNO_INVAL, ERRNO_ISDIR, ERRNO_NOENT, ERRNO_NOTDIR,
    ERRNO_SUCCESS, read_bytes, read_iovecs, write_bytes, write_u32, write_u64,
};
use crate::embedder_vm::{EmbedderLinker, EmbedderState};
use crate::emscripten_abi::VIRTUAL_EPOCH_NS;
use crate::emscripten_fs::{EACCES, EBADF, EINVAL, EISDIR, ENOENT, ENOTDIR};
use crate::emscripten_syscall::FsSeam;

// ---- wasip1 <-> emscripten flag / errno translation --------------------------
//
// These two translations are the load-bearing correctness details: the guest
// speaks wasip1 (positive errno, wasip1 oflags/rights); the `InMemFs` speaks
// emscripten/musl (negative errno, musl open flags).

/// Emscripten/musl open flag: read-write.
const EM_O_RDWR: i32 = 2;
/// Emscripten/musl open flag: create if absent.
const EM_O_CREAT: i32 = 64;
/// Emscripten/musl open flag: truncate on open.
const EM_O_TRUNC: i32 = 512;

/// wasip1 `oflags`: create the file if it does not exist.
const OFLAGS_CREAT: i32 = 0x1;
/// wasip1 `oflags`: truncate the file to zero length.
const OFLAGS_TRUNC: i32 = 0x8;
/// wasip1 `rights`: the `fd_write` right (implies a writable open).
const RIGHTS_FD_WRITE: i64 = 0x40;

/// Size of the wasip1 `filestat` struct the guest allocates for
/// `fd_filestat_get` / `path_filestat_get`.
const FILESTAT_BYTES: usize = 64;

/// Map an `InMemFs` negative Linux-style errno to its positive wasip1 `errno`.
/// A non-negative input is not an error and must never reach here.
fn em2wasi(neg: i32) -> i32 {
    match neg {
        ENOENT => ERRNO_NOENT,   // -2  -> 44
        EBADF => ERRNO_BADF,     // -9  -> 8
        EACCES => ERRNO_ACCES,   // -13 -> 2
        ENOTDIR => ERRNO_NOTDIR, // -20 -> 54
        EISDIR => ERRNO_ISDIR,   // -21 -> 31
        EINVAL => ERRNO_INVAL,   // -22 -> 28
        // Any other negative errno the FS can surface (EIO, EEXIST, ...) maps
        // to EINVAL rather than fabricating a specific wasip1 code.
        _ => ERRNO_INVAL,
    }
}

/// Translate wasip1 `oflags` + `rights_base` into the emscripten/musl open
/// flags the `InMemFs::open` path understands.
fn open_flags(oflags: i32, rights_base: i64) -> i32 {
    let mut flags = 0;
    if oflags & OFLAGS_CREAT != 0 {
        flags |= EM_O_CREAT;
    }
    if oflags & OFLAGS_TRUNC != 0 {
        flags |= EM_O_TRUNC;
    }
    if rights_base & RIGHTS_FD_WRITE != 0 {
        flags |= EM_O_RDWR;
    }
    flags
}

/// Build the wasip1 64-byte `filestat` for a node. `filetype` is already the
/// wasip1 encoding (3 = directory, 4 = regular file, from `InMemFs::node_info`).
/// Times are pinned to [`VIRTUAL_EPOCH_NS`] to stay sealed and deterministic.
fn write_filestat(ino: u64, filetype: u8, size: u64) -> [u8; FILESTAT_BYTES] {
    let mut b = [0u8; FILESTAT_BYTES];
    // dev: u64 @ 0 (left 0)
    b[8..16].copy_from_slice(&ino.to_le_bytes()); // ino: u64 @ 8
    b[16] = filetype; // filetype: u8 @ 16 (17..24 padding)
    b[24..32].copy_from_slice(&1u64.to_le_bytes()); // nlink: u64 @ 24
    b[32..40].copy_from_slice(&size.to_le_bytes()); // size: u64 @ 32
    b[40..48].copy_from_slice(&VIRTUAL_EPOCH_NS.to_le_bytes()); // atim @ 40
    b[48..56].copy_from_slice(&VIRTUAL_EPOCH_NS.to_le_bytes()); // mtim @ 48
    b[56..64].copy_from_slice(&VIRTUAL_EPOCH_NS.to_le_bytes()); // ctim @ 56
    b
}

// ---- shadowed filesystem imports --------------------------------------------

/// `path_open(dirfd, dirflags, path, path_len, oflags, rights_base,
/// rights_inheriting, fdflags, opened_fd_out) -> errno`.
///
/// Resolves the guest-absolute path from `dirfd`'s path (fd 3 -> `/`),
/// translates the open flags, and opens against the `InMemFs`. A brand-new node
/// (`O_CREAT` set and the node absent) is journalled as a record-only
/// [`FileOp::Create`] with the resulting fd as its status code; a plain
/// open-for-read emits no effect (its bytes are carried by the later `fd_read`).
#[allow(clippy::too_many_arguments)]
fn path_open(
    mut caller: Caller<'_, EmbedderState>,
    dirfd: i32,
    _dirflags: i32,
    path_ptr: i32,
    path_len: i32,
    oflags: i32,
    rights_base: i64,
    _rights_inheriting: i64,
    _fdflags: i32,
    opened_fd_out: i32,
) -> i32 {
    let Some(raw) = read_bytes(&mut caller, path_ptr, path_len as u32 as usize) else {
        return ERRNO_FAULT;
    };
    let path = String::from_utf8_lossy(&raw).into_owned();
    let base = caller.data().fs.fd_path(dirfd).unwrap_or("/").to_owned();
    let abs = caller.data().fs.resolve(&base, &path);

    // Record-only Create, and only for a node that does not yet exist.
    let creating = oflags & OFLAGS_CREAT != 0 && caller.data().fs.get(&abs).is_none();
    let seam = if creating {
        FsSeam::record_path(&caller, FileOp::Create, &abs)
    } else {
        FsSeam::Off
    };

    let fd = caller
        .data_mut()
        .fs
        .open(abs, open_flags(oflags, rights_base));
    if fd < 0 {
        return em2wasi(fd);
    }
    if !write_u32(&mut caller, opened_fd_out, fd as u32) {
        return ERRNO_FAULT;
    }
    seam.finish(Vec::new(), fd as i64);
    ERRNO_SUCCESS
}

/// `fd_read(fd, iovs, iovs_len, nread_out) -> errno`.
///
/// fd 0 is sealed EOF (n = 0); fd 1/2 are EBADF. fd >= 3 reads from the
/// `InMemFs`, advancing the fd offset. On serve the recorded bytes are
/// scattered across the iovecs and the offset is advanced to stay coherent.
fn fd_read(
    mut caller: Caller<'_, EmbedderState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    nread_out: i32,
) -> i32 {
    if fd == 0 {
        return if write_u32(&mut caller, nread_out, 0) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }
    if fd == 1 || fd == 2 {
        return ERRNO_BADF;
    }
    let Some(iovecs) = read_iovecs(&mut caller, iovs_ptr, iovs_len) else {
        return ERRNO_FAULT;
    };

    let seam = FsSeam::for_fd(&caller, FileOp::Read, fd, Vec::new());
    if let Some(rec) = seam.served() {
        // Serve is authoritative: substitute the recorded bytes, run no real
        // read. Advance the fd offset anyway so a following read is coherent.
        let mut pos = 0usize;
        for (buf, len) in &iovecs {
            if pos >= rec.output.len() {
                break;
            }
            let take = (*len as usize).min(rec.output.len() - pos);
            if take == 0 {
                continue;
            }
            if !write_bytes(&mut caller, *buf as i32, &rec.output[pos..pos + take]) {
                return ERRNO_FAULT;
            }
            pos += take;
        }
        let served = rec.output.len() as i64;
        caller.data_mut().fs.lseek(fd, served, 1);
        return if write_u32(&mut caller, nread_out, pos as u32) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }

    // Record / off: read the real bytes, scatter to the guest, journal them.
    let mut scratch = Vec::new();
    let mut total = 0usize;
    for (buf, len) in &iovecs {
        let mut chunk = vec![0u8; *len as usize];
        let n = caller.data_mut().fs.read(fd, &mut chunk);
        if n < 0 {
            return em2wasi(n);
        }
        let n = n as usize;
        if n > 0 {
            if !write_bytes(&mut caller, *buf as i32, &chunk[..n]) {
                return ERRNO_FAULT;
            }
            scratch.extend_from_slice(&chunk[..n]);
            total += n;
        }
        if n < *len as usize {
            break; // short read => end of file
        }
    }
    seam.finish(scratch, total as i64);
    if write_u32(&mut caller, nread_out, total as u32) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// `fd_pread(fd, iovs, iovs_len, offset, nread_out) -> errno`.
///
/// Positional read: like [`fd_read`] but reads at `offset` (and successive
/// positions across the iovecs) without moving the fd's current offset.
fn fd_pread(
    mut caller: Caller<'_, EmbedderState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    offset: i64,
    nread_out: i32,
) -> i32 {
    if fd == 0 {
        return if write_u32(&mut caller, nread_out, 0) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }
    if fd == 1 || fd == 2 {
        return ERRNO_BADF;
    }
    let Some(iovecs) = read_iovecs(&mut caller, iovs_ptr, iovs_len) else {
        return ERRNO_FAULT;
    };

    let seam = FsSeam::for_fd(&caller, FileOp::Read, fd, Vec::new());
    if let Some(rec) = seam.served() {
        let mut pos = 0usize;
        for (buf, len) in &iovecs {
            if pos >= rec.output.len() {
                break;
            }
            let take = (*len as usize).min(rec.output.len() - pos);
            if take == 0 {
                continue;
            }
            if !write_bytes(&mut caller, *buf as i32, &rec.output[pos..pos + take]) {
                return ERRNO_FAULT;
            }
            pos += take;
        }
        return if write_u32(&mut caller, nread_out, pos as u32) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }

    let mut scratch = Vec::new();
    let mut total = 0usize;
    let mut cur = offset as u64;
    for (buf, len) in &iovecs {
        let mut chunk = vec![0u8; *len as usize];
        let n = caller.data_mut().fs.pread(fd, &mut chunk, cur);
        if n < 0 {
            return em2wasi(n);
        }
        let n = n as usize;
        if n > 0 {
            if !write_bytes(&mut caller, *buf as i32, &chunk[..n]) {
                return ERRNO_FAULT;
            }
            scratch.extend_from_slice(&chunk[..n]);
            total += n;
            cur += n as u64;
        }
        if n < *len as usize {
            break;
        }
    }
    seam.finish(scratch, total as i64);
    if write_u32(&mut caller, nread_out, total as u32) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// Gather the iovec payload of an `fd_write` / `fd_pwrite` into one binary-safe
/// buffer, or `None` on a guest FAULT.
fn gather(caller: &mut Caller<'_, EmbedderState>, iovs_ptr: i32, iovs_len: i32) -> Option<Vec<u8>> {
    let iovecs = read_iovecs(caller, iovs_ptr, iovs_len)?;
    let mut bytes = Vec::new();
    for (buf, len) in &iovecs {
        let chunk = read_bytes(caller, *buf as i32, *len as usize)?;
        bytes.extend_from_slice(&chunk);
    }
    Some(bytes)
}

/// The recorded byte count of a served write (the status `code`), or the
/// gathered length as a fallback if the record carries an error status.
fn served_write_code(rec_status: &EffectStatus, fallback: usize) -> i64 {
    match rec_status {
        EffectStatus::Ok { code, .. } => *code,
        EffectStatus::Err(_) => fallback as i64,
    }
}

/// `fd_write(fd, iovs, iovs_len, nwritten_out) -> errno`.
///
/// fd 1/2 append to [`wasi_stdout`](crate::embedder_vm::EmbedderState::wasi_stdout)
/// (the captured-stdout path); fd 0 is EBADF; fd >= 3 appends to the `InMemFs`.
/// On serve no real write happens and the recorded byte count is returned.
fn fd_write(
    mut caller: Caller<'_, EmbedderState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    nwritten_out: i32,
) -> i32 {
    let Some(bytes) = gather(&mut caller, iovs_ptr, iovs_len) else {
        return ERRNO_FAULT;
    };
    if fd == 1 || fd == 2 {
        caller.data_mut().wasi_stdout.extend_from_slice(&bytes);
        return if write_u32(&mut caller, nwritten_out, bytes.len() as u32) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }
    if fd == 0 {
        return ERRNO_BADF;
    }

    let seam = FsSeam::for_fd_write(&caller, fd, &bytes);
    if let Some(rec) = seam.served() {
        let code = served_write_code(&rec.status, bytes.len());
        return if write_u32(&mut caller, nwritten_out, code as u32) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }

    let n = caller.data_mut().fs.write(fd, &bytes);
    if n < 0 {
        return em2wasi(n);
    }
    // The input bytes are already carried by the effect (content addressing);
    // a write's output is empty.
    seam.finish(Vec::new(), n as i64);
    if write_u32(&mut caller, nwritten_out, n as u32) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// `fd_pwrite(fd, iovs, iovs_len, offset, nwritten_out) -> errno`.
///
/// Positional write: like [`fd_write`] on fd >= 3 but at `offset`, without
/// moving the fd's current offset. fd 0/1/2 behave as in [`fd_write`].
fn fd_pwrite(
    mut caller: Caller<'_, EmbedderState>,
    fd: i32,
    iovs_ptr: i32,
    iovs_len: i32,
    offset: i64,
    nwritten_out: i32,
) -> i32 {
    let Some(bytes) = gather(&mut caller, iovs_ptr, iovs_len) else {
        return ERRNO_FAULT;
    };
    if fd == 1 || fd == 2 {
        caller.data_mut().wasi_stdout.extend_from_slice(&bytes);
        return if write_u32(&mut caller, nwritten_out, bytes.len() as u32) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }
    if fd == 0 {
        return ERRNO_BADF;
    }

    let seam = FsSeam::for_fd_write(&caller, fd, &bytes);
    if let Some(rec) = seam.served() {
        let code = served_write_code(&rec.status, bytes.len());
        return if write_u32(&mut caller, nwritten_out, code as u32) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }

    let n = caller.data_mut().fs.pwrite(fd, &bytes, offset as u64);
    if n < 0 {
        return em2wasi(n);
    }
    seam.finish(Vec::new(), n as i64);
    if write_u32(&mut caller, nwritten_out, n as u32) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// `fd_seek(fd, offset, whence, newoffset_out) -> errno`. Pure fd state, not
/// journalled (deterministic given the prior ops). wasip1 whence
/// SET/CUR/END (0/1/2) matches `InMemFs::lseek` directly.
fn fd_seek(
    mut caller: Caller<'_, EmbedderState>,
    fd: i32,
    offset: i64,
    whence: i32,
    newoffset_out: i32,
) -> i32 {
    let r = caller.data_mut().fs.lseek(fd, offset, whence);
    if r < 0 {
        return em2wasi(r as i32);
    }
    if write_u64(&mut caller, newoffset_out, r as u64) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// `fd_close(fd) -> errno`. fd lifecycle, not journalled.
fn fd_close(mut caller: Caller<'_, EmbedderState>, fd: i32) -> i32 {
    let r = caller.data_mut().fs.close(fd);
    if r < 0 { em2wasi(r) } else { ERRNO_SUCCESS }
}

/// `fd_filestat_get(fd, filestat_out) -> errno`. Emits a [`FileOp::Stat`]; on
/// serve the recorded 64-byte struct is copied out verbatim.
fn fd_filestat_get(mut caller: Caller<'_, EmbedderState>, fd: i32, filestat_out: i32) -> i32 {
    let Some(abs) = caller.data().fs.fd_path(fd).map(str::to_owned) else {
        return ERRNO_BADF;
    };
    let seam = FsSeam::for_fd(&caller, FileOp::Stat, fd, Vec::new());
    if let Some(rec) = seam.served() {
        if rec.output.len() < FILESTAT_BYTES {
            return ERRNO_INVAL;
        }
        return if write_bytes(&mut caller, filestat_out, &rec.output[..FILESTAT_BYTES]) {
            ERRNO_SUCCESS
        } else {
            ERRNO_FAULT
        };
    }
    let Some(info) = caller.data_mut().fs.node_info(&abs) else {
        return ERRNO_NOENT;
    };
    let buf = write_filestat(info.ino, info.filetype, info.size);
    if !write_bytes(&mut caller, filestat_out, &buf) {
        return ERRNO_FAULT;
    }
    seam.finish(buf.to_vec(), 0);
    ERRNO_SUCCESS
}

/// `path_filestat_get(dirfd, flags, path, path_len, filestat_out) -> errno`.
/// Record-only [`FileOp::Stat`] via the resolved path.
fn path_filestat_get(
    mut caller: Caller<'_, EmbedderState>,
    dirfd: i32,
    _flags: i32,
    path_ptr: i32,
    path_len: i32,
    filestat_out: i32,
) -> i32 {
    let Some(raw) = read_bytes(&mut caller, path_ptr, path_len as u32 as usize) else {
        return ERRNO_FAULT;
    };
    let path = String::from_utf8_lossy(&raw).into_owned();
    let base = caller.data().fs.fd_path(dirfd).unwrap_or("/").to_owned();
    let abs = caller.data().fs.resolve(&base, &path);
    let seam = FsSeam::record_path(&caller, FileOp::Stat, &abs);
    let Some(info) = caller.data_mut().fs.node_info(&abs) else {
        return ERRNO_NOENT;
    };
    let buf = write_filestat(info.ino, info.filetype, info.size);
    if !write_bytes(&mut caller, filestat_out, &buf) {
        return ERRNO_FAULT;
    }
    seam.finish(buf.to_vec(), 0);
    ERRNO_SUCCESS
}

/// `path_create_directory(dirfd, path, path_len) -> errno`. Record-only
/// [`FileOp::Create`].
fn path_create_directory(
    mut caller: Caller<'_, EmbedderState>,
    dirfd: i32,
    path_ptr: i32,
    path_len: i32,
) -> i32 {
    let Some(raw) = read_bytes(&mut caller, path_ptr, path_len as u32 as usize) else {
        return ERRNO_FAULT;
    };
    let path = String::from_utf8_lossy(&raw).into_owned();
    let base = caller.data().fs.fd_path(dirfd).unwrap_or("/").to_owned();
    let abs = caller.data().fs.resolve(&base, &path);
    let seam = FsSeam::record_path(&caller, FileOp::Create, &abs);
    caller.data_mut().fs.mkdir_p(&abs);
    seam.finish(Vec::new(), 0);
    ERRNO_SUCCESS
}

/// `path_unlink_file(dirfd, path, path_len) -> errno`. Record-only
/// [`FileOp::Delete`].
fn path_unlink_file(
    mut caller: Caller<'_, EmbedderState>,
    dirfd: i32,
    path_ptr: i32,
    path_len: i32,
) -> i32 {
    let Some(raw) = read_bytes(&mut caller, path_ptr, path_len as u32 as usize) else {
        return ERRNO_FAULT;
    };
    let path = String::from_utf8_lossy(&raw).into_owned();
    let base = caller.data().fs.fd_path(dirfd).unwrap_or("/").to_owned();
    let abs = caller.data().fs.resolve(&base, &path);
    let seam = FsSeam::record_path(&caller, FileOp::Delete, &abs);
    let r = caller.data_mut().fs.unlink(&abs);
    seam.finish(Vec::new(), r as i64);
    if r < 0 { em2wasi(r) } else { ERRNO_SUCCESS }
}

/// `fd_prestat_get(fd, prestat_out) -> errno`. Advertises exactly one preopen:
/// the `InMemFs` root at fd 3 (`{ tag: 0 (dir), pr_name_len: 1 }`); every other
/// fd is EBADF so wasi-libc stops walking the preopen list. Not journalled.
fn fd_prestat_get(mut caller: Caller<'_, EmbedderState>, fd: i32, prestat_out: i32) -> i32 {
    if fd != 3 {
        return ERRNO_BADF;
    }
    let mut buf = [0u8; 8];
    buf[0] = 0; // tag: __WASI_PREOPENTYPE_DIR
    buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // pr_name_len = len("/")
    if write_bytes(&mut caller, prestat_out, &buf) {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

/// `fd_prestat_dir_name(fd, path, path_len) -> errno`. Writes the preopen name
/// `"/"` for fd 3. Not journalled.
fn fd_prestat_dir_name(
    mut caller: Caller<'_, EmbedderState>,
    fd: i32,
    path_ptr: i32,
    _path_len: i32,
) -> i32 {
    if fd != 3 {
        return ERRNO_BADF;
    }
    if write_bytes(&mut caller, path_ptr, b"/") {
        ERRNO_SUCCESS
    } else {
        ERRNO_FAULT
    }
}

// ---- linker wiring -----------------------------------------------------------

/// Wire the effect-wrapped `wasi_snapshot_preview1` **filesystem** imports (plus
/// the clock + random shadows from [`wire_effect_wrapped_wasi`]) over the stock
/// `wasmtime-wasi` ones.
///
/// This is the opt-in **capture** compile variant: shadowing is a compile-time
/// choice and a module is reused across runs, so the fs shadows must not land on
/// the production sealed module. [`wire_effect_wrapped_wasi`] (clock + random
/// only, stock fs) stays the setup for sealed runs, byte-identical to today, so
/// determinism cannot regress there; this variant is selected only when a
/// recording host is present. Call it from the `setup` callback of
/// [`EmbedderVm::compile`](crate::embedder_vm::EmbedderVm::compile) for a WASI
/// command module compiled with `wasi: true`; it runs after
/// `add_to_linker_sync`, so `allow_shadowing` (enabled by
/// [`wire_effect_wrapped_wasi`]) lets these definitions win.
pub fn wire_effect_wrapped_wasi_fs(linker: &mut EmbedderLinker<'_>) -> Result<()> {
    // Clock + random shadows, and `allow_shadowing(true)`.
    wire_effect_wrapped_wasi(linker)?;

    let m = "wasi_snapshot_preview1";
    linker.func_wrap(m, "path_open", path_open)?;
    linker.func_wrap(m, "fd_read", fd_read)?;
    linker.func_wrap(m, "fd_pread", fd_pread)?;
    linker.func_wrap(m, "fd_write", fd_write)?;
    linker.func_wrap(m, "fd_pwrite", fd_pwrite)?;
    linker.func_wrap(m, "fd_seek", fd_seek)?;
    linker.func_wrap(m, "fd_close", fd_close)?;
    linker.func_wrap(m, "fd_filestat_get", fd_filestat_get)?;
    linker.func_wrap(m, "path_filestat_get", path_filestat_get)?;
    linker.func_wrap(m, "path_create_directory", path_create_directory)?;
    linker.func_wrap(m, "path_unlink_file", path_unlink_file)?;
    linker.func_wrap(m, "fd_prestat_get", fd_prestat_get)?;
    linker.func_wrap(m, "fd_prestat_dir_name", fd_prestat_dir_name)?;
    Ok(())
}

#[cfg(test)]
mod tests;
