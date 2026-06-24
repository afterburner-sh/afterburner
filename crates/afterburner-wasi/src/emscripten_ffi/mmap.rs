// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! File-backed `mmap` / `munmap` / `msync` host functions.
//!
//! Emscripten's libc handles anonymous mappings (`MAP_ANONYMOUS`) entirely
//! inside the guest (musl `mmap` -> `memalign`); it only calls these host
//! functions for FILE-backed mappings of a real fd. The reference `_mmap_js`
//! does `FS.mmap(stream, len, offset, prot, flags)`, which for a regular MEMFS
//! file allocates `len` bytes, copies the file region `[offset, offset+len)`
//! into it, and returns that pointer with `allocated = true`.
//!
//! This port reproduces that: it allocates `len` bytes via the guest allocator,
//! positionally reads the mapped file region from the [`InMemFs`] into the
//! buffer, writes the result pointer and the `allocated` flag, and returns 0.
//! `MAP_PRIVATE` mappings (the only kind CPython's importer and `mmap.mmap`
//! request for a read) need no write-back. A `PROT_WRITE | MAP_SHARED` mapping
//! would need `msync` to flush; `_msync_js` copies the buffer back to the file.
//!
//! Determinism: the buffer comes from the guest's deterministic bump allocator
//! and the file bytes are fixed; there is no clock, randomness, or host address
//! exposure. The returned pointer is a guest offset, identical across runs.

use afterburner_core::{AfterburnerError, Result};
use wasmtime::{Caller, Linker};

use crate::{embedder_vm::EmbedderState, pyo_trace};

use super::{guest_malloc, mem_write, write_u32};

/// errno: bad file descriptor.
const EBADF: i32 = 8;
/// errno: invalid argument.
const EINVAL: i32 = 22;
/// errno: cannot allocate memory.
const ENOMEM: i32 = 12;

/// `PROT_WRITE` (mmap prot bit), used to decide whether `munmap` must flush.
const PROT_WRITE: i32 = 2;

/// Wire `_mmap_js`, `_munmap_js`, `_msync_js`. These carry an i64 offset
/// parameter and so cannot be expressed via the integer-syscall macros; they are
/// wired directly here.
pub(super) fn wire_mmap(linker: &mut Linker<EmbedderState>) -> Result<()> {
    linker.allow_shadowing(true);

    linker
        .func_wrap("env", "_mmap_js", mmap_js)
        .map_err(|e| AfterburnerError::Engine(format!("_mmap_js: {e}")))?;
    linker
        .func_wrap("env", "_munmap_js", munmap_js)
        .map_err(|e| AfterburnerError::Engine(format!("_munmap_js: {e}")))?;
    linker
        .func_wrap("env", "_msync_js", msync_js)
        .map_err(|e| AfterburnerError::Engine(format!("_msync_js: {e}")))?;
    Ok(())
}

/// `_mmap_js(len, prot, flags, fd, offset, allocated, addr) -> 0 | -errno`.
///
/// Allocates `len` guest bytes, copies the file region into them, and writes the
/// pointer to `*addr` and `1` to `*allocated`. The guest pointers `allocated`
/// and `addr` are bounds-checked by [`write_u32`]; an out-of-range fd or a
/// non-file fd returns `-EBADF` so the guest sees `MAP_FAILED` rather than a
/// bogus mapping.
#[allow(clippy::too_many_arguments)]
fn mmap_js(
    mut caller: Caller<'_, EmbedderState>,
    len: i32,
    _prot: i32,
    _flags: i32,
    fd: i32,
    offset: i64,
    allocated: i32,
    addr: i32,
) -> wasmtime::Result<i32> {
    let len_u = len as u32;
    if len <= 0 {
        return Ok(-EINVAL);
    }
    if !caller.data().fs.is_fs_fd(fd) {
        pyo_trace!("[mmap] _mmap_js fd={fd} not a file fd -> EBADF");
        return Ok(-EBADF);
    }

    // Allocate the mapping buffer from the guest allocator (FS.mmap's mmapAlloc).
    let ptr = guest_malloc(&mut caller, len_u)?;
    if ptr == 0 {
        return Ok(-ENOMEM);
    }

    // Positional read of [offset, offset+len) from the file into a host buffer;
    // bytes past EOF stay zero (musl mmap semantics for a short file).
    let mut buf = vec![0u8; len_u as usize];
    let n = caller.data_mut().fs.pread(fd, &mut buf, offset as u64);
    if n < 0 {
        let _ = super::guest_free(&mut caller, ptr);
        pyo_trace!("[mmap] _mmap_js pread fd={fd} off={offset} -> errno {}", -n);
        return Ok(n); // negative errno
    }

    mem_write(&mut caller, ptr, &buf)?;
    write_u32(&mut caller, allocated as u32, 1)?;
    write_u32(&mut caller, addr as u32, ptr)?;
    pyo_trace!("[mmap] _mmap_js len={len} fd={fd} off={offset} -> ptr={ptr:#x} (read {n} bytes)");
    Ok(0)
}

/// `_munmap_js(addr, len, prot, flags, fd, offset) -> 0 | -errno`.
///
/// For a writable mapping, flush the buffer back to the file (msync), then the
/// guest's libc frees the buffer. Read-only / private mappings need nothing.
fn munmap_js(
    mut caller: Caller<'_, EmbedderState>,
    addr: i32,
    len: i32,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> wasmtime::Result<i32> {
    if prot & PROT_WRITE != 0 {
        return do_msync(&mut caller, addr, len, flags, fd, offset);
    }
    Ok(0)
}

/// `_msync_js(addr, len, prot, flags, fd, offset) -> 0 | -errno`.
fn msync_js(
    mut caller: Caller<'_, EmbedderState>,
    addr: i32,
    len: i32,
    _prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> wasmtime::Result<i32> {
    do_msync(&mut caller, addr, len, flags, fd, offset)
}

/// Copy `len` bytes of the mapping at guest `addr` back into the file at
/// `offset` (the write-back half of a writable file mapping). Bounds-checked by
/// [`mem_read`][super::mem_read]; an invalid fd returns `-EBADF`.
fn do_msync(
    caller: &mut Caller<'_, EmbedderState>,
    addr: i32,
    len: i32,
    _flags: i32,
    fd: i32,
    offset: i64,
) -> wasmtime::Result<i32> {
    if len <= 0 {
        return Ok(0);
    }
    if !caller.data().fs.is_fs_fd(fd) {
        return Ok(-EBADF);
    }
    let bytes = super::mem_read(caller, addr as u32, len as usize)?;
    let n = caller.data_mut().fs.pwrite(fd, &bytes, offset as u64);
    if n < 0 {
        return Ok(n);
    }
    pyo_trace!("[mmap] msync addr={addr:#x} len={len} fd={fd} off={offset} flushed {n}");
    Ok(0)
}
