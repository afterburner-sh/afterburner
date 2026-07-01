// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Shared `wasi_snapshot_preview1` ABI helpers for the effect-wrapped command
//! substrate.
//!
//! Both shadow modules ([`crate::effect_wasi`] for clock + random and
//! [`crate::effect_wasi_fs`] for the filesystem imports) speak the same wasip1
//! ABI: positive `errno` return codes and little-endian guest-memory codecs
//! over the module's **exported** `memory`. Those two concerns live here once
//! so the two modules cannot drift on either the error numbers or the way a
//! guest pointer is read or written.
//!
//! WASI command modules **export** their linear memory as `"memory"` (unlike
//! the Emscripten modules that import it as `env.memory`), so every codec
//! resolves it via [`wasmtime::Caller::get_export`] rather than the
//! [`EmbedderState`] handle the Emscripten shims use.

use wasmtime::{Caller, Extern};

use crate::embedder_vm::EmbedderState;

// ---- wasip1 errno constants (positive; success = 0) -------------------------
//
// The wasip1 `errno` enum values (a positive `i32` the guest reads as the
// import's result). Shared by both shadow modules so the two agree on every
// number. `InMemFs` returns negative Linux-style errno; the fs module maps
// those to these via its `em2wasi` table.

/// wasip1 errno: success.
pub(crate) const ERRNO_SUCCESS: i32 = 0;
/// wasip1 errno: permission denied (`EACCES`).
pub(crate) const ERRNO_ACCES: i32 = 2;
/// wasip1 errno: bad file descriptor (`EBADF`).
pub(crate) const ERRNO_BADF: i32 = 8;
/// wasip1 errno: bad address - a guest pointer that does not map into memory
/// (`EFAULT`).
pub(crate) const ERRNO_FAULT: i32 = 21;
/// wasip1 errno: invalid argument (`EINVAL`).
pub(crate) const ERRNO_INVAL: i32 = 28;
/// wasip1 errno: is a directory (`EISDIR`).
pub(crate) const ERRNO_ISDIR: i32 = 31;
/// wasip1 errno: no such file or directory (`ENOENT`).
pub(crate) const ERRNO_NOENT: i32 = 44;
/// wasip1 errno: not a directory (`ENOTDIR`).
pub(crate) const ERRNO_NOTDIR: i32 = 54;

// ---- guest-memory codecs ----------------------------------------------------

/// Resolve the guest's exported linear memory, or `None` when the module
/// exports no `memory`.
fn memory(caller: &mut Caller<'_, EmbedderState>) -> Option<wasmtime::Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

/// Write `bytes` into the guest's exported linear memory at `ptr`
/// (u32 address space). Returns `false` when the module exports no `memory`
/// or the range is out of bounds.
pub(crate) fn write_bytes(caller: &mut Caller<'_, EmbedderState>, ptr: i32, bytes: &[u8]) -> bool {
    let Some(mem) = memory(caller) else {
        return false;
    };
    let data = mem.data_mut(&mut *caller);
    let start = ptr as u32 as usize;
    let Some(end) = start.checked_add(bytes.len()) else {
        return false;
    };
    if end > data.len() {
        return false;
    }
    data[start..end].copy_from_slice(bytes);
    true
}

/// Read `len` bytes out of the guest's exported linear memory at `ptr`.
/// Returns `None` (a guest FAULT) when there is no `memory` export or the
/// range is out of bounds.
pub(crate) fn read_bytes(
    caller: &mut Caller<'_, EmbedderState>,
    ptr: i32,
    len: usize,
) -> Option<Vec<u8>> {
    let mem = memory(caller)?;
    let data = mem.data(&*caller);
    let start = ptr as u32 as usize;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(data[start..end].to_vec())
}

/// Write a little-endian `u32` at `ptr`. `false` on an out-of-range pointer.
pub(crate) fn write_u32(caller: &mut Caller<'_, EmbedderState>, ptr: i32, val: u32) -> bool {
    write_bytes(caller, ptr, &val.to_le_bytes())
}

/// Write a little-endian `u64` at `ptr`. `false` on an out-of-range pointer.
pub(crate) fn write_u64(caller: &mut Caller<'_, EmbedderState>, ptr: i32, val: u64) -> bool {
    write_bytes(caller, ptr, &val.to_le_bytes())
}

/// Decode a wasip1 iovec array at `iovs_ptr` (`iovs_len` entries, each an
/// 8-byte `{ buf: u32, len: u32 }`) into a `(buf, len)` list. `None` (a guest
/// FAULT) when the array itself is out of range.
pub(crate) fn read_iovecs(
    caller: &mut Caller<'_, EmbedderState>,
    iovs_ptr: i32,
    iovs_len: i32,
) -> Option<Vec<(u32, u32)>> {
    let count = iovs_len as u32 as usize;
    let total = count.checked_mul(8)?;
    let raw = read_bytes(caller, iovs_ptr, total)?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 8;
        let buf = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
        let len = u32::from_le_bytes([raw[off + 4], raw[off + 5], raw[off + 6], raw[off + 7]]);
        out.push((buf, len));
    }
    Some(out)
}
