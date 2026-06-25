// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Emscripten `env.*` host-import layer for the embedder VM.
//!
//! ## Purpose
//!
//! Emscripten-compiled Wasm modules (`emcc -o out.wasm`) import a set of
//! functions from the `"env"` namespace that the embedder must supply.
//! This module wires those imports from Rust so any Emscripten-compiled
//! module can run under [`EmbedderVm`] via the standard
//! [`EmbedderLinker`] callback path.
//!
//! ## Scope (this increment)
//!
//! This is the **mechanism de-risk increment**, not a complete Pyodide-ready
//! env.* set. The functions implemented here are the minimal core that
//! standalone Emscripten modules require at import time. A complete
//! Pyodide run additionally needs the functions listed in the honesty
//! section below.
//!
//! ### Implemented env.* functions
//!
//! | Import name                  | Behaviour under sealed deterministic VM |
//! |------------------------------|-----------------------------------------|
//! | `emscripten_resize_heap`     | Grows the wasm linear memory to the requested byte size; returns 1 on success, 0 if the grow fails. Memory name is `"memory"` (Emscripten default). |
//! | `emscripten_memcpy_js`       | Copies `num` bytes from `src` to `dest` within linear memory (host-side memmove, handles overlap). |
//! | `emscripten_memcpy_big`      | Same as `emscripten_memcpy_js` (Emscripten routes large copies here). |
//! | `abort`                      | Traps with an `unreachable` trap (maps to `AfterburnerError::WasmTrap`). |
//! | `_abort_js`                  | Same - Emscripten's newer JS-layer abort shim. |
//! | `emscripten_get_now`         | Returns the deterministic virtual clock value (`VIRTUAL_NOW_MS`). No real wall clock - sealed and deterministic. |
//! | `emscripten_date_now`        | Returns the deterministic virtual epoch ms (`VIRTUAL_EPOCH_MS`). No real wall clock. |
//!
//! ### What Pyodide additionally needs (not in this increment)
//!
//! - Memory initialization: `__set_stack_limits`, `emscripten_stack_init`,
//!   `emscripten_stack_set_limits`, `__cxa_thread_atexit_impl`,
//!   `__c_longjmp` / `__cxa_throw`.
//! - Dynamic linking: `dlopen`, `dlsym`, `dlerror`, `dlclose`.
//! - File-system layer (MEMFS / IDBFS bridge): `emscripten_get_device_id`,
//!   the full `syscall_*` family (`__syscall_openat`, `__syscall_read`, etc.),
//!   `PATH` / `FS` / `Browser` JS globals routed as env imports.
//! - Async / event-loop shims: `emscripten_sleep`, `emscripten_set_main_loop`,
//!   `emscripten_async_call`, `emscripten_yield`.
//! - Network: `emscripten_websocket_*`, `emscripten_fetch_*`.
//! - Threading: `pthread_*` proxying, `emscripten_is_main_runtime_thread`.
//! - Python / CPython-specific: `__syscall_getcwd`, `__syscall_ioctl`,
//!   `__syscall_stat64`, `emscripten_console_log`, `py_*` env shims.
//!
//! These require enumerating against the real Pyodide `.wasm` import section
//! (via `wasm-objdump -x` or `wasmparser`), which requires the Pyodide
//! distribution. That is the follow-on increment.
//!
//! ## Determinism
//!
//! All clock functions return fixed virtual constants - no `std::time`, no
//! `CLOCK_MONOTONIC`, no host-side randomness. Two runs with the same module
//! and imports produce byte-identical results.
//!
//! ## Thread safety
//!
//! All functions are pure closures over compile-time constants. No shared
//! mutable state - no locks, no atomics.
//!
//! [`EmbedderVm`]: crate::embedder_vm::EmbedderVm
//! [`EmbedderLinker`]: crate::embedder_vm::EmbedderLinker

use afterburner_core::Result;
use wasmtime::{Caller, Memory, Trap};

use crate::embedder_vm::{EmbedderLinker, EmbedderState};

// ---- wasmtime::Result is anyhow::Result<T> in wasmtime 44 -------------------
// Host functions that need to trap return `wasmtime::Result<()>` and
// convert `Trap` via its `Into<anyhow::Error>` impl.
type WtResult<T> = wasmtime::Result<T>;

// ---- deterministic clock constants ------------------------------------------

/// Fixed virtual "now" returned by `emscripten_get_now` (milliseconds).
///
/// Value is a fixed point in time. Any non-negative finite f64 works; this
/// one is chosen to be recognizable in tests while still being a plausible
/// uptime value. Two runs always see the same value - sealed + deterministic.
pub const VIRTUAL_NOW_MS: f64 = 1_000.0;

/// Fixed virtual epoch returned by `emscripten_date_now` (milliseconds since
/// Unix epoch). Fixed to a deterministic point so two runs agree.
///
/// 2026-01-01 00:00:00 UTC in milliseconds.
pub const VIRTUAL_EPOCH_MS: f64 = 1_767_139_200_000.0;

/// The same epoch in nanoseconds, for WASI `clock_time_get` (which takes u64 ns).
pub const VIRTUAL_EPOCH_NS: u64 = 1_767_139_200_000_000_000;

// ---- memory helper ----------------------------------------------------------

/// Get the `"memory"` export from the caller's instance.
/// Emscripten modules export their linear memory under this name.
fn caller_memory(caller: &mut Caller<'_, EmbedderState>) -> Option<Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
}

// ---- public surface ---------------------------------------------------------

/// Wire the core Emscripten `env.*` import set into `linker`.
///
/// Call this from your `EmbedderVm::compile` setup callback to make any
/// Emscripten-compiled module's minimal required imports available:
///
/// ```no_run
/// use afterburner_wasi::{embedder_vm::EmbedderVm, emscripten_abi::add_emscripten_imports};
///
/// let vm = EmbedderVm::new().unwrap();
/// // compile an Emscripten wasm (bytes from disk / network at runtime):
/// // let module = vm.compile(&wasm_bytes, false, |linker| {
/// //     add_emscripten_imports(linker)
/// // }).unwrap();
/// ```
///
/// Returns an error if any import is already registered under its name
/// (wasmtime will reject a duplicate definition).
pub fn add_emscripten_imports(linker: &mut EmbedderLinker<'_>) -> Result<()> {
    // emscripten_resize_heap(requested_size: i32) -> i32
    //
    // Emscripten calls this when its heap allocator needs more memory.
    // `requested_size` is the new desired byte length of the linear memory.
    // We attempt a grow() via the wasmtime Memory API and return 1 on
    // success, 0 if the grow is refused (OOM, engine limit).
    //
    // The number of Wasm pages to add = ceil((requested - current) / 65536).
    // We use Caller so we can access the live memory object.
    linker.func_wrap(
        "env",
        "emscripten_resize_heap",
        |mut caller: Caller<'_, EmbedderState>, requested_size: i32| -> i32 {
            let Some(memory) = caller_memory(&mut caller) else {
                // No "memory" export - cannot grow; return failure.
                return 0;
            };
            let current_bytes = memory.data_size(&caller);
            let wanted = requested_size as u32 as usize;
            if wanted <= current_bytes {
                // Already large enough.
                return 1;
            }
            let extra_bytes = wanted - current_bytes;
            // Round up to Wasm page boundary (64 KiB per page).
            let pages = extra_bytes.div_ceil(65_536) as u64;
            match memory.grow(&mut caller, pages) {
                Ok(_) => 1,
                Err(_) => 0,
            }
        },
    )?;

    // emscripten_memcpy_js(dest: i32, src: i32, num: i32)
    //
    // In-memory copy entirely within wasm linear memory. We perform it on
    // the host side via a host-side memmove (handles overlapping regions).
    // Emscripten routes BOTH small and large copies through here (the "big"
    // variant is an alias for large num values in older toolchain versions).
    linker.func_wrap(
        "env",
        "emscripten_memcpy_js",
        |mut caller: Caller<'_, EmbedderState>, dest: i32, src: i32, num: i32| {
            let Some(memory) = caller_memory(&mut caller) else {
                return;
            };
            let d = dest as u32 as usize;
            let s = src as u32 as usize;
            let n = num as u32 as usize;
            let mem = memory.data_mut(&mut caller);
            // Guard: both ranges must be in bounds.
            if s.checked_add(n).is_some_and(|e| e <= mem.len())
                && d.checked_add(n).is_some_and(|e| e <= mem.len())
            {
                mem.copy_within(s..s + n, d);
            }
            // Out-of-bounds: no-op rather than trap; mirrors emscripten's
            // SAFE_HEAP=0 default where the C `memcpy` itself would segfault.
        },
    )?;

    // emscripten_memcpy_big(dest: i32, src: i32, num: i32)
    //
    // Alias for large copies in the Emscripten runtime. Identical semantics
    // to emscripten_memcpy_js.
    linker.func_wrap(
        "env",
        "emscripten_memcpy_big",
        |mut caller: Caller<'_, EmbedderState>, dest: i32, src: i32, num: i32| {
            let Some(memory) = caller_memory(&mut caller) else {
                return;
            };
            let d = dest as u32 as usize;
            let s = src as u32 as usize;
            let n = num as u32 as usize;
            let mem = memory.data_mut(&mut caller);
            if s.checked_add(n).is_some_and(|e| e <= mem.len())
                && d.checked_add(n).is_some_and(|e| e <= mem.len())
            {
                mem.copy_within(s..s + n, d);
            }
        },
    )?;

    // abort()
    //
    // Emscripten calls this when a fatal error is detected at the C level
    // (SIGABRT, assertion failure, etc.). The correct behaviour in a sealed
    // VM is to halt execution immediately with a trap. Wasmtime surfaces
    // the Trap as AfterburnerError::WasmTrap at the run() call site.
    linker.func_wrap(
        "env",
        "abort",
        |_caller: Caller<'_, EmbedderState>| -> WtResult<()> {
            // Trap::UnreachableCodeReached implements Into<anyhow::Error>
            // (wasmtime 44), so ? converts it to a wasmtime::Result Err.
            Err(Trap::UnreachableCodeReached.into())
        },
    )?;

    // _abort_js()
    //
    // Newer Emscripten toolchain versions (post 3.1.x) route the abort
    // through a JS-layer shim named `_abort_js`. Semantics are identical.
    linker.func_wrap(
        "env",
        "_abort_js",
        |_caller: Caller<'_, EmbedderState>| -> WtResult<()> {
            Err(Trap::UnreachableCodeReached.into())
        },
    )?;

    // emscripten_get_now() -> f64
    //
    // High-resolution timer (milliseconds, possibly sub-ms precision).
    // In a sealed deterministic VM there is no wall clock: we return a
    // fixed constant so two runs always produce the same value.
    //
    // vertexia: fixed virtual clock; upgrade path is a per-Store monotonic
    // counter in EmbedderState if callers need time-passage semantics.
    linker.func_wrap(
        "env",
        "emscripten_get_now",
        |_caller: Caller<'_, EmbedderState>| -> f64 { VIRTUAL_NOW_MS },
    )?;

    // emscripten_date_now() -> f64
    //
    // Milliseconds since Unix epoch (equivalent to Date.now() in the
    // Emscripten JS shell). Same sealed-deterministic treatment as get_now.
    //
    // vertexia: fixed virtual epoch; upgrade path is a per-run seed in
    // EmbedderState passed by the embedder for reproducible timestamps.
    linker.func_wrap(
        "env",
        "emscripten_date_now",
        |_caller: Caller<'_, EmbedderState>| -> f64 { VIRTUAL_EPOCH_MS },
    )?;

    Ok(())
}

// ---- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests;
