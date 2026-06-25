// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Opt-in tracing for the Emscripten/Pyodide side-module loader.
//!
//! The dynamic-linking path (dlopen of wheel `.so` files, GOT resolution, data
//! relocs) is intricate, so it carries a dense diagnostic trail. That trail is
//! invaluable while bringing a Pyodide version up, but it must be SILENT on the
//! production `burn run x.py` path - a user running a numpy/pandas script must
//! not see thousands of loader lines on stderr.
//!
//! The `pyo_trace!` macro writes to stderr only when `BURN_PYODIDE_TRACE` is
//! set (any value). It is checked once and cached, so the steady-state cost when
//! tracing is off is a single relaxed atomic load per call - no env lookup, no
//! format.

use std::sync::atomic::{AtomicU8, Ordering};

/// 0 = not yet checked, 1 = off, 2 = on. Cached so a hot loader loop pays only
/// a relaxed load, never a repeated `std::env::var`.
static TRACE: AtomicU8 = AtomicU8::new(0);

/// Whether loader tracing is enabled (`BURN_PYODIDE_TRACE` set). Cached.
#[inline]
pub fn enabled() -> bool {
    match TRACE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let on = std::env::var_os("BURN_PYODIDE_TRACE").is_some();
            TRACE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

/// `eprintln!`, but only when [`enabled`] (i.e. `BURN_PYODIDE_TRACE` is set).
/// Used across the side-module loader so its diagnostics are opt-in and the
/// production Python runtime stays quiet.
#[macro_export]
macro_rules! pyo_trace {
    ($($arg:tt)*) => {
        if $crate::pyodide_trace::enabled() {
            eprintln!($($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `enabled()` reflects the env at first call and then stays cached.
    #[test]
    fn enabled_is_cached_and_total() {
        // Whatever the ambient value, the function must not panic and must be
        // stable across calls within a process.
        let a = enabled();
        let b = enabled();
        assert_eq!(a, b, "enabled() must be stable once cached");
    }
}
