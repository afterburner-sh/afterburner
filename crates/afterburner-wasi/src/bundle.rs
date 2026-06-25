// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Runtime entry to the shared bundle fetch engine, plus the process-global
//! progress reporter the CLI installs.
//!
//! The fetch + verify + translate + cache logic lives in the crate-root
//! `bundle_fetch.rs`, which is `#[path]`-included by BOTH this module and the
//! build script so there is exactly one copy (no drift between the opt-in
//! `BURN_PREFETCH=1` build-time prefetch and the default lazy runtime fetch into
//! `~/.burn`). This module adds the runtime-only pieces: the global reporter
//! (set once by the `burn` CLI so the sunburst gradient bar renders during a
//! cold download) and a `NoProgress` default for every other caller.
//!
//! The bundle resolvers (`pyodide_bundle`, `ruby_bundle`, `wasi_sdk_bundle`)
//! call the `ensure_*` functions here on the `burn run` path: a populated bundle
//! under `~/.burn` is a no-op; a missing one is fetched, with progress, then the
//! resolver reads the populated dir.

use std::path::PathBuf;
use std::sync::OnceLock;

#[path = "../bundle_fetch.rs"]
mod engine;

pub use engine::{
    BundleProgress, NoProgress, burn_home, ensure_pyodide, ensure_ruby, ensure_wasi_sdk,
    pyodide_dir, pyodide_manifest_ok, ruby_dir, ruby_manifest_ok, wasi_sdk_dir,
    wasi_sdk_manifest_ok,
};
#[cfg(feature = "embed-core")]
pub use engine::{PYODIDE_PYTHON_XY, PYODIDE_VERSION};
#[cfg(feature = "embed-ruby")]
pub use engine::{RUBY_ABI_VERSION, RUBY_RELEASE};

/// The process-global progress reporter. The `burn` CLI installs one (rendering
/// the gradient bar via `cli::style`) before running a script; every other
/// caller (a library embed, a test, the build script) leaves it unset and the
/// fetch renders nothing. A global avoids threading a reporter through the deep
/// `resolve()` call chain, mirroring how the install pool keeps rendering in the
/// CLI while the fetch logic stays here.
static REPORTER: OnceLock<Box<dyn BundleProgress>> = OnceLock::new();

/// Install the global progress reporter. Idempotent: the first call wins (a
/// second is a silent no-op), since a process has one stderr to render on.
pub fn set_progress_reporter(reporter: Box<dyn BundleProgress>) {
    let _ = REPORTER.set(reporter);
}

/// The installed reporter, or a `NoProgress` no-op when none was set. Returned
/// as a reference the `ensure_*` callers pass straight to the engine.
fn reporter() -> &'static dyn BundleProgress {
    static NONE: NoProgress = NoProgress;
    REPORTER.get().map(|b| b.as_ref()).unwrap_or(&NONE)
}

/// Resolve `~/.burn` (or `$BURN_HOME`), returning `None` when no home directory
/// can be located so the resolver falls back to its env-var override.
pub fn home() -> Option<PathBuf> {
    burn_home()
}

/// Ensure the Python runtime bundle under `~/.burn`, rendering progress via the
/// installed reporter. A thin wrapper that supplies the global reporter so the
/// resolver does not own progress plumbing.
///
/// With the `embed-core` feature, a fetch failure (no network, no `wasm-opt`)
/// falls back to materializing the embedded core (the main wasm + stdlib baked
/// into the binary), so basic Python runs offline; the error is only returned
/// when even that is unavailable. Without the feature, a fetch failure is
/// returned verbatim for the caller's honest fallback.
pub fn ensure_pyodide_bundle() -> Result<PathBuf, String> {
    let home = home().ok_or_else(|| {
        "cannot locate the Afterburner home dir: neither BURN_HOME nor a home directory (HOME / USERPROFILE) is set. Set \
         BURN_PYTHON_RUNTIME to a prebuilt runtime dir, or set HOME (USERPROFILE on Windows)."
            .to_string()
    })?;
    match ensure_pyodide(&home, reporter()) {
        Ok(()) => Ok(pyodide_dir(&home)),
        Err(fetch_err) => embed_core_fallback(&home, fetch_err),
    }
}

/// With `embed-core`, write the embedded core into `~/.burn` so offline Python
/// works when the network fetch failed; without it, propagate the fetch error.
#[cfg(feature = "embed-core")]
fn embed_core_fallback(home: &std::path::Path, fetch_err: String) -> Result<PathBuf, String> {
    crate::pyodide_embed::materialize_core(home).map_err(|embed_err| {
        // Both paths failed: surface the fetch error (the actionable one) and
        // note the embed attempt, so the user is not misled about which broke.
        format!("{fetch_err} (embedded-core fallback also failed: {embed_err})")
    })
}

/// Without `embed-core`, there is nothing to fall back to: propagate the error.
#[cfg(not(feature = "embed-core"))]
fn embed_core_fallback(_home: &std::path::Path, fetch_err: String) -> Result<PathBuf, String> {
    Err(fetch_err)
}

/// Ensure the Ruby runtime bundle under `~/.burn`, rendering progress.
///
/// With the `embed-ruby` feature, a fetch failure (no network) falls back to
/// materializing the embedded interpreter + stdlib (baked into the binary), so
/// Ruby runs offline; the error is only returned when even that is unavailable.
/// Without the feature, a fetch failure is returned verbatim.
pub fn ensure_ruby_bundle() -> Result<PathBuf, String> {
    let home = home().ok_or_else(|| {
        "cannot locate the Afterburner home dir: neither BURN_HOME nor a home directory (HOME / USERPROFILE) is set. Set \
         BURN_RUBY_RUNTIME to a prebuilt runtime dir, or set HOME (USERPROFILE on Windows)."
            .to_string()
    })?;
    match ensure_ruby(&home, reporter()) {
        Ok(()) => Ok(ruby_dir(&home)),
        Err(fetch_err) => embed_ruby_fallback(&home, fetch_err),
    }
}

/// With `embed-ruby`, materialize the embedded runtime into `~/.burn` so offline
/// Ruby works when the network fetch failed; without it, propagate the error.
#[cfg(feature = "embed-ruby")]
fn embed_ruby_fallback(home: &std::path::Path, fetch_err: String) -> Result<PathBuf, String> {
    crate::ruby_embed::materialize_core(home).map_err(|embed_err| {
        format!("{fetch_err} (embedded-ruby fallback also failed: {embed_err})")
    })
}

/// Without `embed-ruby`, propagate the fetch error directly.
#[cfg(not(feature = "embed-ruby"))]
fn embed_ruby_fallback(_home: &std::path::Path, fetch_err: String) -> Result<PathBuf, String> {
    Err(fetch_err)
}

/// Ensure the C/C++ toolchain bundle under `~/.burn`, rendering progress.
pub fn ensure_wasi_sdk_bundle() -> Result<PathBuf, String> {
    let home = home().ok_or_else(|| {
        "cannot locate the Afterburner home dir: neither BURN_HOME nor a home directory (HOME / USERPROFILE) is set. Set \
         WASI_SDK_PATH to a wasi-sdk install, or set HOME (USERPROFILE on Windows)."
            .to_string()
    })?;
    ensure_wasi_sdk(&home, reporter())?;
    Ok(wasi_sdk_dir(&home))
}
