// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Resolver for the self-contained Python runtime payload, fetched lazily into
//! `~/.burn` on first use.
//!
//! On a miss, [`crate::bundle::ensure_pyodide_bundle`] downloads the stock
//! Python runtime main wasm, the stdlib, and the pandas dependency closure
//! (numpy, six, python-dateutil, pytz, pandas) from their pinned, sha256-checked
//! sources, exnref-translates the wasm and each wheel `.so` locally, and
//! populates `~/.burn/pyodide-<ver>/` atomically with a `manifest.txt`. A
//! populated bundle is a cache hit (no network). This module reads that manifest
//! and returns the resolved paths, so `burn run x.py` (and the REPL, and a
//! programmatic embed calling [`crate::pyodide_runner::resolve_runtime`]) run
//! numpy + pandas with NO env vars beyond the first-use download.
//!
//! `BURN_PYTHON_RUNTIME` / `BURN_WHEELS` remain optional OVERRIDES handled one
//! level up in [`crate::pyodide_runner::resolve_runtime`]; this resolver is the
//! default path. When the fetch fails (no network, no `wasm-opt`), `resolve`
//! returns `None` and the caller falls back to the env-var path with an honest
//! error.

use std::path::{Path, PathBuf};

/// A resolved, ready-to-run Python payload: absolute paths to the exnref main
/// wasm, the stdlib zip, the wheels (in dependency order), and the interpreter
/// `X.Y` version the stdlib + wheels were built for.
#[derive(Debug, Clone)]
pub struct BundledRuntime {
    /// The exnref-translated main wasm.
    pub wasm_path: PathBuf,
    /// `python_stdlib.zip`.
    pub stdlib_path: PathBuf,
    /// Wheel paths in dependency (load) order. Empty for a stdlib-only bundle.
    pub wheels: Vec<PathBuf>,
    /// Interpreter `X.Y`, e.g. `"3.13"`, for the stdlib mount + soabi tag.
    pub python_xy: String,
}

/// Resolve the Python payload, fetching it into `~/.burn` on a miss, or `None`
/// when neither the fetch nor a populated bundle is available (so the caller
/// falls back to `BURN_PYTHON_RUNTIME`).
///
/// Ensures the bundle (a cache hit is a no-op; a miss downloads with the gradient
/// bar), then validates that every file the manifest lists is present; a
/// half-populated bundle resolves to `None` rather than a broken run.
pub fn resolve() -> Option<BundledRuntime> {
    // Fetch into `~/.burn` on a miss (no-op on a hit). A failure here (no
    // network, no `wasm-opt`) is reported by the caller's honest fallback error,
    // so swallow it to `None` and let the env-var path take over.
    let dir = crate::bundle::ensure_pyodide_bundle().ok()?;
    resolve_dir(&dir)
}

/// Parse the manifest in a populated bundle `dir` into resolved paths, returning
/// `None` when the manifest is absent, malformed, or lists a missing file. Pure
/// (no network, no env): the fetch happened in [`resolve`].
fn resolve_dir(dir: &Path) -> Option<BundledRuntime> {
    let text = std::fs::read_to_string(dir.join("manifest.txt")).ok()?;

    let mut wasm_path = None;
    let mut stdlib_path = None;
    let mut wheels = Vec::new();
    let mut python_xy = String::from("3.13");

    for line in text.lines() {
        let (key, val) = line.split_once('=')?;
        match key {
            "python" => python_xy = val.to_owned(),
            "wasm" => wasm_path = Some(dir.join(val)),
            "stdlib" => stdlib_path = Some(dir.join(val)),
            "wheel" => wheels.push(dir.join(val)),
            _ => {}
        }
    }

    let wasm_path = wasm_path?;
    let stdlib_path = stdlib_path?;
    // Every listed file must exist; otherwise the bundle is partial.
    if !wasm_path.exists() || !stdlib_path.exists() || wheels.iter().any(|w| !w.exists()) {
        return None;
    }

    Some(BundledRuntime {
        wasm_path,
        stdlib_path,
        wheels,
        python_xy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a complete fixture bundle under `dir`, so `resolve_dir` can be
    /// exercised without a network fetch or any env mutation (parallel-safe).
    fn write_fixture(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("pyodide-exnref.wasm"), b"wasm").unwrap();
        std::fs::write(dir.join("python_stdlib.zip"), b"zip").unwrap();
        std::fs::write(dir.join("numpy.exnref.whl"), b"whl").unwrap();
        std::fs::write(
            dir.join("manifest.txt"),
            "version=0\npython=3.13\nwasm=pyodide-exnref.wasm\nstdlib=python_stdlib.zip\nwheel=numpy.exnref.whl\n",
        )
        .unwrap();
    }

    /// A complete bundle dir resolves to every listed path (the cache-hit shape:
    /// `resolve` is `ensure_*` + this).
    #[test]
    fn resolves_a_complete_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path());
        let rt = resolve_dir(tmp.path()).expect("a complete bundle resolves");
        assert!(rt.wasm_path.exists());
        assert!(rt.stdlib_path.exists());
        assert_eq!(rt.python_xy, "3.13");
        assert_eq!(rt.wheels.len(), 1);
    }

    /// A bundle whose manifest lists a missing file resolves to `None` (a partial
    /// cache never reads back as complete).
    #[test]
    fn partial_bundle_resolves_none() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path());
        std::fs::remove_file(tmp.path().join("python_stdlib.zip")).unwrap();
        assert!(resolve_dir(tmp.path()).is_none());
    }

    /// An absent manifest resolves to `None`, never a panic.
    #[test]
    fn missing_manifest_resolves_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(resolve_dir(tmp.path()).is_none());
    }
}
