// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Resolver for the self-contained C/C++ toolchain payload, fetched lazily into
//! `~/.burn` on first use.
//!
//! On a miss, [`crate::bundle::ensure_wasi_sdk_bundle`] downloads the stock
//! toolchain release for the host platform from its pinned, sha256-checked
//! source, unpacks the whole tree (the `clang`/`clang++` drivers, their resource
//! dir, and the WASI sysroot) into `~/.burn/wasi-sdk-<tag>/`, and writes a
//! `manifest.txt`. A populated bundle is a cache hit (no network). This module
//! reads that manifest and returns the resolved paths, so `burn run x.c` /
//! `burn run x.cpp` compile with NO env vars beyond the first-use download.
//!
//! `WASI_SDK_PATH` remains an optional OVERRIDE handled one level up in the
//! CLI's `find_wasi_sdk`; this resolver is the default path. When the fetch
//! fails (an unsupported host, no network), `resolve` returns `None` and the
//! caller falls back to the `WASI_SDK_PATH` path with an honest error.

use std::path::{Path, PathBuf};

/// A resolved, ready-to-use C/C++ toolchain: absolute paths to the bundled
/// `clang`/`clang++` drivers and the WASI sysroot to compile against.
#[derive(Debug, Clone)]
pub struct BundledWasiSdk {
    /// The bundled `clang` driver (a host executable; its config auto-selects
    /// the sysroot, but the compile path passes `--sysroot` explicitly too).
    pub clang: PathBuf,
    /// The bundled `clang++` driver.
    pub clangxx: PathBuf,
    /// The WASI sysroot (`share/wasi-sysroot`) for `--sysroot`.
    pub sysroot: PathBuf,
}

/// Resolve the bundled C/C++ toolchain, fetching it into `~/.burn` on a miss, or
/// `None` when neither the fetch nor a populated bundle is available (so the
/// caller falls back to `WASI_SDK_PATH`).
///
/// Ensures the bundle (a cache hit is a no-op; a miss downloads with the gradient
/// bar), then validates that the driver + sysroot the manifest lists are present;
/// a half-populated bundle resolves to `None` rather than a broken run.
pub fn resolve() -> Option<BundledWasiSdk> {
    // Fetch into `~/.burn` on a miss (no-op on a hit). A failure (unsupported
    // host, no network) is reported by the caller's honest fallback error, so
    // swallow it to `None` and let the WASI_SDK_PATH path take over.
    let dir = crate::bundle::ensure_wasi_sdk_bundle().ok()?;
    resolve_dir(&dir)
}

/// Parse the manifest in a populated bundle `dir` into resolved paths, returning
/// `None` when the manifest is absent, malformed, or lists a missing driver or
/// sysroot. Pure (no network, no env): the fetch happened in [`resolve`].
fn resolve_dir(dir: &Path) -> Option<BundledWasiSdk> {
    let text = std::fs::read_to_string(dir.join("manifest.txt")).ok()?;

    let mut clang = None;
    let mut clangxx = None;
    let mut sysroot = None;

    for line in text.lines() {
        let (key, val) = line.split_once('=')?;
        match key {
            "clang" => clang = Some(dir.join(val)),
            "clangxx" => clangxx = Some(dir.join(val)),
            "sysroot" => sysroot = Some(dir.join(val)),
            _ => {}
        }
    }

    let clang = clang?;
    let clangxx = clangxx?;
    let sysroot = sysroot?;
    // The driver and the sysroot must exist; otherwise the bundle is partial.
    if !clang.exists() || !sysroot.exists() {
        return None;
    }

    Some(BundledWasiSdk {
        clang,
        clangxx,
        sysroot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a complete fixture bundle under `dir`, exercising `resolve_dir`
    /// without a network fetch or env mutation (parallel-safe).
    fn write_fixture(dir: &Path) {
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("share/wasi-sysroot/include")).unwrap();
        std::fs::write(dir.join("bin/clang"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.join("bin/clang++"), b"#!/bin/sh\n").unwrap();
        std::fs::write(
            dir.join("manifest.txt"),
            "release=wasi-sdk-33\nversion=33.0\nclang=bin/clang\nclangxx=bin/clang++\nsysroot=share/wasi-sysroot\n",
        )
        .unwrap();
    }

    /// A complete bundle dir resolves to the driver + sysroot.
    #[test]
    fn resolves_a_complete_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path());
        let sdk = resolve_dir(tmp.path()).expect("a complete bundle resolves");
        assert!(sdk.clang.exists());
        assert!(sdk.sysroot.exists());
        assert!(sdk.sysroot.join("include").exists());
    }

    /// A bundle missing the sysroot resolves to `None`.
    #[test]
    fn partial_bundle_resolves_none() {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path());
        std::fs::remove_dir_all(tmp.path().join("share/wasi-sysroot")).unwrap();
        assert!(resolve_dir(tmp.path()).is_none());
    }

    /// An absent manifest resolves to `None`, never a panic.
    #[test]
    fn missing_manifest_resolves_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(resolve_dir(tmp.path()).is_none());
    }
}
