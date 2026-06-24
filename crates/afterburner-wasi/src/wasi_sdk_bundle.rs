// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Resolver for the self-contained C/C++ compiler payload that the build script
//! assembles (see `build.rs` + `wasi_sdk_payload.rs`).
//!
//! The build script fetches the stock toolchain release for the host platform,
//! unpacks the whole tree (the `clang`/`clang++` drivers, their resource dir,
//! and the WASI sysroot) under the workspace target, and writes a
//! `manifest.txt`. The dir path is baked in at compile time as
//! `AFTERBURNER_WASI_SDK_BUNDLE_DIR`.
//!
//! This module reads that manifest at runtime and returns the resolved paths,
//! so `burn run x.c` / `burn run x.cpp` compile with NO env vars and NO runtime
//! download. `WASI_SDK_PATH` remains an optional OVERRIDE. When the bundle is
//! absent (a build on an unsupported platform, or where the network was
//! unavailable), `resolve` returns `None` and the caller falls back to the
//! `WASI_SDK_PATH` path with an honest error.

use std::path::{Path, PathBuf};

/// Compile-time path to the cache dir the build script populates. Always set
/// (the build script emits it unconditionally); the dir may or may not be
/// populated depending on whether the host is supported and the network was
/// available at build time.
const BUNDLE_DIR: &str = env!("AFTERBURNER_WASI_SDK_BUNDLE_DIR");

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

/// Resolve the bundled C/C++ toolchain from the build-time cache, or `None` if
/// it was not assembled (so the caller falls back to `WASI_SDK_PATH`).
///
/// Validates that the manifest exists and the driver + sysroot it lists are
/// present; a half-populated cache resolves to `None` rather than a broken run.
pub fn resolve() -> Option<BundledWasiSdk> {
    let dir = Path::new(BUNDLE_DIR);
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
    // The driver and the sysroot must exist; otherwise the cache is partial.
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

    /// The compile-time bundle dir env is always set by the build script.
    #[test]
    fn bundle_dir_env_is_set() {
        assert!(
            !BUNDLE_DIR.is_empty(),
            "AFTERBURNER_WASI_SDK_BUNDLE_DIR must be baked in by build.rs"
        );
    }

    /// `resolve` never panics: it returns `Some` when the cache is fully
    /// populated (the normal dev/CI path on a supported host with network) and
    /// `None` when it is absent. Either is a valid, honest outcome.
    #[test]
    fn resolve_is_total() {
        match resolve() {
            Some(sdk) => {
                assert!(sdk.clang.exists(), "resolved clang must exist");
                assert!(sdk.sysroot.exists(), "resolved sysroot must exist");
                assert!(
                    sdk.sysroot.join("include").exists(),
                    "sysroot must carry an include tree: {}",
                    sdk.sysroot.display()
                );
            }
            None => { /* bundle not assembled in this build; acceptable */ }
        }
    }
}
