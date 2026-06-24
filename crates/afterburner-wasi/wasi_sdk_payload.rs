// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Build-time assembly of the self-contained C/C++ compiler payload.
//!
//! Fetches the stock toolchain release tarball for the HOST platform from the
//! `WebAssembly/wasi-sdk` GitHub release (sha256-pinned per platform), unpacks
//! it verbatim (stripping the leading version dir) into a stable cache dir under
//! the workspace target, and records a `manifest.txt`. Unlike the Pyodide and
//! ruby.wasm payloads, the artifact is a native HOST toolchain (a `clang` and
//! its companion resource dir, headers, and the WASI sysroot), so the whole tree
//! is unpacked preserving symlinks and executable permissions: the bundled
//! `clang`/`clang++` resolve their resource dir and `--sysroot` by relative path
//! exactly as the stock SDK intends (its `bin/clang.cfg` carries
//! `--sysroot=<CFGDIR>/../share/wasi-sysroot`), so `burn run x.c` / `burn run
//! x.cpp` compile with no env vars and no runtime download.
//!
//! The runtime reads `AFTERBURNER_WASI_SDK_BUNDLE_DIR` (a `cargo:rustc-env`
//! emitted here) plus the `manifest.txt` the dir contains. Nothing is committed
//! to git and nothing is downloaded at runtime. The fetch SKIPS cleanly (a
//! `cargo:warning`, never a panic) when the host platform is unsupported or the
//! network is unreachable; the C/C++ compile then falls back to the
//! `WASI_SDK_PATH` override path with an honest error, never a fake success.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::sha256_hex;

/// wasi-sdk release the bundled toolchain tracks: the `WebAssembly/wasi-sdk`
/// GitHub release `wasi-sdk-33`, version `33.0`. The release tag and the version
/// embedded in the asset names differ (tag `wasi-sdk-33`, version `33.0`).
const RELEASE_TAG: &str = "wasi-sdk-33";
const VERSION: &str = "33.0";

/// One host platform's stock asset and its pinned sha256.
struct PlatformAsset {
    /// `std::env::consts::ARCH` for the host this asset targets.
    arch: &'static str,
    /// `std::env::consts::OS` for the host this asset targets.
    os: &'static str,
    /// Stock release asset file name: `wasi-sdk-<VERSION>-<a>-<o>.tar.gz`.
    file: &'static str,
    /// sha256 of the STOCK download (GitHub release asset, immutable).
    sha256: &'static str,
}

/// The per-platform asset table. Keyed by Rust's `{ARCH, OS}` so the host
/// selects its own toolchain. Each sha256 is the stock GitHub asset's digest
/// (computed once from the published release; the release is immutable).
const PLATFORMS: &[PlatformAsset] = &[
    PlatformAsset {
        arch: "x86_64",
        os: "linux",
        file: "wasi-sdk-33.0-x86_64-linux.tar.gz",
        sha256: "0ba8b5bfaeb2adf3f29bab5841d76cf5318ab8e1642ea195f88baba1abd47bce",
    },
    PlatformAsset {
        arch: "aarch64",
        os: "linux",
        file: "wasi-sdk-33.0-arm64-linux.tar.gz",
        sha256: "4f98ee738c7abb45c81a94d1461fc53cc569d1cd01498951c8184d841a027844",
    },
    PlatformAsset {
        arch: "x86_64",
        os: "macos",
        file: "wasi-sdk-33.0-x86_64-macos.tar.gz",
        sha256: "18f3f201ba9734e6a4455b0b6410690395a55e9ffa9f6f5066f66083a94b93b3",
    },
    PlatformAsset {
        arch: "aarch64",
        os: "macos",
        file: "wasi-sdk-33.0-arm64-macos.tar.gz",
        sha256: "85c997a2665ead91673b5bb88b7d0df3fc8900df3bfa244f720d478187bbdc78",
    },
    PlatformAsset {
        arch: "x86_64",
        os: "windows",
        file: "wasi-sdk-33.0-x86_64-windows.tar.gz",
        sha256: "df14ca2a2127c2d6b6be07e6f5549b3af9c1b3c0112430c200a4749970c59f06",
    },
];

/// The host driver name inside the unpacked `bin/` dir. On Windows the GitHub
/// asset ships `clang.exe`; elsewhere a bare `clang` (a symlink to `clang-NN`).
const fn driver_names() -> (&'static str, &'static str) {
    if cfg!(windows) {
        ("clang.exe", "clang++.exe")
    } else {
        ("clang", "clang++")
    }
}

/// `cargo build` entry point: populate (or reuse) the toolchain bundle cache and
/// export its dir so the runtime can resolve it.
pub(crate) fn build() {
    let dir = bundle_dir();
    // Always export the dir so the runtime knows where to look, even if this
    // build can't populate it (the runtime then falls back honestly).
    println!(
        "cargo:rustc-env=AFTERBURNER_WASI_SDK_BUNDLE_DIR={}",
        dir.display()
    );
    println!("cargo:rerun-if-changed=wasi_sdk_payload.rs");
    // An explicit opt-out for offline/minimal builds that don't want C/C++.
    println!("cargo:rerun-if-env-changed=AFTERBURNER_SKIP_WASI_SDK_BUNDLE");
    if std::env::var_os("AFTERBURNER_SKIP_WASI_SDK_BUNDLE").is_some() {
        println!(
            "cargo:warning=AFTERBURNER_SKIP_WASI_SDK_BUNDLE set; skipping the C/C++ toolchain payload"
        );
        return;
    }

    let Some(asset) = host_asset() else {
        // No stock asset for this host platform: skip cleanly. The C/C++
        // compile falls back to WASI_SDK_PATH with an honest error.
        println!(
            "cargo:warning=no bundled C/C++ toolchain for {}-{}; `burn run x.c` will fall back to WASI_SDK_PATH.",
            std::env::consts::ARCH,
            std::env::consts::OS
        );
        return;
    };

    let manifest = dir.join("manifest.txt");
    if manifest.exists() && manifest_complete(&dir, &manifest) {
        // Cache hit: the driver and the sysroot are present. No network.
        return;
    }

    if let Err(e) = std::fs::create_dir_all(&dir) {
        println!(
            "cargo:warning=C/C++ toolchain bundle: cannot create {}: {e}",
            dir.display()
        );
        return;
    }

    if let Err(e) = assemble(&dir, asset) {
        println!(
            "cargo:warning=C/C++ toolchain bundle: {e}; `burn run x.c` will fall back to WASI_SDK_PATH."
        );
    }
}

/// The stock asset for the host `{ARCH, OS}`, or `None` if unsupported.
fn host_asset() -> Option<&'static PlatformAsset> {
    let (arch, os) = (std::env::consts::ARCH, std::env::consts::OS);
    PLATFORMS.iter().find(|p| p.arch == arch && p.os == os)
}

/// Fetch the stock tarball, unpack the toolchain tree into `dir`, and write the
/// manifest. Returns `Err` (a single actionable string) on any failure so the
/// caller can warn-and-skip without a panic.
fn assemble(dir: &Path, asset: &PlatformAsset) -> Result<(), String> {
    let (clang_rel, clangxx_rel) = driver_names();
    let clang = dir.join("bin").join(clang_rel);
    let sysroot = dir.join("share").join("wasi-sysroot");
    // Re-unpack only when the cache is missing the driver or the sysroot.
    if !clang.exists() || !sysroot.exists() {
        let tar_gz = fetch(asset)?;
        extract(&tar_gz, dir)?;
    }
    if !clang.exists() {
        return Err(format!(
            "{clang_rel} not present after unpacking {}",
            asset.file
        ));
    }
    if !sysroot.exists() {
        return Err(format!(
            "share/wasi-sysroot not present after unpacking {}",
            asset.file
        ));
    }

    let lines = [
        format!("release={RELEASE_TAG}"),
        format!("version={VERSION}"),
        format!("clang=bin/{clang_rel}"),
        format!("clangxx=bin/{clangxx_rel}"),
        "sysroot=share/wasi-sysroot".to_string(),
    ];
    std::fs::write(dir.join("manifest.txt"), lines.join("\n") + "\n")
        .map_err(|e| format!("writing manifest: {e}"))
}

/// Download the stock release asset and verify its pinned sha256.
fn fetch(asset: &PlatformAsset) -> Result<Vec<u8>, String> {
    let url = format!(
        "https://github.com/WebAssembly/wasi-sdk/releases/download/{RELEASE_TAG}/{}",
        asset.file
    );
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("read body {url}: {e}"))?;
    let got = sha256_hex(&buf);
    if got != asset.sha256 {
        return Err(format!(
            "{} sha256 mismatch: expected {}, got {got} (release changed?)",
            asset.file, asset.sha256
        ));
    }
    Ok(buf)
}

/// Unpack the whole toolchain tree into `dir`, stripping the single leading
/// version dir (`wasi-sdk-<VERSION>-<arch>-<os>/`) so the cache holds
/// `bin/`, `lib/`, `include/`, `share/wasi-sysroot`, etc. directly.
///
/// The full tree is preserved (symlinks and Unix executable bits included):
/// `bin/clang` is a symlink to the real `clang-NN`, and clang resolves its
/// resource dir, the `.cfg` files, and the sysroot by paths relative to its own
/// location, so a partial extraction would break compilation. The man-page tree
/// under `share/man` is the one branch skipped (pure docs, never read by the
/// compiler).
fn extract(tar_gz: &[u8], dir: &Path) -> Result<(), String> {
    let gz = flate2::read::GzDecoder::new(tar_gz);
    let mut ar = tar::Archive::new(gz);
    // Preserve permissions (clang must stay executable). Symlinks are unpacked
    // as symlinks by default.
    ar.set_preserve_permissions(true);
    ar.set_overwrite(true);

    let entries = ar.entries().map_err(|e| format!("read tar entries: {e}"))?;
    let mut unpacked = 0usize;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("tar entry path: {e}"))?
            .into_owned();
        // Strip the single leading version-dir component. An entry that is just
        // the top dir (no child) yields an empty rel and is skipped.
        let rel: PathBuf = path.components().skip(1).collect();
        if rel.as_os_str().is_empty() {
            continue;
        }
        // Skip the man-page tree: pure documentation, never read at compile time.
        if rel.starts_with("share/man") {
            continue;
        }
        let dest = dir.join(&rel);
        // `Entry::unpack` does not create parents; ensure the dir exists so we
        // are robust to any entry ordering (a file before its dir entry) and to
        // the skipped man tree leaving a gap.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        entry
            .unpack(&dest)
            .map_err(|e| format!("unpack {}: {e}", rel.display()))?;
        unpacked += 1;
    }

    if unpacked == 0 {
        return Err("tarball contained no entries to unpack".to_string());
    }
    Ok(())
}

/// A manifest is complete when the driver and the sysroot it lists both exist
/// (so a half-populated cache re-unpacks).
fn manifest_complete(dir: &Path, manifest: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(manifest) else {
        return false;
    };
    let mut clang_ok = false;
    let mut sysroot_ok = false;
    for line in text.lines() {
        let Some((key, rel)) = line.split_once('=') else {
            continue;
        };
        match key {
            "clang" => clang_ok = dir.join(rel).exists(),
            "sysroot" => sysroot_ok = dir.join(rel).exists(),
            _ => {}
        }
    }
    clang_ok && sysroot_ok
}

/// The cache dir: `<target>/wasi-sdk-bundle/<release>`. Under the target dir so
/// `cargo clean` clears it and it never lands in git, but stable across normal
/// rebuilds (unlike `OUT_DIR`). Honors `CARGO_TARGET_DIR`; otherwise the
/// workspace `target`. Mirrors the Pyodide and ruby.wasm bundle dir scheme.
fn bundle_dir() -> PathBuf {
    let target = if let Some(t) = std::env::var_os("CARGO_TARGET_DIR") {
        PathBuf::from(t)
    } else {
        // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out. Walk up to <target>.
        let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR set in build script"));
        out.ancestors()
            .nth(4)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| out.clone())
    };
    target.join("wasi-sdk-bundle").join(RELEASE_TAG)
}
