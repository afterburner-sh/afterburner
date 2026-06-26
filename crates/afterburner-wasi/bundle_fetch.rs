// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The one fetch + verify + translate + cache engine for the language runtime
//! bundles (the Python runtime, the C/C++ toolchain, the Ruby runtime).
//!
//! This file is `#[path]`-included into BOTH compilation units that need it:
//! the runtime crate (`src/lib.rs`, behind `mod bundle_fetch`) and the build
//! script (`build.rs`, behind `mod bundle_fetch`). One copy, no drift: a stock
//! artifact fetched + translated here is byte-identical whether it was assembled
//! at build time (the opt-in `BURN_PREFETCH=1` prefetch) or on the first
//! `burn run` (the default, lazy, runtime fetch into `~/.burn`).
//!
//! It depends only on `ureq`, `flate2`, `tar`, `sha2`, and `std` so it links
//! cleanly into the build script's own crate graph as well as the runtime's.
//! Nothing here touches the rest of the runtime crate.
//!
//! ## Determinism
//!
//! The fetched bytes are sha256-pinned to the validated artifact set, and the
//! exnref translation is a pure function of its input (verified: the stock
//! Pyodide wasm -> `wasm-opt --translate-to-exnref` reproduces the known-good
//! exnref binary byte for byte). So a bundle populated here is bit-identical to
//! the bundle the build-time path produced, and a run over it is byte-for-byte
//! unaffected by which path populated `~/.burn`.
//!
//! ## Atomicity
//!
//! A bundle is populated under a sibling temp dir, fsync'd, then `rename`d into
//! place, so a half-populated dir from an interrupted fetch never reads back as
//! complete: the next run re-fetches. Each bundle dir carries a `manifest.txt`
//! (`key=relpath` lines) that the resolvers read to locate the runtime files;
//! `*_manifest_ok` validate a dir against its own manifest (the same check the
//! atomic populate uses before the rename).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

// ── progress reporting ──────────────────────────────────────────────────────

/// A sink for download + assemble progress, implemented by the CLI (with the
/// sunburst gradient bar in `cli::style`) and a no-op everywhere else (the build
/// script, a library consumer, a non-TTY stderr).
///
/// The engine drives it: one labeled line per bundle. `begin` opens the line,
/// `bytes` advances the gradient bar against the content length, `assembling`
/// switches to the spinner for the translate/unpack step, and `finish` clears
/// the line. The trait is object-safe and `Send + Sync` so a single reporter can
/// be shared by reference across the fetch.
pub trait BundleProgress: Send + Sync {
    /// Start a labeled progress line. `label` is the user-facing runtime name
    /// (no internal codenames): "Fetching Python runtime", etc. `total` is the
    /// content length in bytes when the server reported one, else `None`.
    fn begin(&self, label: &str, total: Option<u64>);
    /// Advance to `downloaded` bytes total (cumulative, not a delta).
    fn bytes(&self, downloaded: u64);
    /// The download is done; the assemble step (translate / unpack) is running.
    fn assembling(&self, label: &str);
    /// Clear the line. Called once, on success or failure.
    fn finish(&self);
}

/// The no-op reporter the build script and library callers use: every method is
/// a no-op, so the engine renders nothing.
pub struct NoProgress;

impl BundleProgress for NoProgress {
    fn begin(&self, _label: &str, _total: Option<u64>) {}
    fn bytes(&self, _downloaded: u64) {}
    fn assembling(&self, _label: &str) {}
    fn finish(&self) {}
}

// ── home directory ──────────────────────────────────────────────────────────

/// The Afterburner home dir where runtime bundles live: `$BURN_HOME` when set
/// (honored verbatim, so a test or a packager can redirect it), else `~/.burn`
/// under the user's home directory. Returns `None` only when no home can be
/// located, in which case the caller falls back to the env-var runtime override
/// path with an honest error rather than guessing a location.
pub fn burn_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("BURN_HOME")
        && !h.is_empty()
    {
        return Some(PathBuf::from(h));
    }
    Some(user_home_dir()?.join(".burn"))
}

/// The user's home directory, resolved cross-platform without a `dirs`/`home`
/// dependency: `$HOME` on Unix, and on Windows `%USERPROFILE%` then
/// `%HOMEDRIVE%%HOMEPATH%` (Windows usually leaves `HOME` unset). Returns `None`
/// only when none of these is set, so `~/.burn` resolves on Linux, macOS, and
/// Windows alike.
fn user_home_dir() -> Option<PathBuf> {
    home_from(
        std::env::var_os("HOME"),
        std::env::var_os("USERPROFILE"),
        std::env::var_os("HOMEDRIVE"),
        std::env::var_os("HOMEPATH"),
    )
}

/// Pure home-dir resolution from the four environment values, so the
/// cross-platform precedence is unit-testable without mutating the process
/// environment: `$HOME`, then `%USERPROFILE%`, then `%HOMEDRIVE%%HOMEPATH%`.
/// Empty values are skipped at each step.
fn home_from(
    home: Option<std::ffi::OsString>,
    userprofile: Option<std::ffi::OsString>,
    homedrive: Option<std::ffi::OsString>,
    homepath: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    if let Some(h) = home.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(h));
    }
    if let Some(up) = userprofile.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(up));
    }
    let drive = homedrive.filter(|s| !s.is_empty())?;
    let path = homepath.filter(|s| !s.is_empty())?;
    let mut combined = drive;
    combined.push(path);
    Some(PathBuf::from(combined))
}

// ── sha256 ──────────────────────────────────────────────────────────────────

/// Lowercase hex SHA-256 of `bytes`. Local to this engine (not the runtime
/// crate's `afterburner_core::sha256`) so the build script, which cannot link
/// the runtime crate, shares the identical implementation.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Public alias for [`sha256_hex`], reachable from the build script (which
/// `#[path]`-includes this file as its own module) so the plugin-drift gate
/// shares the one sha256 implementation instead of carrying a second copy.
/// `#[allow(dead_code)]`: unused on the runtime side, used on the build side.
#[allow(dead_code)]
pub fn sha256_hex_pub(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

// ── wasm-opt ────────────────────────────────────────────────────────────────

/// `wasm-opt` flags that translate legacy try/catch EH to the exnref proposal
/// while preserving the side-module structure (the `dylink.0` custom section,
/// the `GOT.func` / `GOT.mem` imports, and the active element segments).
///
/// Kept byte-for-byte identical to `emscripten_exnref::WASM_OPT_FLAGS` (the
/// runtime side-module path): the bundle assembly and the on-demand `.so`
/// translation must apply the SAME lowering so a stock `.so` translated here is
/// the same as one translated on the dlopen path. A divergence would mean a
/// bundled wheel `.so` differs from its runtime-translated twin.
const WASM_OPT_FLAGS: &[&str] = &[
    "--translate-to-exnref",
    "--enable-exception-handling",
    "--enable-reference-types",
    "--enable-bulk-memory",
    "--enable-simd",
    "--enable-sign-ext",
    "--enable-nontrapping-float-to-int",
    "--enable-mutable-globals",
    "--enable-multivalue",
];

/// Locate `wasm-opt`: `$BURN_WASM_OPT` first (an explicit override), then
/// `PATH`, then the emsdk fallback Pyodide builds ship. Returns `None` when none
/// is present (the caller then surfaces an actionable error only if a
/// translation was actually required). Identical resolution order to the
/// runtime side-module path's `find_wasm_opt`.
fn find_wasm_opt() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BURN_WASM_OPT") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(out) = Command::new("wasm-opt").arg("--version").output()
        && out.status.success()
    {
        return Some(PathBuf::from("wasm-opt"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join("emsdk/upstream/bin/wasm-opt");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Translate a wasm module to exnref via `wasm-opt`, writing the result to
/// `out`. `wasm-opt` reads/writes files, not stdio, so a temp round-trip in the
/// destination dir is required.
fn translate_wasm(wasm_opt: &Path, stock: &[u8], out: &Path) -> Result<(), String> {
    let tmp_in = out.with_extension("stock.wasm");
    std::fs::write(&tmp_in, stock).map_err(|e| e.to_string())?;
    let status = Command::new(wasm_opt)
        .args(WASM_OPT_FLAGS)
        .arg(&tmp_in)
        .arg("-o")
        .arg(out)
        .status()
        .map_err(|e| format!("spawn wasm-opt: {e}"))?;
    let _ = std::fs::remove_file(&tmp_in);
    if !status.success() {
        return Err(format!("wasm-opt exited {status}"));
    }
    Ok(())
}

/// Translate a single `.so` (a wasm side module) to exnref, returning the
/// translated bytes. Uses temp files under `scratch_dir` so a wheel repack does
/// not collide with another in the same process.
fn translate_so_bytes(
    wasm_opt: &Path,
    so: &[u8],
    name: &str,
    scratch_dir: &Path,
) -> Result<Vec<u8>, String> {
    let key = sha256_hex(name.as_bytes());
    let tmp_in = scratch_dir.join(format!("afb-so-{}-{key}.in.wasm", std::process::id()));
    let tmp_out = tmp_in.with_extension("out.wasm");
    std::fs::write(&tmp_in, so).map_err(|e| e.to_string())?;
    let status = Command::new(wasm_opt)
        .args(WASM_OPT_FLAGS)
        .arg(&tmp_in)
        .arg("-o")
        .arg(&tmp_out)
        .status()
        .map_err(|e| format!("spawn wasm-opt for {name}: {e}"))?;
    let result = if status.success() {
        std::fs::read(&tmp_out).map_err(|e| e.to_string())
    } else {
        Err(format!("wasm-opt exited {status} for {name}"))
    };
    let _ = std::fs::remove_file(&tmp_in);
    let _ = std::fs::remove_file(&tmp_out);
    result
}

// ── network fetch (progress-reporting) ──────────────────────────────────────

/// Download `url`, streaming the body so the gradient bar advances against the
/// content length, and verify the pinned sha256. The progress line is opened
/// with `label` (a user-facing runtime name) and closed by the caller via
/// `prog.finish()`. Returns the verified bytes.
fn fetch_verified(
    url: &str,
    sha256: &str,
    label: &str,
    prog: &dyn BundleProgress,
) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let total: Option<u64> = resp
        .header("Content-Length")
        .and_then(|s| s.trim().parse::<u64>().ok());
    prog.begin(label, total);

    let mut reader = resp.into_reader();
    // Cap the buffer at the content length when known, else a sane default, so a
    // single allocation holds the bundle (the largest single artifact is the
    // toolchain tarball, ~250 MiB; bounded by the pinned content length).
    let mut buf: Vec<u8> = Vec::with_capacity(total.unwrap_or(8 << 20) as usize);
    let mut chunk = [0u8; 64 << 10];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| format!("read body {url}: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        prog.bytes(buf.len() as u64);
    }

    let got = sha256_hex(&buf);
    if got != sha256 {
        return Err(format!(
            "sha256 mismatch for {url}: expected {sha256}, got {got} (upstream content changed?)"
        ));
    }
    Ok(buf)
}

// ── atomic bundle population ────────────────────────────────────────────────

/// Populate `final_dir` atomically: run `populate` against a fresh sibling
/// staging dir (`<final_dir>.staging-<pid>`), and on success fsync + rename it
/// into place. A pre-existing complete `final_dir` (its `manifest.txt` lists
/// files that all exist) is a cache hit and returns immediately with no work and
/// no network. A half-populated `final_dir` (manifest absent or a listed file
/// missing) is discarded and re-fetched.
///
/// `manifest_ok` validates a candidate dir against its own `manifest.txt`; it is
/// the per-bundle completeness check (the resolvers share the identical logic).
fn ensure_populated(
    final_dir: &Path,
    manifest_ok: &dyn Fn(&Path) -> bool,
    populate: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    if final_dir.join("manifest.txt").exists() && manifest_ok(final_dir) {
        return Ok(()); // cache hit
    }

    // A stale, half-populated dir from an interrupted run: remove it so the
    // rename target is clear and a partial tree never lingers.
    if final_dir.exists() {
        let _ = std::fs::remove_dir_all(final_dir);
    }
    if let Some(parent) = final_dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }

    let staging = final_dir.with_file_name(format!(
        "{}.staging-{}",
        final_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bundle".to_string()),
        std::process::id()
    ));
    // A leftover staging dir from a crashed prior run on the same pid is junk.
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("mkdir {}: {e}", staging.display()))?;

    let result = populate(&staging).and_then(|()| {
        if !manifest_ok(&staging) {
            return Err("bundle assembly produced an incomplete tree".to_string());
        }
        fsync_dir(&staging);
        // The rename target was cleared above; rename is atomic on the same fs.
        std::fs::rename(&staging, final_dir).map_err(|e| {
            format!(
                "rename {} -> {}: {e}",
                staging.display(),
                final_dir.display()
            )
        })
    });

    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

/// fsync a directory (best-effort) so the rename that follows is durable: the
/// staged files are on disk before the dir entry flips to the final name.
fn fsync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Write `bytes` to `path` inside the staging dir, creating parents. No
/// temp-rename here: the whole staging dir is the atomic unit (it is renamed
/// into place only once complete), so an individual file write is direct.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

// ── zip (wheel) read / write ────────────────────────────────────────────────

/// One entry pulled out of a stock wheel, ready to (re)pack.
struct WheelEntry {
    name: String,
    /// Final (post-translation) uncompressed bytes.
    data: Vec<u8>,
}

/// Parse a zip's local file headers into decompressed entries. Supports the two
/// methods Pyodide wheels use: 0 (stored) and 8 (deflate). Skips directory
/// entries. Mirrors the runtime-side parser in `pyodide_runner::mount_wheel`.
fn read_zip_entries(zip: &[u8]) -> Result<Vec<WheelEntry>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 30 <= zip.len() {
        let sig = u32::from_le_bytes(zip[pos..pos + 4].try_into().unwrap());
        if sig == 0x0201_4b50 || sig == 0x0605_4b50 {
            break; // central directory / end-of-central-directory
        }
        if sig != 0x0403_4b50 {
            pos += 1;
            continue;
        }
        let method = u16::from_le_bytes(zip[pos + 8..pos + 10].try_into().unwrap());
        let comp_size = u32::from_le_bytes(zip[pos + 18..pos + 22].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(zip[pos + 26..pos + 28].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(zip[pos + 28..pos + 30].try_into().unwrap()) as usize;
        let name_start = pos + 30;
        let name_end = name_start + name_len;
        if name_end > zip.len() {
            break;
        }
        let name = String::from_utf8_lossy(&zip[name_start..name_end]).into_owned();
        let data_start = name_end + extra_len;
        let data_end = data_start + comp_size;
        if data_end > zip.len() {
            break;
        }
        if !name.ends_with('/') {
            let raw = &zip[data_start..data_end];
            let data = match method {
                0 => raw.to_vec(),
                8 => {
                    let mut dec = flate2::read::DeflateDecoder::new(raw);
                    let mut b = Vec::new();
                    dec.read_to_end(&mut b)
                        .map_err(|e| format!("inflate {name}: {e}"))?;
                    b
                }
                m => return Err(format!("{name}: unsupported zip method {m}")),
            };
            out.push(WheelEntry { name, data });
        }
        pos = data_end;
    }
    Ok(out)
}

/// Encode entries as a deflate zip (local headers + central directory + EOCD).
/// The runtime's wheel mounter (which scans local headers) parses it directly.
fn write_deflate_zip(entries: &[WheelEntry]) -> Result<Vec<u8>, String> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    let mut buf: Vec<u8> = Vec::new();
    // (name, crc32, comp_size, uncomp_size, local_header_offset)
    let mut central: Vec<(String, u32, u32, u32, u32)> = Vec::with_capacity(entries.len());

    for e in entries {
        let offset = buf.len() as u32;
        let mut crc = flate2::Crc::new();
        crc.update(&e.data);
        let crc32 = crc.sum();

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&e.data).map_err(|err| err.to_string())?;
        let compressed = enc.finish().map_err(|err| err.to_string())?;

        let name = e.name.as_bytes();
        // Local file header.
        buf.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&8u16.to_le_bytes()); // method = deflate
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc32.to_le_bytes());
        buf.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
        buf.extend_from_slice(name);
        buf.extend_from_slice(&compressed);

        central.push((
            e.name.clone(),
            crc32,
            compressed.len() as u32,
            e.data.len() as u32,
            offset,
        ));
    }

    let cd_start = buf.len() as u32;
    for (name, crc32, comp, uncomp, offset) in &central {
        let nb = name.as_bytes();
        buf.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        buf.extend_from_slice(&20u16.to_le_bytes()); // version made by
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&8u16.to_le_bytes()); // method
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&crc32.to_le_bytes());
        buf.extend_from_slice(&comp.to_le_bytes());
        buf.extend_from_slice(&uncomp.to_le_bytes());
        buf.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra len
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        buf.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(nb);
    }
    let cd_size = buf.len() as u32 - cd_start;

    // End of central directory.
    buf.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
    buf.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    buf.extend_from_slice(&(central.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(central.len() as u16).to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_start.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment len
    Ok(buf)
}

/// Repackage a wheel with every `.so` translated to exnref, leaving every other
/// entry untouched. `scratch_dir` holds the per-`.so` wasm-opt temp files.
fn translate_wheel_bytes(
    wasm_opt: &Path,
    stock: &[u8],
    scratch_dir: &Path,
) -> Result<Vec<u8>, String> {
    let mut entries = read_zip_entries(stock)?;
    for e in &mut entries {
        if e.name.ends_with(".so") {
            e.data = translate_so_bytes(wasm_opt, &e.data, &e.name, scratch_dir)?;
        }
    }
    write_deflate_zip(&entries)
}

// ── Pyodide (Python runtime) bundle ─────────────────────────────────────────

/// User-facing label for the Python runtime download (no internal codename).
const PY_LABEL: &str = "Fetching Python runtime";

/// Pyodide release the bundled payload tracks. CPython 3.13.2, Emscripten
/// 4.0.9, abi `pyodide_2025_0` - the validated 0.28.3 runtime that runs
/// numpy + pandas today.
const PYODIDE_VER: &str = "0.28.3";
const PYODIDE_CDN: &str = "https://cdn.jsdelivr.net/pyodide/v0.28.3/full";
/// CPython `X.Y` of the bundled interpreter, written into the manifest so the
/// runtime mounts the matching stdlib + soabi without a hardcode.
const PY_XY: &str = "3.13";

/// One stock artifact to fetch from the CDN, its pinned sha256, and how it must
/// be assembled (the main wasm and the wheels that carry `.so` are translated).
struct PyArtifact {
    file: &'static str,
    sha256: &'static str,
    kind: PyKind,
}

enum PyKind {
    /// The main `pyodide.asm.wasm`: translate the whole module to exnref.
    MainWasm,
    /// `python_stdlib.zip`: copied verbatim.
    Stdlib,
    /// A wheel that ships `.so` side modules: repackage with each `.so`
    /// translated to exnref.
    WheelWithSo,
    /// A pure-Python wheel (no `.so`): copied verbatim.
    PureWheel,
}

/// The 0.28.3 payload: the main wasm, the stdlib, and the pandas dependency
/// closure (numpy, six, python-dateutil, pytz, pandas) in import order.
const PY_ARTIFACTS: &[PyArtifact] = &[
    PyArtifact {
        file: "pyodide.asm.wasm",
        sha256: "5effb6a1a6cc4a1a85bec4622701aa797c031e1de923cbbaf2ad47abdc4ab325",
        kind: PyKind::MainWasm,
    },
    PyArtifact {
        file: "python_stdlib.zip",
        sha256: "71fee17f88a6260ec8c9c7c063533ee59c021fdc88a1ce76247378d3c4a35f4c",
        kind: PyKind::Stdlib,
    },
    PyArtifact {
        file: "numpy-2.2.5-cp313-cp313-pyodide_2025_0_wasm32.whl",
        sha256: "3db3c4f3e0448f4d62a85c262692f1260ccd8a91335442bd2442f21ffeddb558",
        kind: PyKind::WheelWithSo,
    },
    PyArtifact {
        file: "six-1.17.0-py2.py3-none-any.whl",
        sha256: "618e0357f1724d937c20b75d691f0ba9e404de2701084e3c4f35995cfb879665",
        kind: PyKind::PureWheel,
    },
    PyArtifact {
        file: "python_dateutil-2.9.0.post0-py2.py3-none-any.whl",
        sha256: "26b50ce706a17abdde09dbb95745a44f9320dfdb99e950c52b1a62a3d99e452c",
        kind: PyKind::PureWheel,
    },
    PyArtifact {
        file: "pytz-2025.2-py2.py3-none-any.whl",
        sha256: "1d7f409837318a3a234a6394253a77900072616a42e5dba89c3214f70e77f31b",
        kind: PyKind::PureWheel,
    },
    PyArtifact {
        file: "pandas-2.3.1-cp313-cp313-pyodide_2025_0_wasm32.whl",
        sha256: "01d16ef68eb333f3ac18e370aa352660f8f8d432f607ff1272a16cd2ea2e87ce",
        kind: PyKind::WheelWithSo,
    },
];

/// The Python bundle dir: `<burn_home>/pyodide-<ver>`.
pub fn pyodide_dir(home: &Path) -> PathBuf {
    home.join(format!("pyodide-{PYODIDE_VER}"))
}

/// A Python bundle manifest is complete when every `key=relpath` it lists
/// (`wasm`, `stdlib`, `wheel`) points at a file that exists in `dir`.
pub fn pyodide_manifest_ok(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("manifest.txt")) else {
        return false;
    };
    for line in text.lines() {
        let Some((key, rel)) = line.split_once('=') else {
            continue;
        };
        if matches!(key, "wasm" | "stdlib" | "wheel") && !dir.join(rel).exists() {
            return false;
        }
    }
    true
}

/// Fetch + assemble ONE Python artifact into `staging`, returning the
/// `manifest.txt` line that records where the result landed. The single place
/// the fetch/translate/copy per kind is decided, so `ensure_pyodide` (the full
/// bundle) and `assemble_pyodide_core` (the embed-core subset) cannot diverge.
fn assemble_py_artifact(
    art: &PyArtifact,
    staging: &Path,
    wasm_opt: &Path,
    prog: &dyn BundleProgress,
) -> Result<String, String> {
    let url = format!("{PYODIDE_CDN}/{}", art.file);
    Ok(match art.kind {
        PyKind::MainWasm => {
            let stock = fetch_verified(&url, art.sha256, PY_LABEL, prog)?;
            prog.assembling(PY_LABEL);
            translate_wasm(wasm_opt, &stock, &staging.join("pyodide-exnref.wasm"))?;
            "wasm=pyodide-exnref.wasm".to_string()
        }
        PyKind::Stdlib => {
            let stock = fetch_verified(&url, art.sha256, PY_LABEL, prog)?;
            write_file(&staging.join("python_stdlib.zip"), &stock)?;
            "stdlib=python_stdlib.zip".to_string()
        }
        PyKind::PureWheel => {
            let stock = fetch_verified(&url, art.sha256, PY_LABEL, prog)?;
            write_file(&staging.join(art.file), &stock)?;
            format!("wheel={}", art.file)
        }
        PyKind::WheelWithSo => {
            let stock = fetch_verified(&url, art.sha256, PY_LABEL, prog)?;
            prog.assembling(PY_LABEL);
            let name = format!("{}.exnref.whl", art.file.trim_end_matches(".whl"));
            let translated = translate_wheel_bytes(wasm_opt, &stock, staging)?;
            write_file(&staging.join(&name), &translated)?;
            format!("wheel={name}")
        }
    })
}

/// Resolve `wasm-opt`, or an actionable error naming the override + install path.
fn require_wasm_opt() -> Result<PathBuf, String> {
    find_wasm_opt().ok_or_else(|| {
        "the Python runtime needs `wasm-opt` (Binaryen) to assemble; it was not found on PATH, \
         at $BURN_WASM_OPT, or at $HOME/emsdk/upstream/bin/wasm-opt. Install Binaryen, or set \
         BURN_PYTHON_RUNTIME to a prebuilt runtime dir."
            .to_string()
    })
}

/// Ensure the Python runtime bundle exists under `home`, fetching + translating
/// it on a miss with progress on `prog`. Idempotent: a complete bundle is a
/// no-op. Returns `Err` (a single actionable string) on any failure so the
/// caller can fall back to `BURN_PYTHON_RUNTIME` with an honest error.
pub fn ensure_pyodide(home: &Path, prog: &dyn BundleProgress) -> Result<(), String> {
    let dir = pyodide_dir(home);
    let manifest_ok = |d: &Path| pyodide_manifest_ok(d);
    let populate = |staging: &Path| -> Result<(), String> {
        let wasm_opt = require_wasm_opt()?;
        let mut lines: Vec<String> =
            vec![format!("version={PYODIDE_VER}"), format!("python={PY_XY}")];
        for art in PY_ARTIFACTS {
            lines.push(assemble_py_artifact(art, staging, &wasm_opt, prog)?);
        }
        write_file(
            &staging.join("manifest.txt"),
            (lines.join("\n") + "\n").as_bytes(),
        )
    };

    let r = ensure_populated(&dir, &manifest_ok, &populate);
    prog.finish();
    r
}

/// Assemble JUST the Python core (the exnref main wasm + the stdlib zip, no
/// wheels) into `out_dir`, written directly (not under `home` / not staged):
/// the caller owns the dir's lifecycle. Used by the build script under the
/// `embed-core` feature to bake the core into the binary via `include_bytes!`.
///
/// The result is byte-identical to the core the full [`ensure_pyodide`] writes
/// (same artifacts, same translation), so an embedded core and a fetched bundle
/// share `~/.burn/pyodide-<ver>`. The written manifest lists only `wasm` +
/// `stdlib`, which [`pyodide_manifest_ok`] accepts (it requires every LISTED
/// file, and a stdlib-only bundle simply lists no wheels).
#[allow(dead_code)] // used by the build script (embed-core); unused on the runtime side
pub fn assemble_pyodide_core(out_dir: &Path, prog: &dyn BundleProgress) -> Result<(), String> {
    let wasm_opt = require_wasm_opt()?;
    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
    let mut lines: Vec<String> = vec![format!("version={PYODIDE_VER}"), format!("python={PY_XY}")];
    for art in PY_ARTIFACTS
        .iter()
        .filter(|a| matches!(a.kind, PyKind::MainWasm | PyKind::Stdlib))
    {
        lines.push(assemble_py_artifact(art, out_dir, &wasm_opt, prog)?);
    }
    write_file(
        &out_dir.join("manifest.txt"),
        (lines.join("\n") + "\n").as_bytes(),
    )?;
    prog.finish();
    Ok(())
}

/// The CPython `X.Y` the embedded core's stdlib was built for, so the
/// runtime-side embed materializer writes a manifest matching what the runner
/// expects without re-stating the constant.
#[allow(dead_code)] // used by the runtime embed path (embed-core)
pub const PYODIDE_PYTHON_XY: &str = PY_XY;

/// The bundle dir name component for the tracked Python release
/// (`pyodide-<ver>`), exposed so the embed materializer targets the SAME
/// `~/.burn` dir a network fetch would, making an embedded core a cache hit for
/// a later online run.
#[allow(dead_code)] // used by the runtime embed path (embed-core)
pub const PYODIDE_VERSION: &str = PYODIDE_VER;

// ── Ruby runtime bundle ─────────────────────────────────────────────────────

/// User-facing label for the Ruby runtime download (no internal codename).
const RUBY_LABEL: &str = "Fetching Ruby runtime";

/// ruby.wasm release the bundled payload tracks: the official `ruby/ruby.wasm`
/// release `2.9.4`, CRuby 3.4 built for `wasm32-unknown-wasip1`.
const RUBY_WASM_RELEASE: &str = "2.9.4";
/// Ruby `X.Y.Z` ABI dir the stdlib lives under inside the tarball.
const RUBY_ABI: &str = "3.4.0";
const RUBY_TARBALL: &str = "ruby-3.4-wasm32-unknown-wasip1-full.tar.gz";
const RUBY_TARBALL_SHA256: &str =
    "ccda86a375a4fe09849846d3b03a370172a4902a0c571087f48457388a2762c7";
/// Top-level dir name inside the tarball; stripped so the cache keeps `usr/...`.
const RUBY_TARBALL_ROOT: &str = "ruby-3.4-wasm32-unknown-wasip1-full/";
/// The standalone interpreter path inside the tarball (a pure-WASI command).
const RUBY_BIN: &str = "ruby-3.4-wasm32-unknown-wasip1-full/usr/local/bin/ruby";
/// The stdlib tree prefix inside the tarball; kept under `usr/local/lib/ruby`.
const RUBY_LIB_PREFIX: &str = "ruby-3.4-wasm32-unknown-wasip1-full/usr/local/lib/ruby/";
/// Cache-relative path of the stdlib root, used to detect a complete extraction.
const RUBY_STDLIB_ABI_REL: &str = "usr/local/lib/ruby";

/// The Ruby bundle dir: `<burn_home>/ruby-<release>`.
pub fn ruby_dir(home: &Path) -> PathBuf {
    home.join(format!("ruby-{RUBY_WASM_RELEASE}"))
}

/// The ruby.wasm release tag, exposed so the embed materializer targets the
/// same `~/.burn` dir a network fetch would.
#[allow(dead_code)] // used by the runtime embed path (embed-ruby)
pub const RUBY_RELEASE: &str = RUBY_WASM_RELEASE;

/// The Ruby ABI (`X.Y.Z`) the embedded stdlib was built for, exposed so the
/// embed materializer can write a manifest that the resolver validates.
#[allow(dead_code)] // used by the runtime embed path (embed-ruby)
pub const RUBY_ABI_VERSION: &str = RUBY_ABI;

/// A Ruby bundle manifest is complete when the wasm and the versioned stdlib dir
/// it lists both exist.
pub fn ruby_manifest_ok(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("manifest.txt")) else {
        return false;
    };
    let mut wasm_ok = false;
    let mut stdlib_ok = false;
    for line in text.lines() {
        let Some((key, rel)) = line.split_once('=') else {
            continue;
        };
        match key {
            "wasm" => wasm_ok = dir.join(rel).exists(),
            "usr" => stdlib_ok = dir.join(RUBY_STDLIB_ABI_REL).join(RUBY_ABI).exists(),
            _ => {}
        }
    }
    wasm_ok && stdlib_ok
}

/// Ensure the Ruby runtime bundle exists under `home`. No translation, no
/// `wasm-opt`: the interpreter imports only `wasi_snapshot_preview1`.
pub fn ensure_ruby(home: &Path, prog: &dyn BundleProgress) -> Result<(), String> {
    let dir = ruby_dir(home);
    let manifest_ok = |d: &Path| ruby_manifest_ok(d);
    let populate = |staging: &Path| -> Result<(), String> {
        let url = format!(
            "https://github.com/ruby/ruby.wasm/releases/download/{RUBY_WASM_RELEASE}/{RUBY_TARBALL}"
        );
        let tar_gz = fetch_verified(&url, RUBY_TARBALL_SHA256, RUBY_LABEL, prog)?;
        prog.assembling(RUBY_LABEL);
        extract_ruby(&tar_gz, staging)?;
        let lines = [
            format!("release={RUBY_WASM_RELEASE}"),
            format!("ruby={RUBY_ABI}"),
            "wasm=ruby.wasm".to_string(),
            "usr=usr".to_string(),
        ];
        write_file(
            &staging.join("manifest.txt"),
            (lines.join("\n") + "\n").as_bytes(),
        )
    };

    let r = ensure_populated(&dir, &manifest_ok, &populate);
    prog.finish();
    r
}

/// Assemble the Ruby core (the `ruby.wasm` interpreter + the full `usr` stdlib
/// tree) into `out_dir` for `include_bytes!` embedding under the `embed-ruby`
/// feature. Called by the build script; the caller owns the dir's lifecycle.
///
/// The result is byte-identical to what [`ensure_ruby`] writes into `~/.burn`,
/// so a later online run finds the embedded bytes already in place (a cache hit).
/// No `wasm-opt` required: the interpreter is a pure WASI command module.
#[allow(dead_code)] // used by the build script (embed-ruby); unused on the runtime side
pub fn assemble_ruby_core(out_dir: &Path, prog: &dyn BundleProgress) -> Result<(), String> {
    // A populated dir is a cache hit: both the interpreter and the versioned
    // stdlib dir must be present.
    let wasm_ok = out_dir.join("ruby.wasm").exists();
    let stdlib_ok = out_dir.join(RUBY_STDLIB_ABI_REL).join(RUBY_ABI).exists();
    if wasm_ok && stdlib_ok {
        return Ok(());
    }

    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;

    let url = format!(
        "https://github.com/ruby/ruby.wasm/releases/download/{RUBY_WASM_RELEASE}/{RUBY_TARBALL}"
    );
    let tar_gz = fetch_verified(&url, RUBY_TARBALL_SHA256, RUBY_LABEL, prog)?;
    prog.assembling(RUBY_LABEL);
    extract_ruby(&tar_gz, out_dir)?;

    let lines = [
        format!("release={RUBY_WASM_RELEASE}"),
        format!("ruby={RUBY_ABI}"),
        "wasm=ruby.wasm".to_string(),
        "usr=usr".to_string(),
    ];
    write_file(
        &out_dir.join("manifest.txt"),
        (lines.join("\n") + "\n").as_bytes(),
    )?;
    prog.finish();
    Ok(())
}

/// Extract the standalone `bin/ruby` to `<staging>/ruby.wasm` and every stdlib
/// file under `RUBY_LIB_PREFIX` into `<staging>/usr/local/lib/ruby/...`,
/// preserving the tree shape. Skips the build sysroot (`libruby-static.a` etc.).
fn extract_ruby(tar_gz: &[u8], staging: &Path) -> Result<(), String> {
    let gz = flate2::read::GzDecoder::new(tar_gz);
    let mut ar = tar::Archive::new(gz);
    let mut found_bin = false;
    let mut stdlib_count = 0usize;

    let entries = ar.entries().map_err(|e| format!("read tar entries: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("tar entry path: {e}"))?
            .to_string_lossy()
            .into_owned();

        if path == RUBY_BIN {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| format!("read {RUBY_BIN}: {e}"))?;
            write_file(&staging.join("ruby.wasm"), &bytes)?;
            found_bin = true;
        } else if path.starts_with(RUBY_LIB_PREFIX) {
            let rel = path.strip_prefix(RUBY_TARBALL_ROOT).unwrap_or(&path);
            let dest = staging.join(rel);
            if path.ends_with('/') {
                std::fs::create_dir_all(&dest)
                    .map_err(|e| format!("mkdir {}: {e}", dest.display()))?;
                continue;
            }
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| format!("read stdlib {rel}: {e}"))?;
            write_file(&dest, &bytes)?;
            stdlib_count += 1;
        }
    }

    if !found_bin {
        return Err(format!("{RUBY_BIN} not found in {RUBY_TARBALL}"));
    }
    if stdlib_count == 0 {
        return Err(format!(
            "no stdlib files under {RUBY_LIB_PREFIX} in {RUBY_TARBALL}"
        ));
    }
    Ok(())
}

// ── wasi-sdk (C/C++ toolchain) bundle ───────────────────────────────────────

/// User-facing label for the toolchain download (no internal codename).
const CC_LABEL: &str = "Fetching C/C++ toolchain";

/// wasi-sdk release the bundled toolchain tracks: `wasi-sdk-33`, version `33.0`.
const WASI_RELEASE_TAG: &str = "wasi-sdk-33";
const WASI_VERSION: &str = "33.0";

/// One host platform's stock asset and its pinned sha256.
struct PlatformAsset {
    arch: &'static str,
    os: &'static str,
    file: &'static str,
    sha256: &'static str,
}

/// The per-platform asset table, keyed by Rust's `{ARCH, OS}`.
const WASI_PLATFORMS: &[PlatformAsset] = &[
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

/// The host driver name inside the unpacked `bin/` dir.
const fn wasi_driver_names() -> (&'static str, &'static str) {
    if cfg!(windows) {
        ("clang.exe", "clang++.exe")
    } else {
        ("clang", "clang++")
    }
}

/// The stock asset for the host `{ARCH, OS}`, or `None` if unsupported.
fn wasi_host_asset() -> Option<&'static PlatformAsset> {
    let (arch, os) = (std::env::consts::ARCH, std::env::consts::OS);
    WASI_PLATFORMS.iter().find(|p| p.arch == arch && p.os == os)
}

/// The toolchain bundle dir: `<burn_home>/wasi-sdk-<tag>`.
pub fn wasi_sdk_dir(home: &Path) -> PathBuf {
    home.join(format!("wasi-sdk-{WASI_RELEASE_TAG}"))
}

/// A toolchain manifest is complete when the driver and the sysroot it lists
/// both exist.
pub fn wasi_sdk_manifest_ok(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("manifest.txt")) else {
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

/// Ensure the C/C++ toolchain bundle exists under `home`. The artifact is a
/// native HOST toolchain (a `clang`, its resource dir, and the WASI sysroot), so
/// the whole tree is unpacked preserving symlinks and executable permissions.
/// Returns `Err` on an unsupported host or any failure (the caller then falls
/// back to `WASI_SDK_PATH`).
pub fn ensure_wasi_sdk(home: &Path, prog: &dyn BundleProgress) -> Result<(), String> {
    let asset = wasi_host_asset().ok_or_else(|| {
        format!(
            "no bundled C/C++ toolchain for {}-{}; set WASI_SDK_PATH to a wasi-sdk install.",
            std::env::consts::ARCH,
            std::env::consts::OS
        )
    })?;
    let (clang_rel, clangxx_rel) = wasi_driver_names();
    let dir = wasi_sdk_dir(home);
    let manifest_ok = |d: &Path| wasi_sdk_manifest_ok(d);
    let populate = |staging: &Path| -> Result<(), String> {
        let url = format!(
            "https://github.com/WebAssembly/wasi-sdk/releases/download/{WASI_RELEASE_TAG}/{}",
            asset.file
        );
        let tar_gz = fetch_verified(&url, asset.sha256, CC_LABEL, prog)?;
        prog.assembling(CC_LABEL);
        extract_wasi_sdk(&tar_gz, staging)?;
        let clang = staging.join("bin").join(clang_rel);
        let sysroot = staging.join("share").join("wasi-sysroot");
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
            format!("release={WASI_RELEASE_TAG}"),
            format!("version={WASI_VERSION}"),
            format!("clang=bin/{clang_rel}"),
            format!("clangxx=bin/{clangxx_rel}"),
            "sysroot=share/wasi-sysroot".to_string(),
        ];
        write_file(
            &staging.join("manifest.txt"),
            (lines.join("\n") + "\n").as_bytes(),
        )
    };

    let r = ensure_populated(&dir, &manifest_ok, &populate);
    prog.finish();
    r
}

/// Unpack the whole toolchain tree into `staging`, stripping the single leading
/// version dir, preserving symlinks and Unix executable bits (clang resolves its
/// resource dir and sysroot by relative path). Skips the man-page tree.
fn extract_wasi_sdk(tar_gz: &[u8], staging: &Path) -> Result<(), String> {
    let gz = flate2::read::GzDecoder::new(tar_gz);
    let mut ar = tar::Archive::new(gz);
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
        let rel: PathBuf = path.components().skip(1).collect();
        if rel.as_os_str().is_empty() {
            continue;
        }
        if rel.starts_with("share/man") {
            continue;
        }
        let dest = staging.join(&rel);
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

// ── wasi-vfs (Ruby WASM packer) bundle ──────────────────────────────────────

/// User-facing label for the wasi-vfs CLI download (no internal codename).
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
const WASI_VFS_LABEL: &str = "Fetching wasi-vfs packer";

/// wasi-vfs release the bundled packer tracks.
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
const WASI_VFS_RELEASE: &str = "v0.6.3";

/// Per-platform asset and its pinned sha256.
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
struct WasiVfsPlatformAsset {
    arch: &'static str,
    os: &'static str,
    file: &'static str,
    sha256: &'static str,
}

/// Platform table for wasi-vfs CLI (zip, contains one binary named `wasi-vfs`).
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
const WASI_VFS_PLATFORMS: &[WasiVfsPlatformAsset] = &[
    WasiVfsPlatformAsset {
        arch: "x86_64",
        os: "linux",
        file: "wasi-vfs-cli-x86_64-unknown-linux-gnu.zip",
        sha256: "c9ee8179f6f0882abc37024fbe0cd678311aa8a29083fa364915ed4d29a69485",
    },
    WasiVfsPlatformAsset {
        arch: "aarch64",
        os: "linux",
        file: "wasi-vfs-cli-aarch64-unknown-linux-gnu.zip",
        sha256: "ef71666d26215121f7c49c1713ee029aa5ebe6ea41722013b41d488288cb0186",
    },
    WasiVfsPlatformAsset {
        arch: "x86_64",
        os: "macos",
        file: "wasi-vfs-cli-x86_64-apple-darwin.zip",
        sha256: "b3d86d63350ae48fda9b5877647cca4d9c1ff2f637db5e4eb40852aa5361c340",
    },
    WasiVfsPlatformAsset {
        arch: "aarch64",
        os: "macos",
        file: "wasi-vfs-cli-aarch64-apple-darwin.zip",
        sha256: "d9ebf1cb77927b39c543dccb3fc35842b0f14ca8f70223de1daf2585896de3c1",
    },
];

#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
fn wasi_vfs_host_asset() -> Option<&'static WasiVfsPlatformAsset> {
    let arch = std::env::consts::ARCH;
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        _ => return None,
    };
    WASI_VFS_PLATFORMS
        .iter()
        .find(|a| a.arch == arch && a.os == os)
}

/// The wasi-vfs bundle dir: `<burn_home>/wasi-vfs-<release>`.
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
pub fn wasi_vfs_dir(home: &Path) -> PathBuf {
    home.join(format!("wasi-vfs-{WASI_VFS_RELEASE}"))
}

/// The wasi-vfs CLI binary name on the current platform.
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
#[cfg(unix)]
fn wasi_vfs_bin_name() -> &'static str {
    "wasi-vfs"
}
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
#[cfg(not(unix))]
fn wasi_vfs_bin_name() -> &'static str {
    "wasi-vfs.exe"
}

/// A wasi-vfs manifest is complete when the binary exists.
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
pub fn wasi_vfs_manifest_ok(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join("manifest.txt")) else {
        return false;
    };
    for line in text.lines() {
        let Some((key, rel)) = line.split_once('=') else {
            continue;
        };
        if key == "bin" {
            return dir.join(rel).exists();
        }
    }
    false
}

/// Ensure the wasi-vfs CLI bundle exists under `home`. The CLI binary is
/// extracted from the platform zip and cached at
/// `~/.burn/wasi-vfs-<release>/wasi-vfs`. Returns `Err` on an unsupported
/// host or any fetch/extract failure.
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
pub fn ensure_wasi_vfs(home: &Path, prog: &dyn BundleProgress) -> Result<(), String> {
    let asset = wasi_vfs_host_asset().ok_or_else(|| {
        format!(
            "no bundled wasi-vfs for {}-{}; set WASI_VFS to a wasi-vfs binary path.",
            std::env::consts::ARCH,
            std::env::consts::OS
        )
    })?;
    let dir = wasi_vfs_dir(home);
    let bin_name = wasi_vfs_bin_name();
    let manifest_ok = |d: &Path| wasi_vfs_manifest_ok(d);
    let populate = |staging: &Path| -> Result<(), String> {
        let url = format!(
            "https://github.com/kateinoigakukun/wasi-vfs/releases/download/{WASI_VFS_RELEASE}/{}",
            asset.file
        );
        let zip_bytes = fetch_verified(&url, asset.sha256, WASI_VFS_LABEL, prog)?;
        prog.assembling(WASI_VFS_LABEL);
        extract_wasi_vfs_bin(&zip_bytes, staging, bin_name)?;
        write_file(
            &staging.join("manifest.txt"),
            format!("release={WASI_VFS_RELEASE}\nbin={bin_name}\n").as_bytes(),
        )
    };
    let r = ensure_populated(&dir, &manifest_ok, &populate);
    prog.finish();
    r
}

/// Extract the single `wasi-vfs` binary from the zip into `staging/<bin_name>`,
/// setting the executable bit on Unix. The zip contains exactly one file with
/// `wasi-vfs` as its name (no directory prefix in these releases).
#[allow(dead_code)] // used by the runtime side (bundle.rs); unused in the build script
fn extract_wasi_vfs_bin(zip: &[u8], staging: &Path, bin_name: &str) -> Result<(), String> {
    let entries = read_zip_entries(zip)?;
    let entry = entries
        .into_iter()
        .find(|e| {
            let base = e.name.rsplit('/').next().unwrap_or(&e.name);
            base == "wasi-vfs" || base == "wasi-vfs.exe"
        })
        .ok_or_else(|| "wasi-vfs binary not found in downloaded zip".to_string())?;
    let dest = staging.join(bin_name);
    write_file(&dest, &entry.data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod +x {}: {e}", dest.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod home_dir_tests {
    use super::home_from;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn os(s: &str) -> Option<OsString> {
        Some(OsString::from(s))
    }

    #[test]
    fn unix_home_takes_precedence() {
        // $HOME wins even when Windows vars are also present.
        assert_eq!(
            home_from(os("/home/u"), os(r"C:\Users\u"), os("C:"), os(r"\Users\u")),
            Some(PathBuf::from("/home/u"))
        );
    }

    #[test]
    fn windows_userprofile_when_home_absent() {
        assert_eq!(
            home_from(None, os(r"C:\Users\u"), None, None),
            Some(PathBuf::from(r"C:\Users\u"))
        );
    }

    #[test]
    fn windows_homedrive_homepath_fallback() {
        let mut expected = OsString::from("C:");
        expected.push(r"\Users\u");
        assert_eq!(
            home_from(None, None, os("C:"), os(r"\Users\u")),
            Some(PathBuf::from(expected))
        );
    }

    #[test]
    fn empty_values_are_skipped_then_none() {
        // Empty HOME/USERPROFILE are ignored; with nothing usable -> None.
        assert_eq!(home_from(os(""), os(""), os(""), os("")), None);
        assert_eq!(home_from(None, None, None, None), None);
    }
}
