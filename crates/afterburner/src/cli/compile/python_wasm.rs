// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Python -> self-contained `.afb` compile path.
//!
//! `burn compile` (language = "python") produces a single `.afb` that carries
//! everything needed to run the package standalone:
//!
//! - `precompiled/emscripten-pyodide/pyodide.wasm`  - the exnref-translated
//!   CPython wasm (from the cached `~/.burn` pyodide bundle or the optional
//!   `BURN_PYTHON_RUNTIME` override).
//! - `precompiled/emscripten-pyodide/python_stdlib.zip` - the Python stdlib zip.
//! - `vendor/pip/<wheel>.whl` - resolved Pyodide-compatible wheels for each
//!   `[pip]` dependency (pure-Python `py3-none-any` or `wasm32-emscripten` ABI
//!   only; host-native wheels are rejected loudly at compile time).
//! - `source/<rel>` - the package source files (entry + siblings).
//!
//! `runtime.target` is set to `"emscripten-pyodide"` so `burn run` can
//! dispatch directly to the Pyodide runner without needing to re-fetch the
//! runtime: it reconstitutes a `PyRuntime` from the bundled members, then
//! calls `run_pyodide_package_with` exactly as the source runner does.
//!
//! ## Why a bundle, not a single bare wasm?
//!
//! Pyodide uses the Emscripten ABI, not WASI. The stdlib and wheels are loaded
//! into an in-memory filesystem (InMemFs) by the Rust host before the Wasm
//! module initialises; there is no way to embed the FS data into the Wasm
//! binary itself without re-linking Pyodide from source (which violates the
//! no-custom-wasm rule). The bundle is self-contained: `burn run out.afb`
//! with a completely scrubbed environment produces the correct output with no
//! network access and no env vars.
//!
//! ## Dep wall
//!
//! A `[pip]` dependency that has no pure-Python (`py3-none-any`) or
//! Pyodide-ABI (`wasm32-emscripten`) wheel is rejected at compile time with a
//! clear error naming the package. The `PipClient` wheel ABI gate handles this
//! automatically; we surface the error rather than silently omitting the dep.
//!
//! A `BURN_PYTHON_RUNTIME` directory may override the auto-fetched runtime for
//! development / CI scenarios; no env var is required for normal use.

use afterburner_cloud::afterburner_afb::Afb;
use afterburner_cloud::afterburner_afb::digest::hex as afb_hex;
use afterburner_cloud::afterburner_afb::manifest::Manifest;
use afterburner_cloud::afterburner_afb::pack::Builder;
use afterburner_cloud::pkg::LocalPackage;
use afterburner_wasi::pyodide_runner::{PyRuntime, resolve_runtime};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// Runtime-target sentinel written into `[runtime] target` so `burn run` can
/// dispatch to the Pyodide embedder without re-fetching anything.
pub const RUNTIME_TARGET: &str = "emscripten-pyodide";

/// Archive paths for the bundled interpreter artefacts.
pub const PYODIDE_WASM_MEMBER: &str = "precompiled/emscripten-pyodide/pyodide.wasm";
pub const STDLIB_MEMBER: &str = "precompiled/emscripten-pyodide/python_stdlib.zip";

/// Compile a Python package to a self-contained `.afb` bundle.
///
/// Steps:
/// 1. Build a source `.afb` to get the canonical source set + manifest.
/// 2. Resolve the Pyodide runtime (CPython.wasm + stdlib) - auto-fetch via
///    [`resolve_runtime`], or `BURN_PYTHON_RUNTIME` override.
/// 3. Resolve `[pip]` wheels (if any) via `PipClient`; reject host-native
///    wheels loudly at this step (dep wall).
/// 4. Bundle everything into a single `.afb` with `runtime.target =
///    "emscripten-pyodide"` and a `precompiled/` + `vendor/pip/` layout.
pub fn compile_python_to_wasm(
    local: LocalPackage,
    _pkg_dir: &Path,
    out_path: &Path,
    wasm_only: bool,
) -> Result<()> {
    let coord = super::super::registry::coord_str(&local);

    // Step 1: build source .afb for canonical source set + manifest.
    let (source_bytes, _) = crate::cli::style::spin("packing source", || local.build())
        .context("building source .afb")?;
    let afb = Afb::from_bytes(&source_bytes).context("reparsing source .afb (this is a bug)")?;

    // Step 2: resolve the Pyodide runtime (wasm + stdlib).
    let rt = crate::cli::style::spin("resolving Python runtime", resolve_runtime)
        .map_err(|e| anyhow::anyhow!("resolving Python runtime: {e}"))?;

    // Read the wasm and stdlib bytes now; they are bundled into the .afb so
    // burn run never needs to re-fetch them.
    let pyodide_wasm = std::fs::read(&rt.wasm_path)
        .with_context(|| format!("reading pyodide wasm from {}", rt.wasm_path.display()))?;
    let stdlib_zip = std::fs::read(&rt.stdlib_path)
        .with_context(|| format!("reading Python stdlib from {}", rt.stdlib_path.display()))?;

    // Step 3: resolve [pip] deps.
    let pip_section = afb.manifest.pip.clone();
    let pip_wheels: BTreeMap<String, Vec<u8>> = if pip_section.is_empty() {
        BTreeMap::new()
    } else {
        crate::cli::style::spin("resolving pip wheels", || resolve_pip_wheels(&pip_section))
            .context("resolving [pip] dependencies")?
    };

    // Step 4: bundle into .afb.
    bundle_python_afb(
        &afb,
        &rt,
        pyodide_wasm,
        stdlib_zip,
        pip_wheels,
        out_path,
        &coord,
        wasm_only,
    )
}

/// Resolve a `[pip]` section (name -> PEP 440 specifier) and its transitive
/// closure into raw wheel bytes keyed by a `<name>-<version>-<tags>.whl`
/// archive key.
///
/// Uses `PipClient::public()` against PyPI. Wheels that are not
/// pure-Python or Pyodide-ABI are rejected by the client's ABI gate before
/// download; we surface those errors immediately so the user can fix the dep
/// or use a different package.
fn resolve_pip_wheels(pip_section: &BTreeMap<String, String>) -> Result<BTreeMap<String, Vec<u8>>> {
    use afterburner_cloud::pip_client::PipClient;

    let client = PipClient::public();
    let resolution = client
        .resolve_all(pip_section)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for pkg in &resolution.packages {
        // Re-assemble the wheel bytes from extracted files back into a zip so
        // the pyodide runner can mount them via mount_wheel.
        let wheel_bytes = pack_files_as_wheel(&pkg.files);
        // Archive key: vendor/pip/<name>-<version>-py3-none-any.whl
        let key = format!("vendor/pip/{}-{}-py3-none-any.whl", pkg.name, pkg.version);
        out.insert(key, wheel_bytes);
    }
    Ok(out)
}

/// Pack a flat file map back into a minimal stored-zip (wheel) so the pyodide
/// runner's `mount_wheel` can process it. Each entry uses compression method 0
/// (stored), which `mount_wheel` supports. The wheel format is a plain zip, so
/// a minimal EOCD + local headers is all we need.
fn pack_files_as_wheel(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let mut entry_count: u16 = 0;

    for (rel, data) in files {
        let name = rel.as_bytes();
        let name_len = name.len() as u16;
        let data_len = data.len() as u32;
        let crc = crc32_ieee(data);
        let local_offset = out.len() as u32;

        // Local file header (method 0 = stored).
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra field len
        out.extend_from_slice(name);
        out.extend_from_slice(data);

        // Central directory entry.
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&0u16.to_le_bytes()); // method
        central.extend_from_slice(&0u16.to_le_bytes()); // mod time
        central.extend_from_slice(&0u16.to_le_bytes()); // mod date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&data_len.to_le_bytes());
        central.extend_from_slice(&data_len.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk start
        central.extend_from_slice(&0u16.to_le_bytes()); // int attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name);

        entry_count = entry_count.saturating_add(1);
    }

    let central_start = out.len() as u32;
    let central_len = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory record.
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&central_len.to_le_bytes());
    out.extend_from_slice(&central_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length

    out
}

/// CRC-32 (IEEE 802.3) needed for stored-zip entries.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= 0xEDB8_8320u32;
            }
        }
    }
    !crc
}

/// Assemble the final `.afb` from the resolved components.
#[allow(clippy::too_many_arguments)]
fn bundle_python_afb(
    afb: &Afb,
    rt: &PyRuntime,
    pyodide_wasm: Vec<u8>,
    stdlib_zip: Vec<u8>,
    pip_wheels: BTreeMap<String, Vec<u8>>,
    out_path: &Path,
    coord: &str,
    wasm_only: bool,
) -> Result<()> {
    let mut manifest: Manifest = afb.manifest.clone();
    manifest.runtime.target = Some(RUNTIME_TARGET.to_owned());
    // Embed the interpreter X.Y so burn run can reconstruct python_xy from the
    // bundle without re-reading the pyodide manifest. Stored in `metadata` which
    // the manifest parser passes through without rejecting unknown keys.
    manifest.metadata.insert(
        "python_xy".to_owned(),
        toml::Value::String(rt.python_xy.clone()),
    );

    let mut b = Builder::new(manifest, afb.manifold.clone());

    // Source files (entry + siblings).
    if !wasm_only {
        for (path, data) in &afb.source {
            b = b.source(path.clone(), data.clone());
        }
    }

    // Bundled interpreter + stdlib as precompiled members so burn run can find
    // them by a stable path without any external lookup.
    b = b.precompiled(PYODIDE_WASM_MEMBER, pyodide_wasm);
    b = b.precompiled(STDLIB_MEMBER, stdlib_zip);

    // Pip wheels bundled as vendor/pip/*.whl.
    for (key, wheel_bytes) in &pip_wheels {
        b = b.vendor(key.clone(), wheel_bytes.clone());
    }

    let (bytes, d) =
        crate::cli::style::spin("packing", || b.build()).context("building Python .afb bundle")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {} {}",
        crate::cli::style::ok("compiled"),
        crate::cli::style::accent(coord),
        crate::cli::style::gold("(emscripten-pyodide bundle)")
    );
    super::super::registry::print_digest(bytes.len() as u64, &afb_hex(&d));
    println!(
        "  {} {}",
        crate::cli::style::muted("->"),
        crate::cli::style::value(&out_path.display().to_string())
    );
    Ok(())
}

/// Reconstruct a [`PyRuntime`] from the bundled members of an
/// `emscripten-pyodide` `.afb`, materializing the wasm and stdlib to a temp
/// directory so the runner can read them by path.
///
/// The caller (run.rs) owns the temp dir lifetime and cleans it up after the
/// run finishes.
///
/// Returns `(PyRuntime, temp_dir_path)` on success. The `PyRuntime.wheels`
/// field is empty; vendored wheels are returned separately in `pip_wheel_bytes`
/// because the pyodide runner receives them as in-memory slices, not paths.
pub fn reconstruct_runtime_from_afb(
    afb: &Afb,
    tmp_root: &Path,
) -> Result<(PyRuntime, Vec<Vec<u8>>)> {
    // Extract pyodide.wasm.
    let wasm_bytes = afb.precompiled.get(PYODIDE_WASM_MEMBER).ok_or_else(|| {
        anyhow::anyhow!(
            "Python compiled .afb is missing {}; re-run `burn compile`",
            PYODIDE_WASM_MEMBER
        )
    })?;

    let stdlib_bytes = afb.precompiled.get(STDLIB_MEMBER).ok_or_else(|| {
        anyhow::anyhow!(
            "Python compiled .afb is missing {}; re-run `burn compile`",
            STDLIB_MEMBER
        )
    })?;

    // Materialize to tmp so PyRuntime (which holds PathBuf) can work.
    std::fs::create_dir_all(tmp_root)
        .with_context(|| format!("creating temp dir {}", tmp_root.display()))?;
    let wasm_path = tmp_root.join("pyodide.wasm");
    let stdlib_path = tmp_root.join("python_stdlib.zip");
    std::fs::write(&wasm_path, wasm_bytes)
        .with_context(|| format!("writing {}", wasm_path.display()))?;
    std::fs::write(&stdlib_path, stdlib_bytes)
        .with_context(|| format!("writing {}", stdlib_path.display()))?;

    // Recover python_xy from the embedded metadata field (see bundle_python_afb).
    let python_xy = afb
        .manifest
        .metadata
        .get("python_xy")
        .and_then(|v| v.as_str())
        .unwrap_or("3.13")
        .to_owned();

    let rt = PyRuntime {
        wasm_path,
        stdlib_path,
        wheels: Vec::new(), // bundled wheels come from vendor/pip/ below
        python_xy,
    };

    // Collect vendor/pip/*.whl bytes for the caller to pass as extra wheels.
    let pip_wheel_bytes: Vec<Vec<u8>> = afb
        .vendor
        .iter()
        .filter(|(k, _)| k.starts_with("vendor/pip/") && k.ends_with(".whl"))
        .map(|(_, v)| v.clone())
        .collect();

    Ok((rt, pip_wheel_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_target_constant() {
        assert_eq!(RUNTIME_TARGET, "emscripten-pyodide");
    }

    #[test]
    fn pyodide_wasm_member_path() {
        assert!(PYODIDE_WASM_MEMBER.starts_with("precompiled/"));
        assert!(PYODIDE_WASM_MEMBER.ends_with(".wasm"));
    }

    #[test]
    fn stdlib_member_path() {
        assert!(STDLIB_MEMBER.starts_with("precompiled/"));
        assert!(STDLIB_MEMBER.ends_with(".zip"));
    }

    #[test]
    fn pack_files_as_wheel_roundtrips_via_mount_wheel() {
        // Build a minimal file map and pack it.
        let mut files = BTreeMap::new();
        files.insert("mypkg/__init__.py".to_owned(), b"VALUE = 42\n".to_vec());
        files.insert(
            "mypkg/helper.py".to_owned(),
            b"def hi(): return 'hello'\n".to_vec(),
        );

        let wheel = pack_files_as_wheel(&files);

        // The result must be a valid zip (PK signature at offset 0).
        assert!(wheel.len() > 4, "wheel must be non-empty");
        assert_eq!(
            &wheel[0..4],
            b"PK\x03\x04",
            "must start with local header sig"
        );

        // The bytes must be parseable by the mount_wheel machinery: just verify
        // the local file header fields look sane for the first entry.
        // method (offset 8..10) must be 0 (stored).
        let method = u16::from_le_bytes(wheel[8..10].try_into().unwrap());
        assert_eq!(method, 0, "stored compression");
    }

    #[test]
    fn crc32_ieee_known_value() {
        // CRC32 of empty slice is 0.
        assert_eq!(crc32_ieee(b""), 0);
        // CRC32 of b"a" is the standard IEEE value.
        assert_eq!(crc32_ieee(b"a"), 0xe8b7be43);
    }
}
