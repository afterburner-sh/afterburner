// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Build-time assembly of the self-contained Pyodide 0.28.3 payload.
//!
//! Fetches the stock artifacts from the jsDelivr CDN (sha256-pinned to the
//! validated 0.28.3 set), exnref-translates the main wasm and each wheel `.so`
//! with `wasm-opt`, and writes the result into a stable cache dir under the
//! workspace target. The translation is deterministic (verified: the stock
//! 0.28.3 wasm -> `wasm-opt --translate-to-exnref` reproduces the known-good
//! exnref binary byte for byte), so a cache hit needs no network and no work.
//!
//! The runtime reads `AFTERBURNER_PYODIDE_BUNDLE_DIR` (a `cargo:rustc-env`
//! emitted here) plus a `manifest.txt` the dir contains. Nothing is committed
//! to git and nothing is downloaded at runtime.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{find_wasm_opt, sha256_hex};

/// Pyodide release the bundled payload tracks. CPython 3.13.2, Emscripten
/// 4.0.9, abi `pyodide_2025_0` - the validated 0.28.3 runtime that runs
/// numpy + pandas today.
const PYODIDE_VER: &str = "0.28.3";
const CDN: &str = "https://cdn.jsdelivr.net/pyodide/v0.28.3/full";

/// One stock artifact to fetch from the CDN, its pinned sha256, and whether it
/// must be exnref-translated (the main wasm and the wheels that carry `.so`).
struct Artifact {
    /// CDN file name, also the cache file name for non-translated artifacts.
    file: &'static str,
    /// sha256 of the STOCK download (CDN-immutable; cross-checked against the
    /// 0.28.3 `pyodide-lock.json`). Translated OUTPUT shas are not pinned: zip
    /// repackaging is not byte-stable, while the `.so` contents are.
    sha256: &'static str,
    kind: Kind,
}

enum Kind {
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
const ARTIFACTS: &[Artifact] = &[
    Artifact {
        file: "pyodide.asm.wasm",
        sha256: "5effb6a1a6cc4a1a85bec4622701aa797c031e1de923cbbaf2ad47abdc4ab325",
        kind: Kind::MainWasm,
    },
    Artifact {
        file: "python_stdlib.zip",
        sha256: "71fee17f88a6260ec8c9c7c063533ee59c021fdc88a1ce76247378d3c4a35f4c",
        kind: Kind::Stdlib,
    },
    Artifact {
        file: "numpy-2.2.5-cp313-cp313-pyodide_2025_0_wasm32.whl",
        sha256: "3db3c4f3e0448f4d62a85c262692f1260ccd8a91335442bd2442f21ffeddb558",
        kind: Kind::WheelWithSo,
    },
    Artifact {
        file: "six-1.17.0-py2.py3-none-any.whl",
        sha256: "618e0357f1724d937c20b75d691f0ba9e404de2701084e3c4f35995cfb879665",
        kind: Kind::PureWheel,
    },
    Artifact {
        file: "python_dateutil-2.9.0.post0-py2.py3-none-any.whl",
        sha256: "26b50ce706a17abdde09dbb95745a44f9320dfdb99e950c52b1a62a3d99e452c",
        kind: Kind::PureWheel,
    },
    Artifact {
        file: "pytz-2025.2-py2.py3-none-any.whl",
        sha256: "1d7f409837318a3a234a6394253a77900072616a42e5dba89c3214f70e77f31b",
        kind: Kind::PureWheel,
    },
    Artifact {
        file: "pandas-2.3.1-cp313-cp313-pyodide_2025_0_wasm32.whl",
        sha256: "01d16ef68eb333f3ac18e370aa352660f8f8d432f607ff1272a16cd2ea2e87ce",
        kind: Kind::WheelWithSo,
    },
];

/// CPython `X.Y` of the bundled interpreter, written into the manifest so the
/// runtime mounts the matching stdlib + soabi without a hardcode.
const PY_XY: &str = "3.13";

/// `wasm-opt` flags that translate legacy try/catch EH to the exnref proposal
/// while preserving the side-module structure (dylink.0, GOT imports, segments).
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

pub(crate) fn build() {
    let dir = bundle_dir();
    // Always export the dir so the runtime knows where to look, even if this
    // build can't populate it (the runtime then falls back honestly).
    println!(
        "cargo:rustc-env=AFTERBURNER_PYODIDE_BUNDLE_DIR={}",
        dir.display()
    );
    // The payload is content-pinned (versioned dir + sha manifest), so it never
    // needs a rebuild from a source-file change; only a missing/partial cache
    // triggers work. Re-run if this build module changes.
    println!("cargo:rerun-if-changed=pyodide_payload.rs");
    // An explicit opt-out for offline/minimal builds that don't want Python.
    println!("cargo:rerun-if-env-changed=AFTERBURNER_SKIP_PYODIDE_BUNDLE");
    if std::env::var_os("AFTERBURNER_SKIP_PYODIDE_BUNDLE").is_some() {
        println!("cargo:warning=AFTERBURNER_SKIP_PYODIDE_BUNDLE set; skipping Pyodide payload");
        return;
    }

    let manifest = dir.join("manifest.txt");
    if manifest.exists() && manifest_complete(&dir, &manifest) {
        // Cache hit: every listed artifact is present. No network, no work.
        return;
    }

    if let Err(e) = std::fs::create_dir_all(&dir) {
        println!(
            "cargo:warning=Pyodide bundle: cannot create {}: {e}",
            dir.display()
        );
        return;
    }

    let wasm_opt = find_wasm_opt();
    if wasm_opt.is_none() {
        println!(
            "cargo:warning=Pyodide bundle: `wasm-opt` not found on PATH or at \
             $HOME/emsdk/upstream/bin/wasm-opt; cannot exnref-translate the runtime. \
             `burn run x.py` will fall back to BURN_PYTHON_RUNTIME. Install Binaryen \
             (wasm-opt) to enable the zero-config Python runtime."
        );
        return;
    }
    let wasm_opt = wasm_opt.unwrap();

    let mut lines: Vec<String> = vec![format!("version={PYODIDE_VER}"), format!("python={PY_XY}")];
    for art in ARTIFACTS {
        match assemble(&dir, art, &wasm_opt) {
            Ok(rel) => lines.push(rel),
            Err(e) => {
                println!(
                    "cargo:warning=Pyodide bundle: {} failed ({e}); skipping the rest. \
                     `burn run x.py` will fall back to BURN_PYTHON_RUNTIME.",
                    art.file
                );
                return;
            }
        }
    }
    if let Err(e) = std::fs::write(&manifest, lines.join("\n") + "\n") {
        println!("cargo:warning=Pyodide bundle: writing manifest failed: {e}");
    }
}

/// Assemble one artifact into the cache. Returns the manifest line describing
/// where the result lives (`role=relpath`), reusing an existing cache file.
fn assemble(dir: &Path, art: &Artifact, wasm_opt: &Path) -> Result<String, String> {
    match art.kind {
        Kind::MainWasm => {
            let out = dir.join("pyodide-exnref.wasm");
            if !out.exists() {
                let stock = fetch(art)?;
                translate_wasm(wasm_opt, &stock, &out)?;
            }
            Ok("wasm=pyodide-exnref.wasm".to_string())
        }
        Kind::Stdlib => {
            let out = dir.join("python_stdlib.zip");
            if !out.exists() {
                let stock = fetch(art)?;
                std::fs::write(&out, &stock).map_err(|e| e.to_string())?;
            }
            Ok("stdlib=python_stdlib.zip".to_string())
        }
        Kind::PureWheel => {
            let out = dir.join(art.file);
            if !out.exists() {
                let stock = fetch(art)?;
                std::fs::write(&out, &stock).map_err(|e| e.to_string())?;
            }
            Ok(format!("wheel={}", art.file))
        }
        Kind::WheelWithSo => {
            // Cache the translated wheel under a `.exnref.whl` name.
            let name = format!("{}.exnref.whl", art.file.trim_end_matches(".whl"));
            let out = dir.join(&name);
            if !out.exists() {
                let stock = fetch(art)?;
                translate_wheel(wasm_opt, &stock, &out)?;
            }
            Ok(format!("wheel={name}"))
        }
    }
}

/// Download a stock artifact and verify its pinned sha256.
fn fetch(art: &Artifact) -> Result<Vec<u8>, String> {
    let url = format!("{CDN}/{}", art.file);
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut buf)
        .map_err(|e| format!("read body {url}: {e}"))?;
    let got = sha256_hex(&buf);
    if got != art.sha256 {
        return Err(format!(
            "{} sha256 mismatch: expected {}, got {got} (CDN content changed?)",
            art.file, art.sha256
        ));
    }
    Ok(buf)
}

/// Translate the whole main module to exnref.
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

/// One entry pulled out of the stock wheel, ready to (re)pack.
struct WheelEntry {
    name: String,
    /// Final (post-translation) uncompressed bytes.
    data: Vec<u8>,
}

/// Repackage a wheel with every `.so` translated to exnref, leaving every other
/// entry (the `.py`, metadata) untouched. Mirrors `scripts/load_pkg.py`.
///
/// Reads the stock zip's local file headers (stored / deflate) and writes a
/// fresh, standards-valid deflate zip (local headers + central directory +
/// EOCD) using `flate2` - no new dependency, and the runtime's wheel mounter
/// (which scans local headers) parses it directly.
fn translate_wheel(wasm_opt: &Path, stock: &[u8], out: &Path) -> Result<(), String> {
    let mut entries = read_zip_entries(stock)?;
    for e in &mut entries {
        if e.name.ends_with(".so") {
            e.data = translate_so_bytes(wasm_opt, &e.data, &e.name)?;
        }
    }
    let zip = write_deflate_zip(&entries)?;
    let tmp = out.with_extension("building.whl");
    std::fs::write(&tmp, &zip).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, out).map_err(|e| e.to_string())?;
    Ok(())
}

/// Parse a zip's local file headers into decompressed entries. Supports the two
/// methods Pyodide wheels use: 0 (stored) and 8 (deflate). Skips directory
/// entries. Mirrors the runtime-side parser in `pyodide_runner::mount_wheel`.
fn read_zip_entries(zip: &[u8]) -> Result<Vec<WheelEntry>, String> {
    use std::io::Read;
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
                    let mut buf = Vec::new();
                    dec.read_to_end(&mut buf)
                        .map_err(|e| format!("inflate {name}: {e}"))?;
                    buf
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

/// Translate a single `.so` (a wasm side module) to exnref via a tmp file.
fn translate_so_bytes(wasm_opt: &Path, so: &[u8], name: &str) -> Result<Vec<u8>, String> {
    let mut tmp_in = std::env::temp_dir();
    tmp_in.push(format!("afb-so-{}.in.wasm", sha256_hex(name.as_bytes())));
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

/// A manifest is complete when every `key=relpath` it lists points at a file
/// that exists in the cache dir (so a half-populated cache rebuilds).
fn manifest_complete(dir: &Path, manifest: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(manifest) else {
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

/// The cache dir: `<target>/pyodide-bundle/<version>`. Under the target dir so
/// `cargo clean` clears it and it never lands in git, but stable across normal
/// rebuilds (unlike `OUT_DIR`, which is per-build-script-rebuild). Honors
/// `CARGO_TARGET_DIR`; otherwise the workspace `target`.
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
    target.join("pyodide-bundle").join(PYODIDE_VER)
}
