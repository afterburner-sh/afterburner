// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The optional embedded Python core (`embed-core` feature).
//!
//! When the crate is built with `--features embed-core`, the exnref main wasm
//! and the stdlib zip (~10.6 MiB) are baked into the binary via `include_bytes!`
//! from the dir the build script assembled (`AFTERBURNER_EMBED_CORE_DIR`). Basic
//! Python then runs OFFLINE with zero download even on a cold `~/.burn`: the
//! resolver materializes these bytes into `~/.burn/pyodide-<ver>` on a miss.
//!
//! Only the CORE is embedded. The wheels (numpy/pandas) and the C/C++ toolchain
//! are NOT - they still fetch lazily into `~/.burn` on demand, so `import numpy`
//! offline fails honestly while `print(1+1)` works.
//!
//! The embedded bytes are byte-identical to what a network fetch + translate
//! produces (same pinned artifacts, same `wasm-opt` flags), so materializing the
//! core writes the SAME `~/.burn/pyodide-<ver>` dir a fetch would, and a later
//! online run that wants wheels re-uses it (a partial-bundle re-fetch tops up the
//! wheels rather than redoing the core). The build script fails the build if it
//! cannot assemble the core, so an `embed-core` binary never ships a hollow
//! "offline Python" promise.

use std::path::{Path, PathBuf};

/// The exnref-translated main wasm, baked in at build time.
static CORE_WASM: &[u8] = include_bytes!(concat!(
    env!("AFTERBURNER_EMBED_CORE_DIR"),
    "/pyodide-exnref.wasm"
));
/// The Python stdlib zip, baked in at build time.
static CORE_STDLIB: &[u8] = include_bytes!(concat!(
    env!("AFTERBURNER_EMBED_CORE_DIR"),
    "/python_stdlib.zip"
));

/// Materialize the embedded core into `~/.burn/pyodide-<ver>` (the same dir a
/// network fetch targets) and return it, so the existing path-based runner mounts
/// it unchanged. Idempotent: a dir already carrying the core wasm + stdlib is a
/// no-op (a network fetch may have since topped it up with wheels - left intact).
///
/// The write is atomic: the bytes go to a sibling staging dir, then `rename` into
/// place, so a crash mid-write never leaves a half-core that reads as complete.
pub fn materialize_core(home: &Path) -> Result<PathBuf, String> {
    let dir = crate::bundle::pyodide_dir(home);

    // Already present (a prior materialize, or a network fetch): reuse it. We
    // check the two core files rather than the manifest so a fetched bundle
    // (whose manifest also lists wheels) counts as "core present" too.
    if dir.join("pyodide-exnref.wasm").exists() && dir.join("python_stdlib.zip").exists() {
        return Ok(dir);
    }

    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let staging = dir.with_file_name(format!("pyodide-embed.staging-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("mkdir {}: {e}", staging.display()))?;

    let write = |name: &str, bytes: &[u8]| -> Result<(), String> {
        std::fs::write(staging.join(name), bytes).map_err(|e| format!("write {name}: {e}"))
    };
    let result = (|| {
        write("pyodide-exnref.wasm", CORE_WASM)?;
        write("python_stdlib.zip", CORE_STDLIB)?;
        // A stdlib-only manifest: `pyodide_manifest_ok` requires every LISTED
        // file, and listing no wheels is a valid (numpy-less) bundle.
        let manifest = format!(
            "version={}\npython={}\nwasm=pyodide-exnref.wasm\nstdlib=python_stdlib.zip\n",
            crate::bundle::PYODIDE_VERSION,
            crate::bundle::PYODIDE_PYTHON_XY,
        );
        std::fs::write(staging.join("manifest.txt"), manifest).map_err(|e| e.to_string())?;
        // The rename target must be clear; a partial dir from an interrupted run
        // is discarded (we already know the core files are absent).
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        std::fs::rename(&staging, &dir)
            .map_err(|e| format!("rename {} -> {}: {e}", staging.display(), dir.display()))
    })();

    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result.map(|()| dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded bytes are non-empty and look like what they claim (a wasm
    /// magic header, a zip local-file-header magic) - a guard against an empty
    /// `include_bytes!` from a misconfigured build.
    #[test]
    fn embedded_core_bytes_are_present_and_shaped() {
        assert!(CORE_WASM.len() > 1_000_000, "core wasm looks too small");
        assert_eq!(&CORE_WASM[0..4], b"\0asm", "core wasm lacks the wasm magic");
        assert!(CORE_STDLIB.len() > 500_000, "stdlib zip looks too small");
        assert_eq!(&CORE_STDLIB[0..2], b"PK", "stdlib lacks the zip magic");
    }

    /// Materializing into a fresh home writes the core + a stdlib-only manifest,
    /// and a second call is a no-op (the core files already exist).
    #[test]
    fn materialize_is_atomic_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = materialize_core(tmp.path()).expect("materialize");
        assert!(dir.join("pyodide-exnref.wasm").exists());
        assert!(dir.join("python_stdlib.zip").exists());
        let manifest = std::fs::read_to_string(dir.join("manifest.txt")).unwrap();
        assert!(manifest.contains("wasm=pyodide-exnref.wasm"));
        assert!(manifest.contains("stdlib=python_stdlib.zip"));
        assert!(
            !manifest.contains("wheel="),
            "core manifest lists no wheels"
        );
        // No staging dir lingers.
        let staging_present = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains("staging"));
        assert!(!staging_present, "staging dir must be renamed away");
        // Second call: no-op, same dir.
        let dir2 = materialize_core(tmp.path()).expect("idempotent materialize");
        assert_eq!(dir, dir2);
    }
}
