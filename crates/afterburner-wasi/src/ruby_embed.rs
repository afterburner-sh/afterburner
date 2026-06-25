// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The optional embedded Ruby runtime (`embed-ruby` feature).
//!
//! When the crate is built with `--features embed-ruby`, the standalone
//! `ruby.wasm` interpreter (~33 MiB) and a tar of the `usr/` stdlib tree
//! (~20 MiB) are baked into the binary via `include_bytes!` from the dir the
//! build script assembled (`AFTERBURNER_EMBED_RUBY_DIR`). Ruby then runs
//! OFFLINE with zero download even on a cold `~/.burn`: the resolver
//! materializes these bytes into `~/.burn/ruby-<release>` on a miss.
//!
//! Only the CORE is embedded (interpreter + stdlib). The lazy `~/.burn` fetch
//! remains the fallback when `embed-ruby` is off.
//!
//! The embedded bytes are byte-identical to what a network fetch produces (same
//! pinned artifact), so materializing the core writes the SAME
//! `~/.burn/ruby-<release>` dir a fetch would, and a later online run re-uses
//! it (a cache hit).

use std::path::{Path, PathBuf};

/// The standalone `ruby.wasm` interpreter, baked in at build time.
static RUBY_WASM: &[u8] = include_bytes!(concat!(env!("AFTERBURNER_EMBED_RUBY_DIR"), "/ruby.wasm"));

/// The `usr/` stdlib tree as a plain (uncompressed) tar, baked in at build time.
static RUBY_USR_TAR: &[u8] =
    include_bytes!(concat!(env!("AFTERBURNER_EMBED_RUBY_DIR"), "/ruby_usr.tar"));

/// Materialize the embedded Ruby runtime into `~/.burn/ruby-<release>` (the
/// same dir a network fetch targets) and return it, so the existing path-based
/// runner mounts it unchanged. Idempotent: a dir already carrying both the
/// interpreter and the versioned stdlib ABI dir is a no-op.
///
/// The write is atomic: bytes land in a sibling staging dir that is renamed
/// into place, so a crash mid-write never leaves a half-populated bundle that
/// reads back as complete.
pub fn materialize_core(home: &Path) -> Result<PathBuf, String> {
    let dir = crate::bundle::ruby_dir(home);

    // A complete bundle: wasm + versioned stdlib ABI dir both present.
    let wasm_ok = dir.join("ruby.wasm").exists();
    let stdlib_ok = dir
        .join("usr/local/lib/ruby")
        .join(crate::bundle::RUBY_ABI_VERSION)
        .exists();
    if wasm_ok && stdlib_ok {
        return Ok(dir);
    }

    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let staging = dir.with_file_name(format!("ruby-embed.staging-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("mkdir {}: {e}", staging.display()))?;

    let result = (|| {
        // Write the interpreter.
        std::fs::write(staging.join("ruby.wasm"), RUBY_WASM)
            .map_err(|e| format!("write ruby.wasm: {e}"))?;

        // Extract the usr/ stdlib tar.
        let mut ar = tar::Archive::new(RUBY_USR_TAR);
        ar.unpack(&staging)
            .map_err(|e| format!("unpack ruby_usr.tar: {e}"))?;

        // Write the manifest (matches the format ensure_ruby produces).
        let manifest = format!(
            "release={}\nruby={}\nwasm=ruby.wasm\nusr=usr\n",
            crate::bundle::RUBY_RELEASE,
            crate::bundle::RUBY_ABI_VERSION,
        );
        std::fs::write(staging.join("manifest.txt"), manifest)
            .map_err(|e| format!("write manifest.txt: {e}"))?;

        // Clear the target (a stale half-populated dir from a prior run).
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

    /// The embedded bytes are non-empty and shaped correctly: wasm magic for the
    /// interpreter, non-empty tar for the stdlib tree.
    #[test]
    fn embedded_ruby_bytes_are_present_and_shaped() {
        assert!(RUBY_WASM.len() > 1_000_000, "ruby.wasm looks too small");
        assert_eq!(&RUBY_WASM[0..4], b"\0asm", "ruby.wasm lacks the wasm magic");
        assert!(
            RUBY_USR_TAR.len() > 1_000_000,
            "ruby_usr.tar looks too small"
        );
        // A plain tar's first header is a 512-byte block; the last 100 bytes of the
        // filename field (bytes 0-99) form a NUL-padded C string starting with "usr".
        assert!(
            RUBY_USR_TAR[..100].starts_with(b"usr"),
            "ruby_usr.tar first entry should start with 'usr'"
        );
    }

    /// Materializing into a fresh home writes the interpreter, extracts the stdlib
    /// tree, writes the manifest, and a second call is a no-op (idempotent).
    #[test]
    fn materialize_is_atomic_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = materialize_core(tmp.path()).expect("materialize");
        assert!(dir.join("ruby.wasm").exists(), "ruby.wasm must be written");
        assert!(
            dir.join("usr/local/lib/ruby")
                .join(crate::bundle::RUBY_ABI_VERSION)
                .exists(),
            "versioned stdlib ABI dir must exist"
        );
        let manifest = std::fs::read_to_string(dir.join("manifest.txt")).unwrap();
        assert!(manifest.contains("wasm=ruby.wasm"));
        assert!(manifest.contains("usr=usr"));
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
