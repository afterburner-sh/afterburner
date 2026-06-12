// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Local content-addressed cache for downloaded `.afb` packages
//! (`~/.cache/burn/packages/<digest>.afb`). The on-disk name *is* the SHA-256
//! of the bytes, so a present file is already verified by construction.

use crate::error::{CloudError, Result};
use afterburner_afb::digest::{digest, hex};
use std::path::{Path, PathBuf};

/// `~/.cache/burn/packages`.
pub fn cache_root() -> Result<PathBuf> {
    let dir = dirs::cache_dir().ok_or(CloudError::NoCacheDir)?;
    Ok(dir.join("burn").join("packages"))
}

/// The on-disk path a given content digest maps to.
pub fn path_for(digest_hex: &str) -> Result<PathBuf> {
    Ok(cache_root()?.join(format!("{digest_hex}.afb")))
}

/// Whether the cache already holds a package with this digest.
pub fn contains(digest_hex: &str) -> bool {
    path_for(digest_hex).map(|p| p.exists()).unwrap_or(false)
}

/// Outcome of [`verify_and_store`].
#[derive(Debug)]
pub struct Stored {
    /// Where the verified `.afb` now lives.
    pub path: PathBuf,
    /// A non-fatal note (e.g. the package targets a newer runtime than this
    /// `burn`): the bytes were cached, but may not run locally.
    pub warning: Option<String>,
}

/// Verify `bytes` hash to `expected_hex`, fully parse them as a `.afb` (size,
/// path, manifest, manifold checks), then atomically store under the content
/// address.
///
/// A digest mismatch is fatal ([`CloudError::DigestMismatch`]) - the registry
/// handed us the wrong bytes. A `RuntimeTooOld` parse result is *not* fatal:
/// the archive is well-formed, it just needs a newer engine, so it is cached
/// with a warning.
pub fn verify_and_store(expected_hex: &str, bytes: &[u8]) -> Result<Stored> {
    let got = hex(&digest(bytes));
    if !got.eq_ignore_ascii_case(expected_hex.trim_start_matches("sha256:")) {
        return Err(CloudError::DigestMismatch {
            expected: expected_hex.trim_start_matches("sha256:").to_string(),
            got,
        });
    }

    let mut warning = None;
    match afterburner_afb::Afb::from_bytes(bytes) {
        Ok(_) => {}
        Err(afterburner_afb::error::AfbError::RuntimeTooOld { required, running }) => {
            warning = Some(format!(
                "package needs runtime >= {required}, this burn is {running}; cached, but it may not run here"
            ));
        }
        Err(e) => return Err(CloudError::Afb(e)),
    }

    let path = path_for(&got)?;
    write_atomic(&path, bytes)?;
    Ok(Stored { path, warning })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CloudError::Cache("cache path has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("afb.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// `~/.cache/burn/pkg-src` - extracted, require-ready package trees, one
/// dir per content digest (immutable once complete, like the npm cache).
pub fn src_root() -> Result<PathBuf> {
    let dir = dirs::cache_dir().ok_or(CloudError::NoCacheDir)?;
    Ok(dir.join("burn").join("pkg-src"))
}

/// Extract a cached `.afb` into its `pkg-src/<digest>` tree, generating a
/// `package.json` whose `main` points at the manifest entry - exactly the
/// shape the module loader resolves for any `node_modules` entry. Returns
/// the extracted dir; idempotent (a complete dir is reused as-is).
///
/// # Errors
/// I/O failure, a missing blob, or a corrupt archive.
pub fn ensure_extracted(digest_hex: &str) -> Result<PathBuf> {
    let dir = src_root()?.join(digest_hex);
    if dir.join(".burn-complete").exists() {
        return Ok(dir);
    }
    let blob = path_for(digest_hex)?;
    let bytes = std::fs::read(&blob)
        .map_err(|e| CloudError::Cache(format!("reading {}: {e}", blob.display())))?;
    let afb = afterburner_afb::Afb::from_bytes(&bytes)
        .map_err(|e| CloudError::Cache(format!("parsing {}: {e}", blob.display())))?;

    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    for (rel, data) in &afb.source {
        let p = tmp.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, data)?;
    }
    let pkg_json = serde_json::json!({
        "name": afb.qualified_name(),
        "version": afb.manifest.package.version,
        "main": afb.manifest.package.entry,
    });
    std::fs::write(
        tmp.join("package.json"),
        serde_json::to_string_pretty(&pkg_json).map_err(|e| CloudError::Cache(e.to_string()))?,
    )?;
    std::fs::write(tmp.join(".burn-complete"), b"1")?;
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&tmp, &dir)?;
    Ok(dir)
}

/// Symlink `link` -> `target` (a copy on platforms without symlinks),
/// replacing whatever was there. The same primitive the npm linker uses
/// for materializing `node_modules` entries.
pub fn link_dir(target: &Path, link: &Path) -> Result<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(link);
    let _ = std::fs::remove_dir_all(link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link)?;
    #[cfg(not(unix))]
    crate::npm::copy_dir_for_link(target, link)?;
    Ok(())
}
