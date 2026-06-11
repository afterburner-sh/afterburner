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
