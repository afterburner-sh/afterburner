// SPDX-License-Identifier: Apache-2.0
//! Building a reproducible `.afb` (Step 34 / §3.3).
//!
//! Same inputs → byte-identical output, on any machine: entries are written
//! in sorted order, every header field that could carry host state
//! (`mtime`, `uid`, `gid`, owner names) is pinned to 0/empty, and zstd runs
//! single-threaded at a fixed level. The returned digest is the SHA-256 of
//! the exact compressed bytes - the package's content address.

use crate::Manifold;
use crate::digest::digest;
use crate::error::{AfbError, Result};
use crate::manifest::Manifest;
use std::collections::BTreeMap;

/// zstd level. 19 is the §3.3 invariant: near-max ratio, and decode cost is
/// level-independent so the smaller artifact is a pure runtime win. Not 22 -
/// `--ultra` can enlarge the decode window, raising unpack memory.
pub const ZSTD_LEVEL: i32 = 19;

/// Builder for an `.afb`. Reuses `afterburner_core::Manifold` so the sealed
/// manifest serialized here is the exact type the runtime enforces.
pub struct Builder {
    manifest: Manifest,
    manifold: Manifold,
    /// Archive-relative path → file contents. `BTreeMap` = deterministic order.
    files: BTreeMap<String, Vec<u8>>,
}

impl Builder {
    /// Start from a manifest and the package's sandbox manifold.
    pub fn new(manifest: Manifest, manifold: Manifold) -> Self {
        Self {
            manifest,
            manifold,
            files: BTreeMap::new(),
        }
    }

    /// Add a source file at an archive path (must be under `source/`).
    pub fn source(mut self, path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.into(), contents.into());
        self
    }

    /// Serialize, tar (reproducibly), zstd-compress, and digest.
    ///
    /// Returns `(compressed_bytes, sha256(compressed_bytes))`.
    pub fn build(self) -> Result<(Vec<u8>, [u8; 32])> {
        // Validate the manifest the same way the unpacker will, so a
        // Builder can't emit a package that fails its own `from_bytes`.
        let manifest_toml = self.manifest.to_toml_string()?;
        Manifest::parse(&manifest_toml)?;

        // Fail-closed on native/C-ABI/N-API artifacts (e.g. a vendored
        // npm dep carrying a `.node` addon): the WASM sandbox can never
        // load them, and shipping one is a sandbox-escape red flag.
        crate::native::reject_native(self.files.keys().map(String::as_str))?;

        let manifold_json = serde_json::to_vec(&self.manifold)
            .map_err(|e| AfbError::ManifoldParse(e.to_string()))?;

        // Canonical entry set, sorted (BTreeMap).
        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        entries.insert("afb.toml".into(), manifest_toml.into_bytes());
        entries.insert("manifold.json".into(), manifold_json);
        for (path, data) in self.files {
            entries.insert(path, data);
        }

        let mut ar = tar::Builder::new(Vec::new());
        for (path, data) in &entries {
            let mut h = tar::Header::new_ustar();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_uid(0);
            h.set_gid(0);
            h.set_entry_type(tar::EntryType::Regular);
            // append_data writes the path into the header and recomputes the
            // checksum last - do not set_cksum manually.
            ar.append_data(&mut h, path, data.as_slice())
                .map_err(AfbError::Io)?;
        }
        let tar_bytes = ar.into_inner().map_err(AfbError::Io)?;

        let compressed =
            zstd::encode_all(tar_bytes.as_slice(), ZSTD_LEVEL).map_err(AfbError::Io)?;
        let d = digest(&compressed);
        Ok((compressed, d))
    }
}
