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
    /// When true, `build_wasm_only` drops every `source/*` entry so the emitted
    /// `.afb` contains only `afb.toml`, `manifold.json`, and `precompiled/*`
    /// members. Not used by `build()`, which preserves all entries.
    omit_source: bool,
}

impl Builder {
    /// Start from a manifest and the package's sandbox manifold.
    pub fn new(manifest: Manifest, manifold: Manifold) -> Self {
        Self {
            manifest,
            manifold,
            files: BTreeMap::new(),
            omit_source: false,
        }
    }

    /// Configure the builder to drop all `source/*` entries when
    /// [`build_wasm_only`](Builder::build_wasm_only) is called.
    ///
    /// Has no effect on [`build`](Builder::build).
    pub fn omit_source(mut self, yes: bool) -> Self {
        self.omit_source = yes;
        self
    }

    /// Add a source file at an archive path (must be under `source/`).
    pub fn source(mut self, path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.into(), contents.into());
        self
    }

    /// Add a pre-compiled WASM artifact at an archive-relative path (must be
    /// under `precompiled/`). The path is inserted into the same sorted
    /// `files` map as source entries, so the reproducible-digest invariant
    /// (zstd-19, entries in sorted order, mtime=0) holds automatically.
    ///
    /// Convention for `rel_path`:
    /// - `"precompiled/wasm32-wasip1/main.wasm"` for a self-contained module.
    /// - `"precompiled/wasm32-wasip1-dyn/main.wasm"` for a dynamically-linked
    ///   module (requires the shared plugin host at instantiation time).
    ///
    /// Set `manifest.runtime.target` to the target string so readers know
    /// which `precompiled/` sub-directory to look in.
    pub fn precompiled(mut self, rel_path: impl Into<String>, bytes: Vec<u8>) -> Self {
        self.files.insert(rel_path.into(), bytes);
        self
    }

    /// Build a WASM-only `.afb`: identical to [`build`](Builder::build) except
    /// that every `source/*` entry is dropped.
    ///
    /// The resulting archive contains only `afb.toml`, `manifold.json`, and any
    /// `precompiled/*` members added via [`precompiled`](Builder::precompiled).
    ///
    /// Errors when no `precompiled/*` member has been added, because shipping
    /// an `.afb` with neither source nor a precompiled WASM is not useful.
    ///
    /// Returns `(compressed_bytes, sha256(compressed_bytes))`.
    pub fn build_wasm_only(mut self) -> Result<(Vec<u8>, [u8; 32])> {
        let has_precompiled = self.files.keys().any(|k| k.starts_with("precompiled/"));
        if !has_precompiled {
            return Err(AfbError::Corrupt(
                "build_wasm_only requires at least one precompiled/ member; \
                 none were added via Builder::precompiled"
                    .into(),
            ));
        }
        self.omit_source = true;
        self.build_inner()
    }

    /// Serialize, tar (reproducibly), zstd-compress, and digest.
    ///
    /// The `omit_source` flag (set via [`omit_source`](Builder::omit_source))
    /// has no effect here - `build()` always includes all entries.
    ///
    /// Returns `(compressed_bytes, sha256(compressed_bytes))`.
    pub fn build(mut self) -> Result<(Vec<u8>, [u8; 32])> {
        // `omit_source` only applies to `build_wasm_only`; always include
        // source here regardless of what the caller set.
        self.omit_source = false;
        self.build_inner()
    }

    fn build_inner(self) -> Result<(Vec<u8>, [u8; 32])> {
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
            if self.omit_source && path.starts_with("source/") {
                continue;
            }
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
