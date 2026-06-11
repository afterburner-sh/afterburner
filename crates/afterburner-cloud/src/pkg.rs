// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! A local package directory (`afb.toml` + `manifold.json` + `source/`) and
//! how to build its reproducible `.afb`. Reuses [`afterburner_afb::pack::Builder`]
//! so a package built by `burn` is byte-identical to one built by the registry
//! tooling, and shares the digest the registry content-addresses by.

use crate::error::{CloudError, Result};
use afterburner_afb::{Manifest, Manifold};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A package loaded from a directory on disk.
pub struct LocalPackage {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub manifold: Manifold,
    /// `source/…` files keyed by archive-relative path.
    pub sources: BTreeMap<String, Vec<u8>>,
}

impl LocalPackage {
    /// Load `afb.toml`, `manifold.json`, and every file under `source/`.
    pub fn load(dir: &Path) -> Result<Self> {
        let manifest_path = dir.join("afb.toml");
        let manifest_src = std::fs::read_to_string(&manifest_path).map_err(|e| {
            CloudError::Package(format!("reading {}: {e}", manifest_path.display()))
        })?;
        let manifest = Manifest::parse(&manifest_src)?;

        let manifold_path = dir.join("manifold.json");
        let manifold_src = std::fs::read_to_string(&manifold_path).map_err(|e| {
            CloudError::Package(format!("reading {}: {e}", manifold_path.display()))
        })?;
        let manifold: Manifold = serde_json::from_str(&manifold_src)
            .map_err(|e| CloudError::Package(format!("{}: {e}", manifold_path.display())))?;

        let mut sources = BTreeMap::new();
        let source_root = dir.join("source");
        collect_sources(&source_root, &mut sources)?;

        if !sources.contains_key(&manifest.package.entry) {
            return Err(CloudError::Package(format!(
                "entry {:?} (from afb.toml) is not present under source/",
                manifest.package.entry
            )));
        }

        Ok(Self {
            dir: dir.to_path_buf(),
            manifest,
            manifold,
            sources,
        })
    }

    /// Build the reproducible `.afb`. Returns `(bytes, sha256)`.
    pub fn build(&self) -> Result<(Vec<u8>, [u8; 32])> {
        let mut b =
            afterburner_afb::pack::Builder::new(self.manifest.clone(), self.manifold.clone());
        for (path, data) in &self.sources {
            b = b.source(path.clone(), data.clone());
        }
        Ok(b.build()?)
    }

    /// The cargo-style default output name: `<ns>-<name>-<ver>.afb`.
    pub fn output_filename(&self) -> String {
        format!(
            "{}-{}-{}.afb",
            self.manifest.package.namespace,
            self.manifest.package.name,
            self.manifest.package.version
        )
    }
}

/// Pin a dependency into a package's `afb.toml` `[dependencies]` table by
/// digest (`"ns/name" = "sha256:…"`) and rewrite the manifest in place.
pub fn add_dependency(dir: &Path, qualified: &str, digest_hex: &str) -> Result<()> {
    let manifest_path = dir.join("afb.toml");
    let src = std::fs::read_to_string(&manifest_path)
        .map_err(|e| CloudError::Package(format!("reading {}: {e}", manifest_path.display())))?;
    let mut manifest = Manifest::parse(&src)?;
    let pin = format!("sha256:{}", digest_hex.trim_start_matches("sha256:"));
    manifest.dependencies.insert(qualified.to_string(), pin);
    let out = manifest.to_toml_string()?;
    write_atomic_text(&manifest_path, &out)
}

fn collect_sources(root: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    fn walk(root: &Path, cur: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
        for entry in std::fs::read_dir(cur).map_err(CloudError::Io)? {
            let entry = entry.map_err(CloudError::Io)?;
            let ft = entry.file_type().map_err(CloudError::Io)?;
            let path = entry.path();
            if ft.is_dir() {
                walk(root, &path, out)?;
            } else if ft.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| CloudError::Package("source path escaped source/".into()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                let data = std::fs::read(&path).map_err(CloudError::Io)?;
                out.insert(format!("source/{rel}"), data);
            }
            // Symlinks / other entry types are skipped — the `.afb` reader
            // rejects them anyway, so they could never round-trip.
        }
        Ok(())
    }
    if root.exists() {
        walk(root, root, out)?;
    }
    Ok(())
}

fn write_atomic_text(path: &Path, text: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CloudError::Package("manifest path has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).map_err(CloudError::Io)?;
    std::fs::rename(&tmp, path).map_err(CloudError::Io)?;
    Ok(())
}
