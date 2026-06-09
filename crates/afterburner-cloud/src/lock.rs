// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn.lock` - the resolved, pinned dependency set for reproducible installs.
//! A locked install skips resolution entirely and just fetches + verifies the
//! recorded digests, so it is both faster and deterministic.

use crate::error::{CloudError, Result};
use crate::resolve::Resolution;
use serde::{Deserialize, Serialize};

/// Lockfile filename, alongside `afb.toml`.
pub const LOCKFILE_NAME: &str = "burn.lock";
const LOCK_VERSION: u32 = 1;

/// The full lockfile. Packages are sorted by `name` for a stable, diff-friendly
/// file (the resolution uses a `BTreeMap`, so this is deterministic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lockfile {
    pub version: u32,
    #[serde(default, rename = "package")]
    pub packages: Vec<LockedPackage>,
}

/// One pinned package in the lock.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPackage {
    /// `namespace/name`.
    pub name: String,
    pub version: String,
    /// `sha256:<hex>` - the exact content to fetch + verify.
    pub digest: String,
    /// Resolved dependency coords (sorted), for the runtime loader.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
}

impl Lockfile {
    /// Build a lockfile from a [`Resolution`].
    pub fn from_resolution(r: &Resolution) -> Self {
        let packages = r
            .selected
            .iter()
            .map(|(coord, p)| LockedPackage {
                name: coord.clone(),
                version: p.version.to_string(),
                digest: format!("sha256:{}", p.digest.trim_start_matches("sha256:")),
                dependencies: p.deps.clone(),
            })
            .collect();
        Lockfile { version: LOCK_VERSION, packages }
    }

    /// Serialize to TOML for writing to `burn.lock`.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| CloudError::Package(format!("serializing {LOCKFILE_NAME}: {e}")))
    }

    /// Parse a `burn.lock`.
    pub fn parse(s: &str) -> Result<Self> {
        let lf: Lockfile = toml::from_str(s)
            .map_err(|e| CloudError::Package(format!("parsing {LOCKFILE_NAME}: {e}")))?;
        if lf.version != LOCK_VERSION {
            return Err(CloudError::Package(format!(
                "unsupported {LOCKFILE_NAME} version {} (this burn understands {LOCK_VERSION})",
                lf.version
            )));
        }
        Ok(lf)
    }

    /// `(name, digest-hex)` pairs to fetch - the input to a concurrent install.
    /// Digests are bare hex (no `sha256:` prefix).
    pub fn fetch_set(&self) -> Vec<(String, String)> {
        self.packages
            .iter()
            .map(|p| (p.name.clone(), p.digest.trim_start_matches("sha256:").to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{Resolution, SelectedPkg};
    use semver::Version;
    use std::collections::BTreeMap;

    #[test]
    fn round_trips_through_toml() {
        let mut selected = BTreeMap::new();
        selected.insert(
            "psila/a".to_string(),
            SelectedPkg {
                version: Version::parse("1.2.0").unwrap(),
                digest: "aa".to_string(),
                deps: vec!["psila/b".to_string()],
            },
        );
        selected.insert(
            "psila/b".to_string(),
            SelectedPkg { version: Version::parse("0.3.1").unwrap(), digest: "bb".to_string(), deps: vec![] },
        );
        let res = Resolution { order: vec!["psila/b".into(), "psila/a".into()], selected };

        let lock = Lockfile::from_resolution(&res);
        let toml = lock.to_toml().unwrap();
        let back = Lockfile::parse(&toml).unwrap();
        assert_eq!(lock, back);
        assert_eq!(back.packages.len(), 2);
        assert!(back.packages.iter().any(|p| p.name == "psila/a" && p.digest == "sha256:aa"));
        assert_eq!(back.fetch_set().iter().find(|(n, _)| n == "psila/a").unwrap().1, "aa");
    }

    #[test]
    fn rejects_unknown_version() {
        let err = Lockfile::parse("version = 999\n").unwrap_err();
        assert!(matches!(err, CloudError::Package(_)));
    }
}
