// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `burn.lock` - the resolved, pinned dependency set for reproducible installs.
//! A locked install skips resolution entirely and just fetches + verifies the
//! recorded digests, so it is both faster and deterministic.
//!
//! ## Format versions
//!
//! - `version = 1`: afb `[[package]]` entries only.
//! - `version = 2`: adds `[[npm]]`, `[[pip]]`, and `[[gem]]` sections.
//!   A version-1 reader rejects this loudly (the existing
//!   `version != LOCK_VERSION` check at parse time). The version-2 reader
//!   accepts both: a version-1 lock is valid with empty npm/pip/gem sections.

use crate::error::{CloudError, Result};
use crate::install::InstallItem;
use crate::resolve::Resolution;
use serde::{Deserialize, Serialize};

/// Lockfile filename, alongside `afb.toml`.
pub const LOCKFILE_NAME: &str = "burn.lock";
/// Current lockfile format version.
const LOCK_VERSION: u32 = 2;
/// Oldest lockfile version this reader accepts (v1 has no npm/pip/gem sections,
/// which default to empty via `#[serde(default)]` on the Vec fields).
const LOCK_VERSION_MIN: u32 = 1;

/// The full lockfile. Packages are sorted by `name` for a stable, diff-friendly
/// file (the resolution uses a `BTreeMap`, so this is deterministic).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lockfile {
    pub version: u32,
    /// Resolved afb-registry packages (unchanged from v1).
    #[serde(default, rename = "package")]
    pub packages: Vec<LockedPackage>,
    /// Resolved npm packages (new in v2).
    #[serde(default, rename = "npm", skip_serializing_if = "Vec::is_empty")]
    pub npm: Vec<LockedNpmPackage>,
    /// Resolved pip (PyPI) packages (new in v2).
    #[serde(default, rename = "pip", skip_serializing_if = "Vec::is_empty")]
    pub pip: Vec<LockedPipPackage>,
    /// Resolved gem (RubyGems) packages (new in v2).
    #[serde(default, rename = "gem", skip_serializing_if = "Vec::is_empty")]
    pub gem: Vec<LockedGemPackage>,
}

/// One pinned afb-registry package in the lock.
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

/// One pinned npm package in the lock (closes gap G1 from the audit).
///
/// `integrity` is the SRI string from `dist.integrity` (sha512) or, for older
/// packages, the sha1 from `dist.shasum`. The format mirrors the npm-lockfile v3
/// SRI field so it is recognizable and interoperable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedNpmPackage {
    pub name: String,
    pub version: String,
    /// SRI integrity string, e.g. `"sha512-..."` or `"sha1-..."`.
    pub integrity: String,
}

/// One pinned PyPI wheel in the lock.
///
/// `wheel` is the wheel filename (e.g. `requests-2.31.0-py3-none-any.whl`);
/// `integrity` is `"sha256-<base64>"` or `"sha256:<hex>"` depending on source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPipPackage {
    pub name: String,
    pub version: String,
    /// The exact wheel filename that was resolved.
    pub wheel: String,
    /// `sha256-<base64>` or `sha256:<hex>` integrity from PyPI.
    pub integrity: String,
}

/// One pinned RubyGems package in the lock.
///
/// `integrity` is `"sha256:<hex>"` from the RubyGems API `sha` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedGemPackage {
    pub name: String,
    pub version: String,
    /// `sha256:<hex>` from the RubyGems registry.
    pub integrity: String,
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
        Lockfile {
            version: LOCK_VERSION,
            packages,
            npm: Vec::new(),
            pip: Vec::new(),
            gem: Vec::new(),
        }
    }

    /// Serialize to TOML for writing to `burn.lock`.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| CloudError::Package(format!("serializing {LOCKFILE_NAME}: {e}")))
    }

    /// Parse a `burn.lock`.
    ///
    /// Accepts v1 (no npm/pip/gem sections) and v2 (all sections). A version
    /// outside `[1, 2]` is rejected with a loud error naming the supported range.
    pub fn parse(s: &str) -> Result<Self> {
        let mut lf: Lockfile = toml::from_str(s)
            .map_err(|e| CloudError::Package(format!("parsing {LOCKFILE_NAME}: {e}")))?;
        if lf.version < LOCK_VERSION_MIN || lf.version > LOCK_VERSION {
            return Err(CloudError::Package(format!(
                "unsupported {LOCKFILE_NAME} version {} \
                 (this burn understands versions {LOCK_VERSION_MIN} to {LOCK_VERSION}; \
                 run `burn install` to regenerate the lockfile)",
                lf.version
            )));
        }
        // Normalise: a v1 lock on disk stays readable; write it out as v2 next
        // time `burn install` runs (the caller decides when to rewrite).
        // Ensure the version field reflects the actual content, not the wire value,
        // so callers that inspect `lf.version` after parse see the real number.
        // The wire value is preserved so a round-trip of a v1 lock stays v1 until
        // a `from_resolution` call upgrades it.
        // (No upgrade needed here; the parse is lossless for v1.)
        let _ = &mut lf; // used mutably by the serde deserialization above
        Ok(lf)
    }

    /// Build `[[gem]]` lock entries from a resolved gem closure.
    ///
    /// Each entry records `name`, `version`, and the `sha256:<hex>` integrity
    /// string verified during resolution.  Sorted by name for a stable diff.
    pub fn gem_pins_from_resolution(
        res: &crate::ecosystem::EcosystemResolution,
    ) -> Vec<LockedGemPackage> {
        let mut entries: Vec<LockedGemPackage> = res
            .packages
            .iter()
            .map(|p| LockedGemPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                integrity: format!("sha256:{}", p.integrity.trim_start_matches("sha256:")),
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
        entries
    }

    /// Build `[[npm]]` lock entries from a resolved npm closure (closes G1).
    ///
    /// Each entry records `name`, `version`, and the SRI integrity string that
    /// was verified during resolution.  Sorted by name for a stable diff-friendly
    /// lockfile.
    pub fn npm_pins_from_resolution(
        res: &crate::ecosystem::EcosystemResolution,
    ) -> Vec<LockedNpmPackage> {
        let mut entries: Vec<LockedNpmPackage> = res
            .packages
            .iter()
            .map(|p| LockedNpmPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                integrity: p.integrity.clone(),
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
        entries
    }

    /// `(name, digest-hex)` pairs to fetch - the input to a concurrent install.
    /// Digests are bare hex (no `sha256:` prefix).
    pub fn fetch_set(&self) -> Vec<(String, String)> {
        self.packages
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    p.digest.trim_start_matches("sha256:").to_string(),
                )
            })
            .collect()
    }

    /// The locked packages as [`InstallItem`]s for [`crate::install_concurrent`]
    /// (coord + version + bare-hex digest).
    pub fn install_items(&self) -> Vec<InstallItem> {
        self.packages
            .iter()
            .map(|p| {
                InstallItem::new(
                    p.name.clone(),
                    p.version.clone(),
                    p.digest.trim_start_matches("sha256:").to_string(),
                )
            })
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
            "burn/a".to_string(),
            SelectedPkg {
                version: Version::parse("1.2.0").unwrap(),
                digest: "aa".to_string(),
                deps: vec!["burn/b".to_string()],
            },
        );
        selected.insert(
            "burn/b".to_string(),
            SelectedPkg {
                version: Version::parse("0.3.1").unwrap(),
                digest: "bb".to_string(),
                deps: vec![],
            },
        );
        let res = Resolution {
            order: vec!["burn/b".into(), "burn/a".into()],
            selected,
        };

        let lock = Lockfile::from_resolution(&res);
        let toml = lock.to_toml().unwrap();
        let back = Lockfile::parse(&toml).unwrap();
        assert_eq!(lock, back);
        assert_eq!(back.packages.len(), 2);
        assert!(
            back.packages
                .iter()
                .any(|p| p.name == "burn/a" && p.digest == "sha256:aa")
        );
        assert_eq!(
            back.fetch_set()
                .iter()
                .find(|(n, _)| n == "burn/a")
                .unwrap()
                .1,
            "aa"
        );
    }

    #[test]
    fn rejects_unknown_version() {
        let err = Lockfile::parse("version = 999\n").unwrap_err();
        assert!(matches!(err, CloudError::Package(_)));
        let msg = format!("{err}");
        assert!(
            msg.contains("unsupported") && msg.contains("999"),
            "error must name the bad version: {msg}"
        );
    }

    // ---- v2 round-trip (pip + gem + npm sections) ---------------------------

    #[test]
    fn v2_lock_with_all_sections_round_trips() {
        let lock = Lockfile {
            version: LOCK_VERSION,
            packages: vec![LockedPackage {
                name: "acme/core".to_string(),
                version: "1.0.0".to_string(),
                digest: "sha256:aabb".to_string(),
                dependencies: vec![],
            }],
            npm: vec![LockedNpmPackage {
                name: "lodash".to_string(),
                version: "4.17.21".to_string(),
                integrity: "sha512-abcdef==".to_string(),
            }],
            pip: vec![LockedPipPackage {
                name: "requests".to_string(),
                version: "2.31.0".to_string(),
                wheel: "requests-2.31.0-py3-none-any.whl".to_string(),
                integrity: "sha256:deadbeef".to_string(),
            }],
            gem: vec![LockedGemPackage {
                name: "faraday".to_string(),
                version: "2.7.12".to_string(),
                integrity: "sha256:cafebabe".to_string(),
            }],
        };

        let toml_str = lock.to_toml().expect("serialize");
        // The TOML must use the array-of-tables keys.
        assert!(
            toml_str.contains("[[npm]]"),
            "must have [[npm]]: {toml_str}"
        );
        assert!(
            toml_str.contains("[[pip]]"),
            "must have [[pip]]: {toml_str}"
        );
        assert!(
            toml_str.contains("[[gem]]"),
            "must have [[gem]]: {toml_str}"
        );

        let back = Lockfile::parse(&toml_str).expect("parse");
        assert_eq!(lock, back);
        assert_eq!(back.npm.len(), 1);
        assert_eq!(back.npm[0].name, "lodash");
        assert_eq!(back.pip.len(), 1);
        assert_eq!(back.pip[0].wheel, "requests-2.31.0-py3-none-any.whl");
        assert_eq!(back.gem.len(), 1);
        assert_eq!(back.gem[0].integrity, "sha256:cafebabe");
    }

    #[test]
    fn v2_lock_without_optional_sections_is_terse() {
        // A v2 lock with only afb packages must not emit empty [[npm]]/[[pip]]/[[gem]].
        let lock = Lockfile {
            version: LOCK_VERSION,
            packages: vec![LockedPackage {
                name: "ns/x".to_string(),
                version: "0.1.0".to_string(),
                digest: "sha256:00".to_string(),
                dependencies: vec![],
            }],
            npm: vec![],
            pip: vec![],
            gem: vec![],
        };
        let toml_str = lock.to_toml().expect("serialize");
        assert!(
            !toml_str.contains("[[npm]]"),
            "empty npm must be omitted: {toml_str}"
        );
        assert!(
            !toml_str.contains("[[pip]]"),
            "empty pip must be omitted: {toml_str}"
        );
        assert!(
            !toml_str.contains("[[gem]]"),
            "empty gem must be omitted: {toml_str}"
        );
        let back = Lockfile::parse(&toml_str).expect("parse");
        assert_eq!(back.npm, vec![]);
        assert_eq!(back.pip, vec![]);
        assert_eq!(back.gem, vec![]);
    }

    #[test]
    fn v1_lock_parses_on_v2_reader() {
        // A v1 lock (no npm/pip/gem) must still parse on the v2 reader.
        let v1 = "version = 1\n\
                   [[package]]\n\
                   name = \"acme/x\"\n\
                   version = \"1.0.0\"\n\
                   digest = \"sha256:abcd\"\n";
        let lock = Lockfile::parse(v1).expect("v1 lock must be accepted by v2 reader");
        assert_eq!(lock.packages.len(), 1);
        assert_eq!(lock.packages[0].name, "acme/x");
        assert_eq!(lock.npm, vec![]);
        assert_eq!(lock.pip, vec![]);
        assert_eq!(lock.gem, vec![]);
    }

    #[test]
    fn v3_lock_is_rejected_loudly() {
        let v3 = "version = 3\n";
        let err = Lockfile::parse(v3).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("unsupported") && msg.contains("version 3"),
            "must name the bad version: {msg}"
        );
        assert!(
            msg.contains("burn install"),
            "error must hint at `burn install`: {msg}"
        );
    }

    // ---- G1: npm_pins_from_resolution ----------------------------------------

    #[test]
    fn npm_pins_from_resolution_round_trips_through_toml() {
        use crate::ecosystem::{EcosystemPackage, EcosystemResolution};
        use std::collections::BTreeMap;

        let mut res = EcosystemResolution::default();
        res.packages.push(EcosystemPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            integrity: "sha512-abc==".to_string(),
            files: BTreeMap::new(),
        });
        res.packages.push(EcosystemPackage {
            name: "axios".to_string(),
            version: "1.6.0".to_string(),
            integrity: "sha512-xyz==".to_string(),
            files: BTreeMap::new(),
        });

        let pins = Lockfile::npm_pins_from_resolution(&res);
        assert_eq!(pins.len(), 2);
        // Sorted by name: axios before lodash.
        assert_eq!(pins[0].name, "axios");
        assert_eq!(pins[0].integrity, "sha512-xyz==");
        assert_eq!(pins[1].name, "lodash");
        assert_eq!(pins[1].integrity, "sha512-abc==");

        // Embed in a full lockfile, round-trip through TOML.
        let lock = Lockfile {
            version: 2,
            packages: vec![],
            npm: pins,
            pip: vec![],
            gem: vec![],
        };
        let toml_str = lock.to_toml().expect("serialize");
        assert!(
            toml_str.contains("[[npm]]"),
            "must emit [[npm]] sections: {toml_str}"
        );
        let back = Lockfile::parse(&toml_str).expect("parse");
        assert_eq!(back.npm.len(), 2);
        assert_eq!(back.npm[0].name, "axios");
        assert_eq!(back.npm[0].integrity, "sha512-xyz==");
    }
}
