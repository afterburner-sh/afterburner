// SPDX-License-Identifier: Apache-2.0
//! `afb.toml` - the package manifest (§3.2) and its evolution policy.
//!
//! Precedent: Python wheels (`Wheel-Version` major/minor: refuse greater
//! major, accept greater minor), npm/Debian (unknown descriptive fields are
//! *ignored*, never hard-rejected, which is what lets an old reader read a
//! newer package), Cargo (`[package.metadata]` reserved namespace).
//!
//! So this is **deliberately not** `deny_unknown_fields` on the descriptive
//! structs - that would make every additive change a breaking change.
//! `Signature` *stays* strict: an identity block with an unexpected field is
//! suspicious and must not be silently tolerated. The capability set itself
//! lives in `afterburner_core::Manifold` (parsed in `unpack`), whose
//! strictness is that crate's responsibility - see `FORMAT.md`.

use crate::error::{AfbError, Result};
use crate::{FORMAT_MAJOR, FORMAT_MINOR};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Parsed `afb.toml`.
///
/// Unknown *top-level sections* are preserved in [`Manifest::extra`] so a
/// parse → repack round-trips a newer additive package without data loss.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: Format,
    pub package: Package,
    pub runtime: Runtime,
    /// Other `.afb` packages this one depends on, pinned by digest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, String>,
    /// npm packages this one depends on, declared `name = "semver-range"`
    /// (cargo-style). `burn install` resolves + vendors them into
    /// `source/node_modules/**`; the sandbox `require()` then serves bare
    /// specifiers from there. Vendored code runs under THIS package's
    /// manifold - it can reach nothing the package itself is not granted.
    #[serde(default, rename = "npm", skip_serializing_if = "BTreeMap::is_empty")]
    pub npm: BTreeMap<String, String>,
    /// Phase-2 signature block. Parsed (strictly) if present so a signed
    /// package round-trips; v0.1 does not verify it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// Reserved free-form namespace (à la Cargo `[package.metadata]`): tools
    /// may put anything here, readers never interpret it, it round-trips.
    #[serde(default, skip_serializing_if = "toml::Table::is_empty")]
    pub metadata: toml::Table,
    /// Unknown top-level sections from a newer minor, preserved verbatim.
    /// Not a wire field - captured/merged by [`Manifest::parse`] /
    /// [`Manifest::to_toml_string`].
    #[serde(skip)]
    pub extra: toml::Table,
}

/// `[format]`. Not `deny_unknown_fields`: a future minor may add format-level
/// keys; one that is *unsafe to ignore* must instead set `min_reader`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Format {
    /// `"MAJOR.MINOR"`.
    pub version: String,
    /// Optional hard floor: reject if this reader is older than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_reader: Option<String>,
}

/// `[package]`. Tolerant of unknown keys (additive evolution).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub namespace: String,
    pub version: String,
    pub language: String,
    pub entry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Free-form search keywords. The registry full-text-indexes these.
    /// An older reader tolerates-then-drops the key (it is descriptive, not a
    /// gate); serialized only when non-empty so sealed packages stay terse.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

/// `[runtime]`. Tolerant of unknown keys - the actual gate is the semver
/// `min` check in [`crate::version`], not field presence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runtime {
    /// Minimum `afterburner-core` version, semver.
    pub min: String,
    /// Precompiled-artifact target; only meaningful with `precompiled/`,
    /// which v0.1 ignores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// `[signature]` - **strict** (`deny_unknown_fields`). Identity/security
/// surface: an unexpected key here is rejected, not tolerated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub algorithm: String,
    pub public_key: String,
}

/// Parse `"MAJOR.MINOR"` (both non-negative integers).
fn parse_mm(s: &str, what: &str) -> Result<(u32, u32)> {
    let s = s.trim();
    let (maj, min) = s
        .split_once('.')
        .ok_or_else(|| AfbError::ManifestParse(format!("{what} {s:?} must be \"MAJOR.MINOR\"")))?;
    let bad = || AfbError::ManifestParse(format!("{what} {s:?} must be \"MAJOR.MINOR\""));
    Ok((
        maj.parse().map_err(|_| bad())?,
        min.parse().map_err(|_| bad())?,
    ))
}

impl Manifest {
    /// Parse, apply the format-evolution gate, and structurally validate.
    ///
    /// Rejects: a `format.version` whose **major** differs from this reader's
    /// ([`AfbError::FormatVersion`] - refuse, never misparse); a
    /// `[format] min_reader` newer than this reader
    /// ([`AfbError::ReaderTooOld`]); a non-semver `package.version`; an
    /// empty/escaping `package.entry`. A **greater minor is accepted** (the
    /// additive contract). Unknown descriptive keys are tolerated; unknown
    /// top-level sections are preserved in [`Manifest::extra`].
    pub fn parse(toml_src: &str) -> Result<Self> {
        let mut m: Manifest =
            toml::from_str(toml_src).map_err(|e| AfbError::ManifestParse(e.to_string()))?;

        // Capture unknown top-level sections for loss-free round-trip.
        let doc: toml::Table =
            toml::from_str(toml_src).map_err(|e| AfbError::ManifestParse(e.to_string()))?;
        let mut extra = doc;
        for known in [
            "format",
            "package",
            "runtime",
            "dependencies",
            "npm",
            "signature",
            "metadata",
        ] {
            extra.remove(known);
        }
        m.extra = extra;

        // --- format-evolution gate (the heart of this module) -------------
        let (fmaj, fmin) = parse_mm(&m.format.version, "format.version")?;
        if fmaj != FORMAT_MAJOR {
            // Greater major = too new; lesser major = a different epoch this
            // reader has not been taught to migrate. Either way: refuse,
            // loudly, rather than misinterpret.
            return Err(AfbError::FormatVersion {
                found: m.format.version.clone(),
                supported: format!("{FORMAT_MAJOR}.x"),
            });
        }
        let _ = fmin; // a greater minor is fine: additive, simply not acted on
        if let Some(mr) = &m.format.min_reader {
            let req = parse_mm(mr, "format.min_reader")?;
            if req > (FORMAT_MAJOR, FORMAT_MINOR) {
                return Err(AfbError::ReaderTooOld {
                    required: mr.clone(),
                    running: format!("{FORMAT_MAJOR}.{FORMAT_MINOR}"),
                });
            }
        }

        // --- structural validation ---------------------------------------
        semver::Version::parse(&m.package.version).map_err(|e| {
            AfbError::ManifestParse(format!("package.version {:?}: {e}", m.package.version))
        })?;
        if m.package.name.is_empty() || m.package.namespace.is_empty() {
            return Err(AfbError::ManifestParse(
                "package.name and package.namespace must be non-empty".into(),
            ));
        }
        let entry = &m.package.entry;
        if entry.is_empty()
            || entry.starts_with('/')
            || entry.split('/').any(|c| c == ".." || c == ".")
            || !entry.starts_with("source/")
        {
            return Err(AfbError::ManifestParse(format!(
                "package.entry {entry:?} must be a relative path under source/"
            )));
        }
        Ok(m)
    }

    /// Serialize back to canonical TOML, merging preserved unknown sections.
    /// `toml::Table` is sorted, so this stays byte-deterministic (the basis
    /// of reproducible `.afb`).
    pub fn to_toml_string(&self) -> Result<String> {
        let value =
            toml::Value::try_from(self).map_err(|e| AfbError::ManifestParse(e.to_string()))?;
        let mut table = value.as_table().cloned().ok_or_else(|| {
            AfbError::ManifestParse("manifest did not serialize to a table".into())
        })?;
        for (k, v) in &self.extra {
            table.entry(k.clone()).or_insert_with(|| v.clone());
        }
        toml::to_string(&table).map_err(|e| AfbError::ManifestParse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> &'static str {
        r#"
[format]
version = "1.0"

[package]
name = "anthropic"
namespace = "burn"
version = "1.4.0"
language = "js"
entry = "source/main.js"
description = "Anthropic client"

[runtime]
min = "0.1.0"
"#
    }

    #[test]
    fn parses_a_valid_manifest() {
        let m = Manifest::parse(good()).unwrap();
        assert_eq!(m.package.name, "anthropic");
        assert_eq!(m.format.version, "1.0");
        assert!(m.dependencies.is_empty());
        assert!(m.signature.is_none());
        assert!(m.extra.is_empty());
    }

    #[test]
    fn greater_major_is_refused() {
        for v in ["2.0", "99.0", "0.9"] {
            let src = good().replace("\"1.0\"", &format!("\"{v}\""));
            assert!(
                matches!(Manifest::parse(&src), Err(AfbError::FormatVersion { .. })),
                "format.version {v} must be refused"
            );
        }
    }

    #[test]
    fn greater_minor_is_accepted_additively() {
        // A package from a future minor still parses on this reader.
        let src = good().replace("\"1.0\"", "\"1.7\"");
        let m = Manifest::parse(&src).expect("greater minor is additive");
        assert_eq!(m.format.version, "1.7");
    }

    #[test]
    fn malformed_version_is_rejected() {
        for v in ["1", "1.x", "", "abc"] {
            let src = good().replace("\"1.0\"", &format!("\"{v}\""));
            assert!(matches!(
                Manifest::parse(&src),
                Err(AfbError::ManifestParse(_))
            ));
        }
    }

    #[test]
    fn min_reader_newer_than_reader_is_rejected() {
        let src = good().replace(
            "version = \"1.0\"",
            "version = \"1.0\"\nmin_reader = \"1.99\"",
        );
        assert!(matches!(
            Manifest::parse(&src),
            Err(AfbError::ReaderTooOld { .. })
        ));
    }

    #[test]
    fn min_reader_satisfied_is_ok() {
        let src = good().replace(
            "version = \"1.0\"",
            "version = \"1.0\"\nmin_reader = \"1.0\"",
        );
        assert!(Manifest::parse(&src).is_ok());
    }

    #[test]
    fn unknown_descriptive_key_is_tolerated() {
        // npm/Debian behavior: an unknown key in a known table does not
        // break an older reader.
        let src = good().replace(
            "language = \"js\"",
            "language = \"js\"\nfuture_hint = \"ignored\"",
        );
        assert!(Manifest::parse(&src).is_ok());
    }

    #[test]
    fn unknown_top_level_section_is_preserved() {
        let src = format!("{good}\n[provenance]\nbuilt_by = \"ci\"\n", good = good());
        let m = Manifest::parse(&src).unwrap();
        assert!(m.extra.contains_key("provenance"), "extra: {:?}", m.extra);
        // …and survives a repack.
        let back = Manifest::parse(&m.to_toml_string().unwrap()).unwrap();
        assert_eq!(back.extra, m.extra);
    }

    #[test]
    fn signature_is_strict() {
        let src = format!(
            "{good}\n[signature]\nalgorithm = \"ed25519\"\npublic_key = \"AA\"\nrogue = true\n",
            good = good()
        );
        assert!(
            matches!(Manifest::parse(&src), Err(AfbError::ManifestParse(_))),
            "an unexpected key in [signature] must be rejected"
        );
    }

    #[test]
    fn reserved_metadata_namespace_roundtrips() {
        let src = format!("{good}\n[metadata.ci]\npipeline = \"gha\"\n", good = good());
        let m = Manifest::parse(&src).unwrap();
        assert!(!m.metadata.is_empty());
        assert_eq!(Manifest::parse(&m.to_toml_string().unwrap()).unwrap(), m);
    }

    #[test]
    fn non_semver_package_version_is_rejected() {
        let src = good().replace("version = \"1.4.0\"", "version = \"not-semver\"");
        assert!(matches!(
            Manifest::parse(&src),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn entry_escaping_source_is_rejected() {
        for bad in ["main.js", "/etc/passwd", "source/../../etc/passwd"] {
            let src = good().replace("source/main.js", bad);
            assert!(
                matches!(Manifest::parse(&src), Err(AfbError::ManifestParse(_))),
                "entry {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn manifest_toml_roundtrips() {
        let m = Manifest::parse(good()).unwrap();
        let back = Manifest::parse(&m.to_toml_string().unwrap()).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn dependencies_roundtrip() {
        let src = format!(
            "{good}\n[dependencies]\n\"burn/http-helpers\" = \"sha256:aabb\"\n",
            good = good()
        );
        let m = Manifest::parse(&src).unwrap();
        assert_eq!(m.dependencies["burn/http-helpers"], "sha256:aabb");
        assert_eq!(Manifest::parse(&m.to_toml_string().unwrap()).unwrap(), m);
    }
}
