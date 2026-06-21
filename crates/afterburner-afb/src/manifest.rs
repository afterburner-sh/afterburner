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
//!
//! ## `[dependencies]` values (FORMAT_MINOR >= 1)
//!
//! Each value is one of:
//! - A semver range string, e.g. `"^0.1.0"`.
//! - An exact `"sha256:<64-char-hex>"` pin.
//! - A path table: `{ path = "../sibling" }`.
//! - A git table: `{ git = "https://...", tag = "v1" }` (or `branch`/`rev`).
//!
//! [`parse_dep_req`] handles string forms. The custom [`Deserialize`] on
//! [`DepReq`] handles all four forms from TOML.
//!
//! A built `.afb` always carries resolved `sha256:` pins (produced by `pack`);
//! a source `afb.toml` may use ranges, path deps, or git deps for convenience.

use crate::error::{AfbError, Result};
use crate::{FORMAT_MAJOR, FORMAT_MINOR};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The git reference for a `{ git = "..." }` dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRef {
    Tag(String),
    Branch(String),
    Rev(String),
}

/// A parsed `[dependencies]` value.
///
/// String values (`"^0.1.0"` or `"sha256:..."`) are parsed by [`parse_dep_req`].
/// Table values (`{ path = "..." }` or `{ git = "...", tag = "..." }`) are
/// handled by the custom [`Deserialize`] implementation.
#[derive(Debug, Clone, PartialEq)]
pub enum DepReq {
    /// An exact `sha256:<64-char-lowercase-hex>` content pin.
    Pin(String),
    /// A semver version requirement, e.g. `"^0.1.0"` or `">=0.2.0, <1.0.0"`.
    Range(semver::VersionReq),
    /// A local path dependency, relative to the depending package directory.
    Path(std::path::PathBuf),
    /// A git repository dependency.
    Git { url: String, reference: GitRef },
}

// Helper types for DepReq deserialization.
#[derive(Deserialize)]
struct PathTable {
    path: String,
}

#[derive(Deserialize)]
struct GitTable {
    git: String,
    tag: Option<String>,
    branch: Option<String>,
    rev: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawDepReq {
    Str(String),
    PathDep(PathTable),
    GitDep(GitTable),
}

impl<'de> Deserialize<'de> for DepReq {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = RawDepReq::deserialize(d)?;
        match raw {
            RawDepReq::Str(s) => parse_dep_req(&s).map_err(serde::de::Error::custom),
            RawDepReq::PathDep(t) => Ok(DepReq::Path(std::path::PathBuf::from(t.path))),
            RawDepReq::GitDep(t) => {
                if t.git.is_empty() {
                    return Err(serde::de::Error::custom("git url must not be empty"));
                }
                let reference = match (t.tag, t.branch, t.rev) {
                    (Some(tag), None, None) => GitRef::Tag(tag),
                    (None, Some(branch), None) => GitRef::Branch(branch),
                    (None, None, Some(rev)) => GitRef::Rev(rev),
                    _ => {
                        return Err(serde::de::Error::custom(
                            "git dependency must specify exactly one of: tag, branch, rev",
                        ));
                    }
                };
                Ok(DepReq::Git {
                    url: t.git,
                    reference,
                })
            }
        }
    }
}

impl Serialize for DepReq {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            DepReq::Pin(p) => s.serialize_str(p),
            DepReq::Range(r) => s.serialize_str(&r.to_string()),
            DepReq::Path(p) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("path", &p.display().to_string())?;
                m.end()
            }
            DepReq::Git { url, reference } => {
                let (key, val) = match reference {
                    GitRef::Tag(t) => ("tag", t),
                    GitRef::Branch(b) => ("branch", b),
                    GitRef::Rev(r) => ("rev", r),
                };
                let mut m = s.serialize_map(Some(2))?;
                m.serialize_entry("git", url)?;
                m.serialize_entry(key, val)?;
                m.end()
            }
        }
    }
}

/// Parse a single `[dependencies]` string value into a [`DepReq`].
///
/// A value starting with `"sha256:"` is a pin; the remainder must be exactly
/// 64 lowercase hex characters. Any other value is parsed as a
/// [`semver::VersionReq`]. Returns [`AfbError::ManifestParse`] if the value
/// is neither a valid pin nor a valid semver range.
///
/// Note: table-form values (`{ path = "..." }`, `{ git = "...", ... }`) are
/// handled by the [`Deserialize`] impl on [`DepReq`], not this function.
pub fn parse_dep_req(value: &str) -> Result<DepReq> {
    if let Some(hex) = value.strip_prefix("sha256:") {
        if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Ok(DepReq::Pin(value.to_string()));
        }
        return Err(AfbError::ManifestParse(format!(
            "dependency pin {value:?}: expected \"sha256:\" followed by 64 lowercase hex digits"
        )));
    }
    semver::VersionReq::parse(value)
        .map(DepReq::Range)
        .map_err(|e| {
            AfbError::ManifestParse(format!(
                "dependency value {value:?} is neither a sha256 pin nor a valid semver range: {e}"
            ))
        })
}

/// Parsed `afb.toml`.
///
/// Unknown *top-level sections* are preserved in [`Manifest::extra`] so a
/// parse -> repack round-trips a newer additive package without data loss.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: Format,
    pub package: Package,
    pub runtime: Runtime,
    /// Other `.afb` packages this one depends on.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, DepReq>,
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
    /// Reserved free-form namespace (a la Cargo `[package.metadata]`): tools
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
    /// Target of the bundled pre-compiled WASM module (FORMAT_MINOR >= 2).
    ///
    /// When `Some`, the archive contains a member at
    /// `precompiled/<target>/main.wasm` that a capable runtime may load
    /// instead of interpreting the `source/` JS. Two target conventions:
    ///
    /// - `"wasm32-wasip1"` - a self-contained WASI module produced by Javy;
    ///   the runtime loads it directly without any dynamic linking.
    /// - `"wasm32-wasip1-dyn"` - a dynamically-linked module that requires
    ///   the shared Afterburner plugin host; the runtime must provide the
    ///   import namespace before instantiation.
    ///
    /// When `None` (or the reader predates FORMAT_MINOR 2), there is no
    /// pre-compiled module and the runtime falls back to the `source/` JS.
    /// Old readers that do not understand this field silently ignore it.
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
        // Validate git deps have a non-empty URL (deserialization already
        // checked exactly one of tag/branch/rev is set).
        for (coord, dep) in &m.dependencies {
            if let DepReq::Git { url, .. } = dep
                && url.is_empty()
            {
                return Err(AfbError::ManifestParse(format!(
                    "dependency {coord:?}: git url must not be empty"
                )));
            }
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

    /// Returns only the registry (Pin + Range) dependencies as string values,
    /// suitable for passing to the resolver, lockfile, and linker.
    /// Path and Git deps are excluded (they are resolved locally).
    pub fn registry_deps(&self) -> BTreeMap<String, String> {
        self.dependencies
            .iter()
            .filter_map(|(coord, req)| match req {
                DepReq::Pin(p) => Some((coord.clone(), p.clone())),
                DepReq::Range(r) => Some((coord.clone(), r.to_string())),
                DepReq::Path(_) | DepReq::Git { .. } => None,
            })
            .collect()
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
name = "widget"
namespace = "acme"
version = "1.4.0"
language = "js"
entry = "source/main.js"
description = "Widget client"

[runtime]
min = "0.1.0"
"#
    }

    #[test]
    fn parses_a_valid_manifest() {
        let m = Manifest::parse(good()).unwrap();
        assert_eq!(m.package.name, "widget");
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
        // ...and survives a repack.
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

    /// A valid 64-char lowercase hex digest, used across dep tests.
    const PIN64: &str = "sha256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

    #[test]
    fn dependencies_roundtrip() {
        let src = format!(
            "{good}\n[dependencies]\n\"acme/helpers\" = \"{PIN64}\"\n",
            good = good(),
            PIN64 = PIN64,
        );
        let m = Manifest::parse(&src).unwrap();
        assert_eq!(
            m.dependencies["acme/helpers"],
            DepReq::Pin(PIN64.to_string())
        );
        assert_eq!(Manifest::parse(&m.to_toml_string().unwrap()).unwrap(), m);
    }

    #[test]
    fn dep_req_range_is_accepted() {
        let src = format!(
            "{good}\n[dependencies]\n\"acme/geo\" = \"^0.1.0\"\n",
            good = good()
        );
        let m = Manifest::parse(&src).expect("semver range should parse");
        let req = m.dependencies["acme/geo"].clone();
        assert!(matches!(req, DepReq::Range(_)));
    }

    #[test]
    fn dep_req_pin_is_accepted() {
        let req = parse_dep_req(PIN64).unwrap();
        assert!(matches!(req, DepReq::Pin(_)));
    }

    #[test]
    fn dep_req_garbage_is_rejected() {
        // Neither a sha256 pin nor a semver range.
        assert!(matches!(
            parse_dep_req("not-a-version-or-pin"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn dep_req_short_sha256_is_rejected() {
        // "sha256:" prefix but only 4 hex chars.
        assert!(matches!(
            parse_dep_req("sha256:aabb"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn manifest_parse_rejects_invalid_dep_value() {
        let src = format!(
            "{good}\n[dependencies]\n\"acme/bad\" = \"definitely-not-valid\"\n",
            good = good()
        );
        assert!(
            matches!(Manifest::parse(&src), Err(AfbError::ManifestParse(_))),
            "a garbage dep value must be rejected by Manifest::parse"
        );
    }

    #[test]
    fn dep_req_path_table_parses() {
        let src = format!(
            "{good}\n[dependencies]\n\"x/sib\" = {{ path = \"../sib\" }}\n",
            good = good()
        );
        let m = Manifest::parse(&src).expect("path dep should parse");
        assert!(
            matches!(&m.dependencies["x/sib"], DepReq::Path(p) if p.to_str() == Some("../sib"))
        );
    }

    #[test]
    fn dep_req_git_tag_parses() {
        let src = format!(
            "{good}\n[dependencies]\n\"x/bar\" = {{ git = \"https://example.com/x/y\", tag = \"v1\" }}\n",
            good = good()
        );
        let m = Manifest::parse(&src).expect("git dep should parse");
        assert!(matches!(
            &m.dependencies["x/bar"],
            DepReq::Git { url, reference: GitRef::Tag(t) }
            if url == "https://example.com/x/y" && t == "v1"
        ));
    }

    #[test]
    fn dep_req_string_range_still_parses() {
        let src = format!(
            "{good}\n[dependencies]\n\"x/foo\" = \"^0.1.0\"\n",
            good = good()
        );
        let m = Manifest::parse(&src).expect("range dep should parse");
        assert!(matches!(&m.dependencies["x/foo"], DepReq::Range(_)));
    }

    #[test]
    fn dep_req_path_missing_errors_clearly() {
        // A path dep that does not exist on the filesystem - the manifest itself should
        // still parse fine. The error comes at compile/resolve time, not manifest parse time.
        let src = format!(
            "{good}\n[dependencies]\n\"x/sib\" = {{ path = \"../missing\" }}\n",
            good = good()
        );
        // Manifest parses OK - path existence is checked at resolution time, not here.
        assert!(Manifest::parse(&src).is_ok());
    }

    #[test]
    fn registry_deps_excludes_path_and_git() {
        let src = format!(
            "{good}\n[dependencies]\n\
             \"x/foo\" = \"^0.1.0\"\n\
             \"x/sib\" = {{ path = \"../sib\" }}\n\
             \"x/bar\" = {{ git = \"https://example.com/x/y\", tag = \"v1\" }}\n",
            good = good()
        );
        let m = Manifest::parse(&src).expect("mixed deps should parse");
        let rdeps = m.registry_deps();
        assert!(rdeps.contains_key("x/foo"), "range dep must appear");
        assert!(!rdeps.contains_key("x/sib"), "path dep must be excluded");
        assert!(!rdeps.contains_key("x/bar"), "git dep must be excluded");
    }
}
