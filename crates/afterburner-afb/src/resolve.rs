// SPDX-License-Identifier: Apache-2.0
//! Dependency resolver: maps a `[dependencies]` table to a fully-resolved
//! closure of `(version, digest)` pairs, suitable for writing an `afb.lock`.
//!
//! Resolution is transitive: each resolved package's own `[dependencies]` are
//! folded in, with diamond deduplication (each coordinate is resolved once).
//! The algorithm picks the **maximum satisfying version** from the index for
//! range deps and verifies digest equality for pin deps.

use crate::error::{AfbError, Result};
use crate::manifest::{DepReq, Manifest, parse_dep_req};
use std::collections::BTreeMap;

/// A fully resolved dependency: the version chosen and its content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub version: semver::Version,
    /// SHA-256 content digest of the resolved `.afb`.
    pub digest: [u8; 32],
}

/// Read-only view of available package versions used by the resolver.
///
/// Implementations are provided by the caller (e.g. a local packages
/// directory, or the registry HTTP API).
pub trait PackageIndex {
    /// All available (version, digest) pairs for the given coordinate
    /// (`"namespace/name"`), in any order. Returns an empty slice when the
    /// coordinate is unknown.
    fn versions(&self, coord: &str) -> Vec<(semver::Version, [u8; 32])>;

    /// Parse the manifest for a specific (coord, version). Used to fetch
    /// transitive dependencies. Returns `None` if not found.
    fn manifest(&self, coord: &str, version: &semver::Version) -> Option<Manifest>;
}

/// Resolve the full transitive dependency closure of `deps`.
///
/// For each entry in `deps`:
/// - `sha256:` pin: confirms the coordinate exists in the index with a
///   matching digest and records it.
/// - semver range: picks the **maximum version** satisfying the range.
///
/// Transitive deps (each resolved package's own `[dependencies]`) are folded
/// in iteratively. Each coordinate is resolved exactly once (diamond-safe).
///
/// Returns a map from coordinate to [`Resolved`], ordered by coordinate.
pub fn resolve_closure(
    deps: &BTreeMap<String, String>,
    index: &dyn PackageIndex,
) -> Result<BTreeMap<String, Resolved>> {
    let mut resolved: BTreeMap<String, Resolved> = BTreeMap::new();
    // Work-list of (coord, raw_value) to resolve. Seeded from the root deps,
    // extended with each resolved package's own deps.
    let mut queue: Vec<(String, String)> =
        deps.iter().map(|(c, v)| (c.clone(), v.clone())).collect();

    while let Some((coord, value)) = queue.pop() {
        if resolved.contains_key(&coord) {
            continue; // already resolved; diamond dedup
        }
        let req = parse_dep_req(&value)?;
        let r = match req {
            // Path and Git deps are not resolved through the registry index.
            // `resolve_closure` is only called with registry-style string maps,
            // so `parse_dep_req` will never produce these variants here.
            // The transitive-dep queue is seeded exclusively from `registry_deps()`.
            DepReq::Path(_) | DepReq::Git { .. } => {
                return Err(AfbError::Dependency {
                    coord: coord.clone(),
                    detail: "path/git dep reached registry resolver (this is a bug)".into(),
                });
            }
            DepReq::Pin(ref pin) => {
                let hex_part = pin.strip_prefix("sha256:").unwrap_or("");
                // Find the index entry whose digest matches the pin.
                let candidates = index.versions(&coord);
                if candidates.is_empty() {
                    return Err(AfbError::Dependency {
                        coord: coord.clone(),
                        detail: format!("pinned to {pin} but no versions found in the index"),
                    });
                }
                let matching = candidates
                    .into_iter()
                    .find(|(_, d)| crate::hex(d) == hex_part);
                let (version, digest) = matching.ok_or_else(|| AfbError::Dependency {
                    coord: coord.clone(),
                    detail: format!("no index entry has digest {pin}; the pin may be stale"),
                })?;
                Resolved { version, digest }
            }
            DepReq::Range(ref vreq) => {
                let candidates = index.versions(&coord);
                if candidates.is_empty() {
                    return Err(AfbError::Dependency {
                        coord: coord.clone(),
                        detail: "no versions found in the index".into(),
                    });
                }
                // Pick the maximum version satisfying the range.
                let best = candidates
                    .into_iter()
                    .filter(|(v, _)| vreq.matches(v))
                    .max_by(|(a, _), (b, _)| a.cmp(b));
                let (version, digest) = best.ok_or_else(|| AfbError::Dependency {
                    coord: coord.clone(),
                    detail: format!("no version satisfies range {vreq}"),
                })?;
                Resolved { version, digest }
            }
        };

        // Enqueue transitive deps from the resolved package's manifest.
        // Only registry deps (Pin + Range) participate in registry resolution;
        // Path and Git deps are skipped here (resolved locally at compile time).
        if let Some(manifest) = index.manifest(&coord, &r.version) {
            for (tc, tv) in manifest.registry_deps() {
                if !resolved.contains_key(&tc) {
                    queue.push((tc, tv));
                }
            }
        }
        resolved.insert(coord, r);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Format, Manifest, Package, Runtime};
    use std::collections::HashMap;

    /// One published version of a package in the mock index:
    /// (version, content digest, that version's manifest deps as raw strings).
    type MockVersion = (semver::Version, [u8; 32], BTreeMap<String, String>);

    /// Minimal in-memory package index for tests.
    struct MockIndex {
        /// coord -> the versions published under it.
        entries: HashMap<String, Vec<MockVersion>>,
    }

    impl MockIndex {
        fn new() -> Self {
            Self {
                entries: HashMap::new(),
            }
        }

        fn add(
            &mut self,
            coord: &str,
            version: &str,
            digest: [u8; 32],
            deps: BTreeMap<String, String>,
        ) {
            self.entries.entry(coord.to_string()).or_default().push((
                semver::Version::parse(version).unwrap(),
                digest,
                deps,
            ));
        }
    }

    impl PackageIndex for MockIndex {
        fn versions(&self, coord: &str) -> Vec<(semver::Version, [u8; 32])> {
            self.entries
                .get(coord)
                .map(|vs| vs.iter().map(|(v, d, _)| (v.clone(), *d)).collect())
                .unwrap_or_default()
        }

        fn manifest(&self, coord: &str, version: &semver::Version) -> Option<Manifest> {
            let entries = self.entries.get(coord)?;
            let (_, _, deps) = entries.iter().find(|(v, _, _)| v == version)?;
            // Build a minimal valid manifest carrying the recorded deps.
            // Convert raw string values to DepReq (all are registry-style strings in tests).
            let mut m = minimal_manifest(coord, &version.to_string());
            m.dependencies = deps
                .iter()
                .map(|(k, v)| (k.clone(), parse_dep_req(v).unwrap()))
                .collect();
            Some(m)
        }
    }

    /// Build the smallest valid Manifest for a coord and version string.
    fn minimal_manifest(coord: &str, version: &str) -> Manifest {
        let (ns, name) = coord.split_once('/').unwrap_or(("test", coord));
        Manifest {
            format: Format {
                version: "1.0".into(),
                min_reader: None,
            },
            package: Package {
                name: name.to_string(),
                namespace: ns.to_string(),
                version: version.to_string(),
                language: "js".into(),
                entry: "source/main.js".into(),
                description: None,
                homepage: None,
                license: None,
                keywords: vec![],
            },
            runtime: Runtime {
                min: "0.1.0".into(),
                target: None,
            },
            dependencies: BTreeMap::new(),
            npm: BTreeMap::new(),
            pip: BTreeMap::new(),
            gem: BTreeMap::new(),
            signature: None,
            metadata: toml::Table::new(),
            extra: toml::Table::new(),
        }
    }

    fn d(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn range_selects_max_satisfying_version() {
        let mut idx = MockIndex::new();
        idx.add("burn/geo", "0.1.0", d(1), BTreeMap::new());
        idx.add("burn/geo", "0.2.0", d(2), BTreeMap::new());
        idx.add("burn/geo", "0.3.0", d(3), BTreeMap::new());

        // ">=0.1.0" matches all three; the resolver must pick the max (0.3.0).
        // Note: "^0.1.0" in the semver crate means >=0.1.0, <0.2.0 (only 0.1.x).
        let mut deps = BTreeMap::new();
        deps.insert("burn/geo".into(), ">=0.1.0".into());

        let closure = resolve_closure(&deps, &idx).unwrap();
        let r = &closure["burn/geo"];
        assert_eq!(r.version, semver::Version::parse("0.3.0").unwrap());
        assert_eq!(r.digest, d(3));
    }

    #[test]
    fn transitive_chain_is_resolved() {
        let mut idx = MockIndex::new();
        // leaf has no deps
        idx.add("burn/leaf", "1.0.0", d(10), BTreeMap::new());
        // middle depends on leaf
        let mut mid_deps = BTreeMap::new();
        mid_deps.insert("burn/leaf".into(), "^1.0.0".into());
        idx.add("burn/middle", "1.0.0", d(20), mid_deps);

        let mut deps = BTreeMap::new();
        deps.insert("burn/middle".into(), "^1.0.0".into());

        let closure = resolve_closure(&deps, &idx).unwrap();
        assert!(
            closure.contains_key("burn/middle"),
            "middle must be resolved"
        );
        assert!(
            closure.contains_key("burn/leaf"),
            "leaf (transitive) must be resolved"
        );
    }

    #[test]
    fn diamond_resolves_coord_once() {
        let mut idx = MockIndex::new();
        idx.add("burn/shared", "1.0.0", d(7), BTreeMap::new());
        let mut a_deps = BTreeMap::new();
        a_deps.insert("burn/shared".into(), "^1.0.0".into());
        let mut b_deps = BTreeMap::new();
        b_deps.insert("burn/shared".into(), "^1.0.0".into());
        idx.add("burn/a", "1.0.0", d(5), a_deps);
        idx.add("burn/b", "1.0.0", d(6), b_deps);

        let mut deps = BTreeMap::new();
        deps.insert("burn/a".into(), "^1.0.0".into());
        deps.insert("burn/b".into(), "^1.0.0".into());

        let closure = resolve_closure(&deps, &idx).unwrap();
        // shared appears exactly once
        assert_eq!(closure.get("burn/shared").unwrap().digest, d(7));
    }

    #[test]
    fn no_satisfying_version_is_an_error() {
        let mut idx = MockIndex::new();
        idx.add("burn/geo", "0.1.0", d(1), BTreeMap::new());

        let mut deps = BTreeMap::new();
        deps.insert("burn/geo".into(), "^2.0.0".into()); // 0.1.0 does not satisfy ^2

        let err = resolve_closure(&deps, &idx).unwrap_err();
        assert!(
            matches!(err, AfbError::Dependency { .. }),
            "expected Dependency error, got {err:?}"
        );
    }

    #[test]
    fn pin_matches_digest_in_index() {
        let digest_bytes = d(42);
        let pin = format!("sha256:{}", crate::hex(&digest_bytes));
        let mut idx = MockIndex::new();
        idx.add("burn/fixed", "1.0.0", digest_bytes, BTreeMap::new());

        let mut deps = BTreeMap::new();
        deps.insert("burn/fixed".into(), pin.clone());

        let closure = resolve_closure(&deps, &idx).unwrap();
        assert_eq!(closure["burn/fixed"].digest, digest_bytes);
    }

    #[test]
    fn pin_missing_from_index_is_an_error() {
        let pin = "sha256:".to_string() + &"ab".repeat(32);
        let idx = MockIndex::new();
        // nothing in the index for this coord
        let mut deps = BTreeMap::new();
        deps.insert("burn/absent".into(), pin);

        let err = resolve_closure(&deps, &idx).unwrap_err();
        assert!(matches!(err, AfbError::Dependency { .. }));
    }
}
