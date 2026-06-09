// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Dependency resolution. Turns root requirements (semver ranges and/or exact
//! digest pins) plus a [`Source`] of available versions into a flat,
//! topologically-ordered set of pinned packages for a `burn.lock`.
//!
//! * **Version selection** uses **PubGrub** (`pubgrub` crate) - the
//!   conflict-driven, backtracking solver used by uv, Dart pub, Poetry and
//!   Bundler, and the designated replacement for cargo's resolver. It is
//!   complete (it backtracks) and explains conflicts clearly, unlike a greedy
//!   walk. We model packages as [`Pkg`], versions as [`semver::Version`], and
//!   version sets as `pubgrub::Ranges<Version>` (semver requirements converted
//!   by [`req_to_ranges`]).
//! * **Ordering + cycle detection** uses **Kahn's algorithm** over the selected
//!   graph (a `BTreeSet` frontier for deterministic, reproducible output). A
//!   leftover node is a dependency cycle, which is rejected.

use crate::error::{CloudError, Result};
use pubgrub::{
    Dependencies, DependencyProvider, PackageResolutionStatistics, PubGrubError, Ranges, Reporter,
};
use semver::{Op, Version, VersionReq};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A dependency requirement on a coord.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Req {
    /// An exact content pin, `sha256:<hex>` (or bare hex).
    Digest(String),
    /// A semver range, e.g. `^1.2`, `>=1, <2`, `*`.
    Range(VersionReq),
}

impl Req {
    /// Parse a dependency value from `afb.toml` `[dependencies]`: `"sha256:aabb…"`
    /// (pin) or a semver range like `"^1.2"`.
    pub fn parse(value: &str) -> Result<Self> {
        let v = value.trim();
        if let Some(hex) = v.strip_prefix("sha256:") {
            return Ok(Req::Digest(normalize_digest(hex)));
        }
        if is_hex64(v) {
            return Ok(Req::Digest(normalize_digest(v)));
        }
        VersionReq::parse(v)
            .map(Req::Range)
            .map_err(|e| CloudError::BadCoord(format!("bad version requirement {value:?}: {e}")))
    }

    /// Build the *root* requirement from a CLI `@version` argument. `None`
    /// resolves the latest non-yanked version (`*`). A plain semver version
    /// (`1.2.3`) pins it exactly (`=1.2.3`, matching `burn install foo@1.2.3`'s
    /// historical exact behavior); a range (`^1.2`, `>=1, <2`) or a digest
    /// (`sha256:…`) is parsed as written.
    pub fn from_cli_version(version: Option<&str>) -> Result<Self> {
        match version {
            None => Ok(Req::Range(VersionReq::STAR)),
            Some(v) => {
                let t = v.trim();
                if let Ok(exact) = Version::parse(t) {
                    let req = VersionReq::parse(&format!("={exact}"))
                        .expect("`=<version>` is always a valid requirement");
                    return Ok(Req::Range(req));
                }
                Req::parse(t)
            }
        }
    }
}

/// Parse the host runtime version string (the `burn`/engine version) used to
/// gate a candidate's `runtime_min`. A non-semver string falls back to `0.0.0`,
/// which keeps newer-than-us packages installable (the cache surfaces a
/// `RuntimeTooOld` warning at install time rather than silently dropping them).
pub fn runtime_version(s: &str) -> Version {
    Version::parse(s.trim()).unwrap_or_else(|_| Version::new(0, 0, 0))
}

/// One available version of a package, as the resolver sees it.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub version: Version,
    /// `sha256:<hex>` (or bare hex - normalized internally).
    pub digest: String,
    pub yanked: bool,
    pub runtime_min: Option<Version>,
    /// `(coord, requirement)` for this version's own dependencies.
    pub deps: Vec<(String, Req)>,
}

/// Where the resolver gets a package's available versions. Abstracted so the
/// resolver is unit-testable without a network and so the real client can
/// memoize / sparse-index behind it.
pub trait Source {
    /// All published versions of `coord` (`namespace/name`). Order is irrelevant.
    fn candidates(&self, coord: &str) -> Result<Vec<Candidate>>;
}

/// A resolved, pinned package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedPkg {
    pub version: Version,
    pub digest: String,
    /// Resolved dependency coords (sorted).
    pub deps: Vec<String>,
}

/// The complete resolution.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// Dependencies-before-dependents install/load order (Kahn).
    pub order: Vec<String>,
    /// coord -> pinned selection.
    pub selected: BTreeMap<String, SelectedPkg>,
}

fn normalize_digest(s: &str) -> String {
    s.trim().trim_start_matches("sha256:").to_ascii_lowercase()
}
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Convert a semver `VersionReq` to a `pubgrub::Ranges<Version>` by intersecting
/// each comparator. Prerelease edge cases are approximated; release versions are
/// exact (validated against `VersionReq::matches` in the tests).
pub fn req_to_ranges(req: &VersionReq) -> Ranges<Version> {
    if req.comparators.is_empty() {
        return Ranges::full(); // `*`
    }
    let mut acc = Ranges::full();
    for c in &req.comparators {
        acc = acc.intersection(&comparator_to_ranges(c));
    }
    acc
}

fn comparator_to_ranges(c: &semver::Comparator) -> Ranges<Version> {
    let (ma, mi, pa) = (c.major, c.minor, c.patch);
    let v = Version::new;
    match c.op {
        Op::Exact => match (mi, pa) {
            (Some(mi), Some(pa)) => Ranges::singleton(v(ma, mi, pa)),
            (Some(mi), None) => Ranges::between(v(ma, mi, 0), v(ma, mi + 1, 0)),
            (None, _) => Ranges::between(v(ma, 0, 0), v(ma + 1, 0, 0)),
        },
        Op::Greater => match (mi, pa) {
            (Some(mi), Some(pa)) => Ranges::strictly_higher_than(v(ma, mi, pa)),
            (Some(mi), None) => Ranges::higher_than(v(ma, mi + 1, 0)),
            (None, _) => Ranges::higher_than(v(ma + 1, 0, 0)),
        },
        Op::GreaterEq => match (mi, pa) {
            (Some(mi), Some(pa)) => Ranges::higher_than(v(ma, mi, pa)),
            (Some(mi), None) => Ranges::higher_than(v(ma, mi, 0)),
            (None, _) => Ranges::higher_than(v(ma, 0, 0)),
        },
        Op::Less => match (mi, pa) {
            (Some(mi), Some(pa)) => Ranges::strictly_lower_than(v(ma, mi, pa)),
            (Some(mi), None) => Ranges::strictly_lower_than(v(ma, mi, 0)),
            (None, _) => Ranges::strictly_lower_than(v(ma, 0, 0)),
        },
        Op::LessEq => match (mi, pa) {
            (Some(mi), Some(pa)) => Ranges::strictly_lower_than(v(ma, mi, pa + 1)),
            (Some(mi), None) => Ranges::strictly_lower_than(v(ma, mi + 1, 0)),
            (None, _) => Ranges::strictly_lower_than(v(ma + 1, 0, 0)),
        },
        Op::Tilde => match (mi, pa) {
            (Some(mi), Some(pa)) => Ranges::between(v(ma, mi, pa), v(ma, mi + 1, 0)),
            (Some(mi), None) => Ranges::between(v(ma, mi, 0), v(ma, mi + 1, 0)),
            (None, _) => Ranges::between(v(ma, 0, 0), v(ma + 1, 0, 0)),
        },
        Op::Caret => {
            let lo = v(ma, mi.unwrap_or(0), pa.unwrap_or(0));
            let hi = if ma > 0 {
                v(ma + 1, 0, 0)
            } else if mi.unwrap_or(0) > 0 {
                v(0, mi.unwrap() + 1, 0)
            } else if let Some(pa) = pa {
                v(0, 0, pa + 1)
            } else if let Some(mi) = mi {
                v(0, mi + 1, 0)
            } else {
                v(1, 0, 0)
            };
            Ranges::between(lo, hi)
        }
        Op::Wildcard => match mi {
            Some(mi) => Ranges::between(v(ma, mi, 0), v(ma, mi + 1, 0)),
            None => Ranges::between(v(ma, 0, 0), v(ma + 1, 0, 0)),
        },
        _ => Ranges::full(),
    }
}

/// PubGrub package: a synthetic root plus each `namespace/name`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Pkg {
    Root,
    Dep(String),
}
impl std::fmt::Display for Pkg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pkg::Root => write!(f, "(root)"),
            Pkg::Dep(c) => write!(f, "{c}"),
        }
    }
}

struct Provider<'a> {
    source: &'a dyn Source,
    runtime: Version,
    root_version: Version,
    roots: Vec<(String, Req)>,
    cache: RefCell<HashMap<String, Vec<Candidate>>>,
}

impl Provider<'_> {
    fn cands(&self, coord: &str) -> Result<Vec<Candidate>> {
        if let Some(c) = self.cache.borrow().get(coord) {
            return Ok(c.clone());
        }
        let mut c = self.source.candidates(coord)?;
        for x in &mut c {
            x.digest = normalize_digest(&x.digest);
        }
        c.sort_by(|a, b| b.version.cmp(&a.version)); // high -> low
        self.cache.borrow_mut().insert(coord.to_string(), c.clone());
        Ok(c)
    }

    fn vs_for(&self, coord: &str, req: &Req) -> Result<Ranges<Version>> {
        match req {
            Req::Range(r) => Ok(req_to_ranges(r)),
            Req::Digest(d) => {
                let cands = self.cands(coord)?;
                Ok(cands
                    .iter()
                    .find(|c| &c.digest == d)
                    .map(|c| Ranges::singleton(c.version.clone()))
                    .unwrap_or_else(Ranges::empty))
            }
        }
    }
}

impl DependencyProvider for Provider<'_> {
    type P = Pkg;
    type V = Version;
    type VS = Ranges<Version>;
    type Priority = (u32, std::cmp::Reverse<usize>);
    type M = String;
    type Err = CloudError;

    fn choose_version(&self, package: &Pkg, range: &Ranges<Version>) -> Result<Option<Version>> {
        match package {
            Pkg::Root => Ok(range
                .contains(&self.root_version)
                .then(|| self.root_version.clone())),
            Pkg::Dep(coord) => {
                let cands = self.cands(coord)?;
                Ok(cands
                    .into_iter()
                    .find(|cand| {
                        range.contains(&cand.version)
                            && !cand.yanked
                            && cand.runtime_min.as_ref().is_none_or(|m| *m <= self.runtime)
                    })
                    .map(|c| c.version))
            }
        }
    }

    fn prioritize(
        &self,
        package: &Pkg,
        _range: &Ranges<Version>,
        stats: &PackageResolutionStatistics,
    ) -> Self::Priority {
        let nversions = match package {
            Pkg::Root => 0,
            Pkg::Dep(c) => self.cands(c).map(|v| v.len()).unwrap_or(0),
        };
        // More conflicts first; fewer candidates first (tighter -> decide sooner).
        (stats.conflict_count(), std::cmp::Reverse(nversions))
    }

    fn get_dependencies(
        &self,
        package: &Pkg,
        version: &Version,
    ) -> Result<Dependencies<Pkg, Ranges<Version>, String>> {
        let deps: Vec<(String, Req)> = match package {
            Pkg::Root => self.roots.clone(),
            Pkg::Dep(coord) => match self
                .cands(coord)?
                .into_iter()
                .find(|c| &c.version == version)
            {
                Some(c) => c.deps,
                None => return Ok(Dependencies::Available(std::iter::empty().collect())),
            },
        };
        let mut pairs: Vec<(Pkg, Ranges<Version>)> = Vec::with_capacity(deps.len());
        for (dcoord, dreq) in deps {
            pairs.push((Pkg::Dep(dcoord.clone()), self.vs_for(&dcoord, &dreq)?));
        }
        Ok(Dependencies::Available(pairs.into_iter().collect()))
    }
}

/// Resolve `roots` (top-level `(coord, Req)`) against `source` for a host
/// `runtime` version. Returns the pinned, ordered set or a precise error.
pub fn resolve(
    roots: &[(String, Req)],
    source: &dyn Source,
    runtime: &Version,
) -> Result<Resolution> {
    let root_version = Version::new(0, 0, 0);
    let provider = Provider {
        source,
        runtime: runtime.clone(),
        root_version: root_version.clone(),
        roots: roots.to_vec(),
        cache: RefCell::new(HashMap::new()),
    };

    let solution = match pubgrub::resolve(&provider, Pkg::Root, root_version.clone()) {
        Ok(s) => s,
        Err(PubGrubError::NoSolution(mut tree)) => {
            tree.collapse_no_versions();
            return Err(CloudError::Resolve(format!(
                "no compatible set of versions:\n{}",
                pubgrub::DefaultStringReporter::report(&tree)
            )));
        }
        Err(PubGrubError::ErrorRetrievingDependencies { source, .. }) => return Err(source),
        Err(PubGrubError::ErrorChoosingVersion { source, .. }) => return Err(source),
        Err(e) => return Err(CloudError::Resolve(e.to_string())),
    };

    let chosen: Vec<(String, Version)> = solution
        .into_iter()
        .filter_map(|(pkg, v)| match pkg {
            Pkg::Dep(c) => Some((c, v)),
            Pkg::Root => None,
        })
        .collect();
    let coord_set: BTreeSet<&str> = chosen.iter().map(|(c, _)| c.as_str()).collect();

    let mut selected: BTreeMap<String, SelectedPkg> = BTreeMap::new();
    for (coord, version) in &chosen {
        let cand = provider
            .cands(coord)?
            .into_iter()
            .find(|c| &c.version == version)
            .ok_or_else(|| CloudError::Resolve(format!("internal: {coord}@{version} vanished")))?;
        let mut deps: Vec<String> = cand
            .deps
            .iter()
            .map(|(d, _)| d.clone())
            .filter(|d| coord_set.contains(d.as_str()))
            .collect();
        deps.sort();
        deps.dedup();
        selected.insert(
            coord.clone(),
            SelectedPkg {
                version: version.clone(),
                digest: cand.digest,
                deps,
            },
        );
    }

    let order = kahn_order(&selected)?;
    Ok(Resolution { order, selected })
}

/// Kahn's algorithm: deps-before-dependents topological order, deterministic via
/// a sorted frontier. `Err` if the selected graph has a cycle.
fn kahn_order(selected: &BTreeMap<String, SelectedPkg>) -> Result<Vec<String>> {
    let mut indegree: HashMap<&str, usize> = selected.keys().map(|k| (k.as_str(), 0)).collect();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for (coord, pkg) in selected {
        for dep in &pkg.deps {
            if selected.contains_key(dep) {
                adj.entry(dep.as_str()).or_default().push(coord.as_str());
                *indegree.get_mut(coord.as_str()).unwrap() += 1;
            }
        }
    }
    let mut frontier: BTreeSet<&str> = indegree
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(k, _)| *k)
        .collect();
    let mut order = Vec::with_capacity(selected.len());
    while let Some(&node) = frontier.iter().next() {
        frontier.remove(node);
        order.push(node.to_string());
        if let Some(deps) = adj.get(node) {
            let mut deps = deps.clone();
            deps.sort();
            for dependent in deps {
                let d = indegree.get_mut(dependent).unwrap();
                *d -= 1;
                if *d == 0 {
                    frontier.insert(dependent);
                }
            }
        }
    }
    if order.len() != selected.len() {
        let mut cyclic: Vec<&str> = indegree
            .iter()
            .filter(|(_, d)| **d > 0)
            .map(|(k, _)| *k)
            .collect();
        cyclic.sort();
        return Err(CloudError::Resolve(format!(
            "dependency cycle involving: {}",
            cyclic.join(", ")
        )));
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock(HashMap<String, Vec<Candidate>>);
    impl Source for Mock {
        fn candidates(&self, coord: &str) -> Result<Vec<Candidate>> {
            Ok(self.0.get(coord).cloned().unwrap_or_default())
        }
    }
    fn cand(v: &str, deps: &[(&str, &str)]) -> Candidate {
        Candidate {
            version: Version::parse(v).unwrap(),
            digest: format!("{:0>64}", v.replace('.', "")),
            yanked: false,
            runtime_min: None,
            deps: deps
                .iter()
                .map(|(c, r)| (c.to_string(), Req::parse(r).unwrap()))
                .collect(),
        }
    }
    fn src(pkgs: &[(&str, Vec<Candidate>)]) -> Mock {
        Mock(
            pkgs.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }
    fn rt() -> Version {
        Version::parse("1.0.0").unwrap()
    }
    fn root(coord: &str, req: &str) -> (String, Req) {
        (coord.to_string(), Req::parse(req).unwrap())
    }

    #[test]
    fn picks_highest_in_range() {
        let s = src(&[(
            "a/x",
            vec![cand("1.0.0", &[]), cand("1.4.0", &[]), cand("2.0.0", &[])],
        )]);
        let r = resolve(&[root("a/x", "^1.0")], &s, &rt()).unwrap();
        assert_eq!(r.selected["a/x"].version.to_string(), "1.4.0");
    }

    #[test]
    fn diamond_resolves_d_once_and_orders_deps_first() {
        let s = src(&[
            ("a/a", vec![cand("1.0.0", &[("a/b", "^1"), ("a/c", "^1")])]),
            ("a/b", vec![cand("1.0.0", &[("a/d", ">=1, <2")])]),
            ("a/c", vec![cand("1.2.0", &[("a/d", "^1.1")])]),
            (
                "a/d",
                vec![cand("1.1.0", &[]), cand("1.5.0", &[]), cand("2.0.0", &[])],
            ),
        ]);
        let r = resolve(&[root("a/a", "^1")], &s, &rt()).unwrap();
        assert_eq!(r.selected.len(), 4);
        assert_eq!(r.selected["a/d"].version.to_string(), "1.5.0");
        let pos = |c: &str| r.order.iter().position(|x| x == c).unwrap();
        assert!(pos("a/d") < pos("a/b") && pos("a/d") < pos("a/c"));
        assert!(pos("a/b") < pos("a/a") && pos("a/c") < pos("a/a"));
    }

    #[test]
    fn incompatible_ranges_conflict() {
        let s = src(&[
            ("a/a", vec![cand("1.0.0", &[("a/b", "^1"), ("a/d", "^1")])]),
            ("a/b", vec![cand("1.0.0", &[("a/d", "^2")])]),
            ("a/d", vec![cand("1.0.0", &[]), cand("2.0.0", &[])]),
        ]);
        let err = resolve(&[root("a/a", "^1")], &s, &rt()).unwrap_err();
        assert!(
            matches!(err, CloudError::Resolve(_)),
            "expected conflict, got {err:?}"
        );
    }

    #[test]
    fn skips_yanked_and_newer_runtime() {
        let mut hi = cand("2.0.0", &[]);
        hi.yanked = true;
        let mut needs_new = cand("1.9.0", &[]);
        needs_new.runtime_min = Some(Version::parse("9.0.0").unwrap());
        let s = src(&[("a/x", vec![cand("1.0.0", &[]), needs_new, hi])]);
        let r = resolve(&[root("a/x", ">=1")], &s, &rt()).unwrap();
        assert_eq!(r.selected["a/x"].version.to_string(), "1.0.0");
    }

    #[test]
    fn digest_pin_selects_exact() {
        let want = cand("1.3.0", &[]);
        let pin = format!("sha256:{}", want.digest);
        let s = src(&[(
            "a/x",
            vec![cand("1.0.0", &[]), want.clone(), cand("2.0.0", &[])],
        )]);
        let r = resolve(&[("a/x".to_string(), Req::parse(&pin).unwrap())], &s, &rt()).unwrap();
        assert_eq!(r.selected["a/x"].version.to_string(), "1.3.0");
    }

    #[test]
    fn detects_cycle() {
        // PubGrub resolves the versions; Kahn rejects the load cycle.
        let s = src(&[
            ("a/a", vec![cand("1.0.0", &[("a/b", "^1")])]),
            ("a/b", vec![cand("1.0.0", &[("a/a", "^1")])]),
        ]);
        let err = resolve(&[root("a/a", "^1")], &s, &rt()).unwrap_err();
        match err {
            CloudError::Resolve(m) => assert!(m.contains("cycle"), "got {m}"),
            other => panic!("expected cycle, got {other:?}"),
        }
    }

    #[test]
    fn backtracks_to_satisfy_a_transitive_conflict() {
        // root wants a ^1 and c ^1. a@2 needs c ^2 (incompatible with c ^1), but
        // a@1 needs c ^1. A greedy "pick highest a" picks a@2 and dead-ends; a
        // real solver backtracks to a@1. PubGrub must select a@1, c@1.
        let s = src(&[
            (
                "a/a",
                vec![
                    cand("1.0.0", &[("a/c", "^1")]),
                    cand("2.0.0", &[("a/c", "^2")]),
                ],
            ),
            ("a/c", vec![cand("1.0.0", &[]), cand("2.0.0", &[])]),
        ]);
        let r = resolve(&[root("a/a", "^1"), root("a/c", "^1")], &s, &rt()).unwrap();
        assert_eq!(r.selected["a/a"].version.to_string(), "1.0.0");
        assert_eq!(r.selected["a/c"].version.to_string(), "1.0.0");
    }

    #[test]
    fn req_to_ranges_matches_semver() {
        // The range conversion must agree with semver's own matcher on release
        // versions, across a spread of requirements.
        let versions: Vec<Version> = [
            "0.0.1", "0.0.3", "0.0.4", "0.1.0", "0.2.3", "0.3.0", "1.0.0", "1.2.0", "1.2.3",
            "1.2.4", "1.3.0", "1.9.9", "2.0.0", "2.1.0", "3.0.0",
        ]
        .iter()
        .map(|v| Version::parse(v).unwrap())
        .collect();
        for spec in [
            "^1.2.3", "^1.2", "^1", "^0.2.3", "^0.0.3", "~1.2.3", "~1.2", "~1", "=1.2.3",
            ">=1.2.3", ">1.2.3", "<2.0.0", "<=1.2.3", ">=1, <2", "1.2.*", "*",
        ] {
            let req = VersionReq::parse(spec).unwrap();
            let ranges = req_to_ranges(&req);
            for v in &versions {
                assert_eq!(
                    ranges.contains(v),
                    req.matches(v),
                    "mismatch for spec {spec:?} version {v}"
                );
            }
        }
    }
}
