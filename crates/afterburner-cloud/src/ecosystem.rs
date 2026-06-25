// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Shared ecosystem-client abstraction.
//!
//! [`EcosystemClient`] is the vocabulary every package-ecosystem registry
//! client implements: fetch version metadata, download + verify one artifact,
//! and evaluate a version-range specifier.  The BFS closure walk
//! ([`resolve_all`]), the integrity gate, the native-artifact gate, and the
//! on-disk content-addressed cache ([`store_artifact`] / [`load_artifact`])
//! are written ONCE here against that trait and shared by every ecosystem.
//! `NpmClient`, `PipClient`, and `GemClient` are thin adapters.

use crate::error::{CloudError, Result};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

// ---- public types ----------------------------------------------------------

/// One published version of a package as the shared resolver sees it.
#[derive(Debug, Clone)]
pub struct EcosystemRelease {
    /// Version string (opaque; meaning is ecosystem-specific).
    pub version: String,
    /// Artifact download URL.
    pub artifact_url: String,
    /// Integrity field: the value used to verify the download.
    /// Format is ecosystem-specific (e.g. sha1-hex for npm, sha256-hex for pip/gem).
    pub integrity: String,
    /// Transitive `(name, specifier)` pairs this version requires.
    pub deps: BTreeMap<String, String>,
}

/// One extracted, integrity-checked package artifact.
#[derive(Debug, Clone)]
pub struct EcosystemPackage {
    pub name: String,
    pub version: String,
    /// Integrity string used to verify this artifact (SRI for npm: e.g.
    /// `"sha512-..."` or `"sha256-..."`; sha1 hex for legacy npm; sha256 hex
    /// for pip/gem). Stored in `burn.lock` `[[npm]]`/`[[pip]]`/`[[gem]]`
    /// sections so locked installs can re-verify without re-resolving (G1).
    pub integrity: String,
    /// Extracted file tree keyed by package-root-relative paths.
    pub files: BTreeMap<String, Vec<u8>>,
}

/// The full resolved closure for one `[npm]`/`[pip]`/`[gem]` section.
#[derive(Debug, Clone, Default)]
pub struct EcosystemResolution {
    /// Every resolved package in BFS (resolution) order.
    pub packages: Vec<EcosystemPackage>,
    /// Hoisted top-level choice per name (first resolved version).
    pub hoisted: BTreeMap<String, String>,
    /// Resolved dependency edges: `"name@version"` -> dep name -> dep version.
    pub edges: BTreeMap<String, BTreeMap<String, String>>,
}

impl EcosystemResolution {
    /// First resolved package with this name (the hoisted one).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&EcosystemPackage> {
        self.packages.iter().find(|p| p.name == name)
    }
}

// ---- trait -----------------------------------------------------------------

/// Per-ecosystem vocabulary the shared resolver calls.
///
/// Implementors supply the three registry-specific behaviors; the BFS walk,
/// integrity gate, native-artifact gate, and disk cache are written once
/// against this trait in [`resolve_all`], [`store_artifact`], and
/// [`load_artifact`].
pub trait EcosystemClient {
    /// All published versions and their deps for `name` (packument / PyPI
    /// simple API / RubyGems versions endpoint).
    fn versions(&self, name: &str) -> Result<Vec<EcosystemRelease>>;

    /// Download `rel`'s artifact and strong-hash-verify it; return the raw bytes.
    fn fetch_artifact(&self, rel: &EcosystemRelease) -> Result<Vec<u8>>;

    /// Whether `version` satisfies `spec` under this ecosystem's grammar
    /// (semver / PEP 440 / RubyGems requirement).
    fn satisfies(&self, version: &str, spec: &str) -> bool;

    /// Extract a downloaded artifact into a file tree.  Each ecosystem has its
    /// own archive format (npm: gzip tar; pip: zip; gem: tar).
    fn extract(&self, name: &str, bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>>;

    /// The filesystem key for `name@version` inside the ecosystem's cache root
    /// (e.g. `npm`, `pip`, `gem`).  Must be a SINGLE path component safe for
    /// the local filesystem (no slashes - encode them).
    fn cache_key(&self, name: &str, version: &str) -> String;

    /// Root of this ecosystem's content-addressed cache: `~/.cache/burn/<eco>`.
    fn cache_root(&self) -> Result<PathBuf>;

    /// Human-readable ecosystem name for error messages (e.g. `"npm"`).
    fn ecosystem_name(&self) -> &'static str;
}

// ---- shared BFS closure resolver -------------------------------------------

/// Resolve `roots` (name -> specifier map) and their full transitive
/// dependency closure, downloading and verifying each artifact.
///
/// Semantics mirror npm's: a specifier reuses an already-resolved version when
/// one satisfies it; otherwise an ADDITIONAL version of the same name joins the
/// closure (allowing per-requester overrides, exactly as npm's nested
/// `node_modules` model).  BFS so roots win the hoisted top-level slot for
/// their names.
pub fn resolve_all(
    client: &dyn EcosystemClient,
    roots: &BTreeMap<String, String>,
) -> Result<EcosystemResolution> {
    let eco = client.ecosystem_name();
    let mut out = EcosystemResolution::default();
    // Queue: (name, specifier, requester "name@version" or None for roots).
    let mut queue: std::collections::VecDeque<(String, String, Option<String>)> = roots
        .iter()
        .map(|(n, s)| (n.clone(), s.clone(), None))
        .collect();
    // name -> every version resolved so far.
    let mut resolved_versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Cached version lists per name (fetch once even when two versions needed).
    let mut version_cache: BTreeMap<String, Vec<EcosystemRelease>> = BTreeMap::new();

    while let Some((name, spec, requester)) = queue.pop_front() {
        let record_edge = |out: &mut EcosystemResolution, version: &str| {
            if let Some(req) = &requester {
                out.edges
                    .entry(req.clone())
                    .or_default()
                    .insert(name.clone(), version.to_string());
            }
        };

        // Reuse an already-resolved version that satisfies this specifier.
        if let Some(existing) = resolved_versions
            .get(&name)
            .and_then(|vs| vs.iter().find(|v| client.satisfies(v, &spec)))
        {
            let existing = existing.clone();
            record_edge(&mut out, &existing);
            continue;
        }

        // Fetch version list on first need.
        if !version_cache.contains_key(&name) {
            version_cache.insert(name.clone(), client.versions(&name)?);
        }
        let releases = &version_cache[&name];

        let rel = pick_release(eco, &name, &spec, releases, client)?;
        let bytes = client.fetch_artifact(&rel)?;
        let files = client.extract(&name, &bytes)?;

        // Native-artifact gate.
        afterburner_afb::native::reject_native(files.keys().map(String::as_str)).map_err(|e| {
            CloudError::Package(format!("{eco} package {name}@{}: {e}", rel.version))
        })?;

        record_edge(&mut out, &rel.version);
        out.hoisted
            .entry(name.clone())
            .or_insert_with(|| rel.version.clone());
        resolved_versions
            .entry(name.clone())
            .or_default()
            .push(rel.version.clone());

        let key = format!("{name}@{}", rel.version);
        for (dn, dr) in &rel.deps {
            queue.push_back((dn.clone(), dr.clone(), Some(key.clone())));
        }

        out.packages.push(EcosystemPackage {
            name: name.clone(),
            version: rel.version.clone(),
            integrity: rel.integrity.clone(),
            files,
        });
    }
    Ok(out)
}

/// Pick the best release satisfying `spec`, highest version first (prerelease
/// skipped unless the specifier names one - conservative default).
fn pick_release(
    eco: &str,
    name: &str,
    spec: &str,
    releases: &[EcosystemRelease],
    client: &dyn EcosystemClient,
) -> Result<EcosystemRelease> {
    // Filter to candidates that satisfy the spec; take the last one (highest
    // in list order, which callers ensure is version-sorted).
    let best = releases
        .iter()
        .filter(|r| client.satisfies(&r.version, spec))
        .last();
    best.cloned()
        .ok_or_else(|| CloudError::Resolve(format!("{eco} {name}: no version satisfies {spec:?}")))
}

// ---- content-addressed disk cache ------------------------------------------

/// Write `pkg`'s file tree into the ecosystem cache (atomic: write to a temp
/// dir then rename).  Idempotent: an existing complete entry is reused.
pub fn store_artifact(client: &dyn EcosystemClient, pkg: &EcosystemPackage) -> Result<PathBuf> {
    let dir = artifact_cache_dir(client, &pkg.name, &pkg.version)?;
    if dir.join(".burn-complete").exists() {
        return Ok(dir);
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(CloudError::Io)?;
    }
    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    for (rel, bytes) in &pkg.files {
        let p = tmp.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(CloudError::Io)?;
        }
        std::fs::write(&p, bytes).map_err(CloudError::Io)?;
    }
    std::fs::write(tmp.join(".burn-complete"), b"1").map_err(CloudError::Io)?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&tmp, &dir).map_err(CloudError::Io)?;
    Ok(dir)
}

/// Load a cached package's files.  Returns `None` if not cached.
pub fn load_artifact(
    client: &dyn EcosystemClient,
    name: &str,
    version: &str,
) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    let dir = artifact_cache_dir(client, name, version)?;
    if !dir.join(".burn-complete").exists() {
        return Ok(None);
    }
    let mut files = BTreeMap::new();
    collect_files(&dir, &dir, &mut files)?;
    files.remove(".burn-complete");
    Ok(Some(files))
}

/// `<cache_root>/<cache_key>` for `name@version`.
pub fn artifact_cache_dir(
    client: &dyn EcosystemClient,
    name: &str,
    version: &str,
) -> Result<PathBuf> {
    Ok(client.cache_root()?.join(client.cache_key(name, version)))
}

fn collect_files(root: &Path, cur: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    for entry in std::fs::read_dir(cur).map_err(CloudError::Io)? {
        let entry = entry.map_err(CloudError::Io)?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| CloudError::Cache("cache path escape".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, std::fs::read(&path).map_err(CloudError::Io)?);
        }
    }
    Ok(())
}

// ---- bounded HTTP download helper ------------------------------------------

/// Download `url` via `agent`, capped at `compressed_limit` bytes.
pub fn download_capped(
    agent: &ureq::Agent,
    url: &str,
    compressed_limit: u64,
    what: &str,
) -> Result<Vec<u8>> {
    let resp = agent.get(url).call().map_err(|e| map_ureq(what, e))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(compressed_limit + 1)
        .read_to_end(&mut buf)
        .map_err(CloudError::Io)?;
    if buf.len() as u64 > compressed_limit {
        return Err(CloudError::Package(format!(
            "{what} exceeds the {compressed_limit}-byte compressed limit"
        )));
    }
    Ok(buf)
}

/// Map a `ureq::Error` to a `CloudError`, substituting `what` as context.
pub fn map_ureq(what: &str, e: ureq::Error) -> CloudError {
    match e {
        ureq::Error::Status(404, _) => CloudError::Package(format!("package not found: {what}")),
        ureq::Error::Status(code, resp) => CloudError::Status {
            code,
            message: format!("{what}: {}", resp.status_text()),
        },
        ureq::Error::Transport(t) => CloudError::Transport(format!("{what}: {t}")),
    }
}
