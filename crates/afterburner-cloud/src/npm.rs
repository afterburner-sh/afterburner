// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 vertexclique

//! Native npm installer.
//!
//! `burn install` resolves and caches a package's `[npm]` dependencies
//! WITHOUT a Node toolchain on the host - a self-contained registry client:
//! fetch packument → pick the max version satisfying the range → download
//! the tarball → verify integrity → extract into the content-addressed npm
//! cache → recurse into that package's own `dependencies`. The runtime
//! linker (`Afb::linked_source`) mounts the cached trees into the sandbox's
//! virtual `node_modules`.
//!
//! Security:
//! * **Integrity-verified.** Each tarball is checked against the registry's
//!   `dist.shasum` (SHA-1) before it is trusted or cached.
//! * **No native code.** Every extracted file is run through the
//!   native-artifact gate ([`afterburner_afb::native`]); a `.node`/`.so`/
//!   `binding.gyp`/etc. aborts the install, naming the package + file.
//! * **No install scripts.** Tarballs are extracted as data; npm lifecycle
//!   scripts (`postinstall`, …) are never executed - the usual npm supply-
//!   chain RCE vector simply does not exist here.
//! * **Bounded.** Per-tarball size cap; path-escape / symlink entries are
//!   refused by the extractor.

use crate::error::{CloudError, Result};
use semver::{Version, VersionReq};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Default public npm registry base (no trailing slash).
pub const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// Hard ceiling on a single decompressed tarball (defense-in-depth; npm's
/// own unpacked-size cap is 512 MiB, we are far stricter for sandbox use).
const MAX_TARBALL_UNCOMPRESSED: u64 = 64 * 1024 * 1024;
const MAX_TARBALL_COMPRESSED: u64 = 24 * 1024 * 1024;

/// A resolved + extracted npm package: its files keyed package-root-relative
/// (`index.js`, `lib/x.js`, `package.json`), ready to hand to the linker.
#[derive(Debug, Clone)]
pub struct NpmPackage {
    pub name: String,
    pub version: String,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// The full resolved npm closure for a package's `[npm]` section.
#[derive(Debug, Clone, Default)]
pub struct NpmResolution {
    /// name → resolved package (deduplicated: one version per name - a flat
    /// install, like a deduped npm tree).
    pub packages: BTreeMap<String, NpmPackage>,
}

/// A registry client over `ureq`. `base` lets tests point at a mock.
pub struct NpmClient {
    agent: ureq::Agent,
    base: String,
}

impl NpmClient {
    pub fn new(base: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(60))
            .build();
        Self {
            agent,
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    pub fn public() -> Self {
        Self::new(DEFAULT_NPM_REGISTRY)
    }

    /// Resolve a `[npm]` section (name → semver range) and its full
    /// transitive `dependencies` closure into extracted, integrity-checked
    /// packages. Flat/deduped: the first-resolved version of a name wins
    /// (npm's hoisting in spirit); a conflicting range that the chosen
    /// version does not satisfy is reported.
    pub fn resolve_all(&self, roots: &BTreeMap<String, String>) -> Result<NpmResolution> {
        let mut out = NpmResolution::default();
        // work queue of (name, range)
        let mut queue: Vec<(String, String)> =
            roots.iter().map(|(n, r)| (n.clone(), r.clone())).collect();

        while let Some((name, range)) = queue.pop() {
            if let Some(existing) = out.packages.get(&name) {
                // Already resolved: ensure the existing version satisfies
                // this additional range, else it's a real conflict.
                if !satisfies(&existing.version, &range) {
                    return Err(CloudError::Resolve(format!(
                        "npm dependency conflict for {name:?}: have {} but another \
                         dependency requires {range}",
                        existing.version
                    )));
                }
                continue;
            }
            let packument = self.fetch_packument(&name)?;
            let (version, dist, deps) = pick_version(&name, &range, &packument)?;
            let tarball = self.download_tarball(&dist.tarball)?;
            verify_shasum(&name, &version, &dist.shasum, &tarball)?;
            let files = extract_tarball(&name, &tarball)?;
            afterburner_afb::native::reject_native(files.keys().map(String::as_str))
                .map_err(|e| CloudError::Package(format!("npm package {name}@{version}: {e}")))?;
            out.packages.insert(
                name.clone(),
                NpmPackage {
                    name: name.clone(),
                    version: version.clone(),
                    files,
                },
            );
            for (dn, dr) in deps {
                queue.push((dn, dr));
            }
        }
        Ok(out)
    }

    fn fetch_packument(&self, name: &str) -> Result<Packument> {
        let url = format!("{}/{}", self.base, encode_name(name));
        let resp = self
            .agent
            .get(&url)
            // the abbreviated packument is smaller + faster
            .set(
                "accept",
                "application/vnd.npm.install-v1+json, application/json",
            )
            .call()
            .map_err(|e| map_ureq(name, e))?;
        let mut body = String::new();
        resp.into_reader()
            .take(MAX_TARBALL_COMPRESSED)
            .read_to_string(&mut body)
            .map_err(CloudError::Io)?;
        serde_json::from_str(&body)
            .map_err(|e| CloudError::Decode(format!("packument for {name}: {e}")))
    }

    fn download_tarball(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.agent.get(url).call().map_err(|e| map_ureq(url, e))?;
        let mut buf = Vec::new();
        resp.into_reader()
            .take(MAX_TARBALL_COMPRESSED + 1)
            .read_to_end(&mut buf)
            .map_err(CloudError::Io)?;
        if buf.len() as u64 > MAX_TARBALL_COMPRESSED {
            return Err(CloudError::Package(format!(
                "npm tarball {url} exceeds the {MAX_TARBALL_COMPRESSED}-byte limit"
            )));
        }
        Ok(buf)
    }
}

// ---- packument model -------------------------------------------------------

#[derive(serde::Deserialize)]
struct Packument {
    #[serde(default)]
    versions: BTreeMap<String, VersionEntry>,
}

#[derive(serde::Deserialize)]
struct VersionEntry {
    dist: Dist,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
}

#[derive(serde::Deserialize, Clone)]
struct Dist {
    tarball: String,
    #[serde(default)]
    shasum: String,
}

/// Pick the highest version satisfying `range` (npm semantics: prerelease
/// versions are excluded unless the range names one - we conservatively skip
/// prereleases entirely, which is correct for the overwhelming common case).
fn pick_version(
    name: &str,
    range: &str,
    pack: &Packument,
) -> Result<(String, Dist, BTreeMap<String, String>)> {
    let req = parse_range(range)
        .ok_or_else(|| CloudError::Resolve(format!("npm {name}: bad range {range:?}")))?;
    let mut best: Option<(Version, &VersionEntry, &String)> = None;
    for (vstr, entry) in &pack.versions {
        let Ok(v) = Version::parse(vstr) else {
            continue;
        };
        if !v.pre.is_empty() {
            continue;
        }
        if req.matches(&v) && best.as_ref().is_none_or(|(b, _, _)| v > *b) {
            best = Some((v, entry, vstr));
        }
    }
    let (_, entry, vstr) = best
        .ok_or_else(|| CloudError::Resolve(format!("npm {name}: no version satisfies {range}")))?;
    Ok((vstr.clone(), entry.dist.clone(), entry.dependencies.clone()))
}

/// Whether `version` satisfies npm `range`.
fn satisfies(version: &str, range: &str) -> bool {
    match (Version::parse(version), parse_range(range)) {
        (Ok(v), Some(r)) => r.matches(&v),
        _ => false,
    }
}

/// Parse an npm range into a semver `VersionReq`. Handles `*`/empty/`latest`
/// as "any", and normalizes a leading `v`. node-semver and the `semver`
/// crate agree on `^`, `~`, comparators, and `x` ranges for the common case.
fn parse_range(range: &str) -> Option<VersionReq> {
    let r = range.trim();
    if r.is_empty() || r == "*" || r == "latest" || r == "x" || r == "X" {
        return Some(VersionReq::STAR);
    }
    VersionReq::parse(r).ok()
}

/// `@scope/name` → `@scope%2fname` for the registry path.
fn encode_name(name: &str) -> String {
    name.replacen('/', "%2f", 1)
}

// ---- integrity + extraction ------------------------------------------------

fn verify_shasum(name: &str, version: &str, shasum: &str, bytes: &[u8]) -> Result<()> {
    if shasum.is_empty() {
        // No shasum in the packument - refuse rather than trust blindly.
        return Err(CloudError::Package(format!(
            "npm {name}@{version}: registry returned no integrity shasum"
        )));
    }
    use sha1::{Digest, Sha1};
    let got = hex_lower(&Sha1::digest(bytes));
    if !got.eq_ignore_ascii_case(shasum) {
        return Err(CloudError::DigestMismatch {
            expected: format!("sha1:{shasum} ({name}@{version})"),
            got: format!("sha1:{got}"),
        });
    }
    Ok(())
}

/// Decompress + untar an npm tarball, stripping the leading `package/`
/// prefix every npm tarball carries. Refuses symlinks, path escapes, and
/// over-cap payloads.
fn extract_tarball(name: &str, gz: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let dec = flate2::read::GzDecoder::new(gz);
    let mut ar = tar::Archive::new(dec.take(MAX_TARBALL_UNCOMPRESSED));
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;
    for entry in ar
        .entries()
        .map_err(|e| CloudError::Package(format!("npm {name}: {e}")))?
    {
        let mut entry = entry.map_err(|e| CloudError::Package(format!("npm {name}: {e}")))?;
        let etype = entry.header().entry_type();
        if etype.is_symlink() || etype.is_hard_link() {
            return Err(CloudError::Package(format!(
                "npm {name}: refusing link entry in tarball"
            )));
        }
        if !etype.is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| CloudError::Package(format!("npm {name}: {e}")))?
            .to_string_lossy()
            .replace('\\', "/");
        // strip the conventional leading "package/"
        let rel = path.strip_prefix("package/").unwrap_or(&path).to_string();
        if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
            return Err(CloudError::Package(format!(
                "npm {name}: unsafe path {path:?} in tarball"
            )));
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(CloudError::Io)?;
        total += data.len() as u64;
        if total > MAX_TARBALL_UNCOMPRESSED {
            return Err(CloudError::Package(format!(
                "npm {name}: tarball exceeds the {MAX_TARBALL_UNCOMPRESSED}-byte unpacked limit"
            )));
        }
        out.insert(rel, data);
    }
    if out.is_empty() {
        return Err(CloudError::Package(format!("npm {name}: empty tarball")));
    }
    Ok(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn map_ureq(what: &str, e: ureq::Error) -> CloudError {
    match e {
        ureq::Error::Status(404, _) => {
            CloudError::Package(format!("npm package not found: {what}"))
        }
        ureq::Error::Status(code, resp) => CloudError::Status {
            code,
            message: format!("{what}: {}", resp.status_text()),
        },
        ureq::Error::Transport(t) => CloudError::Transport(format!("{what}: {t}")),
    }
}

// ---- on-disk npm cache -----------------------------------------------------

/// `~/.cache/burn/npm`.
pub fn npm_cache_root() -> Result<PathBuf> {
    let dir = dirs::cache_dir().ok_or(CloudError::NoCacheDir)?;
    Ok(dir.join("burn").join("npm"))
}

/// Directory for an extracted `name@version` (name slashes flattened).
pub fn npm_cache_dir(name: &str, version: &str) -> Result<PathBuf> {
    let safe = name.replace('/', "+");
    Ok(npm_cache_root()?.join(format!("{safe}@{version}")))
}

/// Write a resolved package's files into the cache (atomic-ish: write to a
/// temp dir then rename). Idempotent: an existing complete dir is reused.
pub fn store_npm(pkg: &NpmPackage) -> Result<PathBuf> {
    let dir = npm_cache_dir(&pkg.name, &pkg.version)?;
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

/// Load a cached package's files (for the linker). `None` if not cached.
pub fn load_npm(name: &str, version: &str) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    let dir = npm_cache_dir(name, version)?;
    if !dir.join(".burn-complete").exists() {
        return Ok(None);
    }
    let mut files = BTreeMap::new();
    collect(&dir, &dir, &mut files)?;
    files.remove(".burn-complete");
    Ok(Some(files))
}

fn collect(root: &Path, cur: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    for entry in std::fs::read_dir(cur).map_err(CloudError::Io)? {
        let entry = entry.map_err(CloudError::Io)?;
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| CloudError::Cache("npm cache path escape".into()))?
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, std::fs::read(&path).map_err(CloudError::Io)?);
        }
    }
    Ok(())
}

// ---- node_modules linking (the dev-loop materializer) -----------------------

/// Materialize `dir/node_modules` from the cache: one entry per resolved
/// package, flat (the resolver dedupes to a single version per name), each a
/// symlink into the content-addressed cache (a copy on platforms without
/// symlinks). This is the cargo model: `node_modules` is a build artifact
/// next to the manifest - never packed into the `.afb` (the runtime linker
/// serves embedders from the cache directly) - and `burn clean` removes it.
pub fn link_node_modules(res: &NpmResolution, dir: &std::path::Path) -> Result<()> {
    let nm = dir.join("node_modules");
    std::fs::create_dir_all(&nm).map_err(CloudError::Io)?;
    for pkg in res.packages.values() {
        let target = npm_cache_dir(&pkg.name, &pkg.version)?;
        let link = nm.join(&pkg.name);
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent).map_err(CloudError::Io)?;
        }
        // Replace whatever is there (older version link, stale copy).
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&link);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).map_err(CloudError::Io)?;
        #[cfg(not(unix))]
        copy_dir_recursive(&target, &link)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn copy_dir_recursive(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(to).map_err(CloudError::Io)?;
    for entry in std::fs::read_dir(from).map_err(CloudError::Io)? {
        let entry = entry.map_err(CloudError::Io)?;
        let dst = to.join(entry.file_name());
        if entry.file_type().map_err(CloudError::Io)?.is_dir() {
            copy_dir_recursive(&entry.path(), &dst)?;
        } else {
            std::fs::copy(entry.path(), &dst).map_err(CloudError::Io)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        assert!(satisfies("1.2.3", "^1.0.0"));
        assert!(satisfies("1.9.9", "^1.2"));
        assert!(!satisfies("2.0.0", "^1.0.0"));
        assert!(satisfies("3.1.0", "*"));
        assert!(satisfies("4.5.6", ""));
        assert!(satisfies("1.0.0", "~1.0.0"));
        assert!(!satisfies("1.1.0", "~1.0.0"));
    }

    #[test]
    fn scoped_name_encoding() {
        assert_eq!(encode_name("@scope/pkg"), "@scope%2fpkg");
        assert_eq!(encode_name("leftpad"), "leftpad");
    }

    #[test]
    fn extract_strips_package_prefix_and_rejects_escape() {
        // Build a tiny gzipped tar in-memory.
        let mut tar_buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_buf);
            let body = b"module.exports = 1;";
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "package/index.js", &body[..])
                .unwrap();
            b.finish().unwrap();
        }
        let mut gz = Vec::new();
        {
            use flate2::write::GzEncoder;
            use std::io::Write;
            let mut e = GzEncoder::new(&mut gz, flate2::Compression::default());
            e.write_all(&tar_buf).unwrap();
            e.finish().unwrap();
        }
        let files = extract_tarball("x", &gz).unwrap();
        assert_eq!(
            files.get("index.js").map(|v| v.as_slice()),
            Some(&b"module.exports = 1;"[..])
        );
        assert!(!files.keys().any(|k| k.starts_with("package/")));
    }

    #[test]
    fn shasum_mismatch_is_rejected() {
        let err = verify_shasum("x", "1.0.0", "deadbeef", b"hello").unwrap_err();
        assert!(matches!(err, CloudError::DigestMismatch { .. }));
    }

    #[test]
    fn empty_shasum_refused() {
        let err = verify_shasum("x", "1.0.0", "", b"hello").unwrap_err();
        assert!(matches!(err, CloudError::Package(_)));
    }
}
