// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! RubyGems registry client.
//!
//! `burn install` resolves and caches a package's `[gem]` dependencies
//! WITHOUT a Ruby toolchain on the host - a self-contained registry client:
//! fetch the RubyGems versions API -> pick the best version satisfying the
//! requirement -> download the `.gem` artifact -> sha256-verify ->
//! extract into the content-addressed gem cache -> recurse over runtime deps.
//!
//! Gem requirement grammar (the `~>` pessimistic operator and plain comparators):
//! * `~> 2.0` - compatible, equivalent to `>= 2.0, < 3` (major pinned).
//! * `~> 2.0.1` - compatible, equivalent to `>= 2.0.1, < 2.1` (minor pinned).
//! * `>= 2.7`, `> 1`, `= 1.4.0`, `< 4`, `!= 3.0` - plain comparators.
//! * A comma-separated list is the logical AND of all comparators.
//! * `*` or empty - any version.
//!
//! Security:
//! * **Integrity-verified.** Each `.gem` is checked against the registry's
//!   `sha` field (SHA-256 hex) before it is trusted or cached.
//! * **No native extensions.** A gem whose `data.tar.gz` contains any file
//!   that looks like a host-native artifact (`.so`, `.bundle`, `.dll`,
//!   `extconf.rb`, `Makefile`) is refused with an actionable error naming
//!   the file. The Ruby runtime runs a WASM sandbox; host-native C
//!   extensions cannot load. Stock pre-built pure-Ruby gems only.
//! * **No install scripts.** The gem's `extconf.rb` / `Rakefile` / gemspec
//!   install hooks are never executed.
//! * **Bounded.** Per-gem size cap; path-escape entries are refused.

use crate::ecosystem::{
    self, EcosystemClient, EcosystemPackage, EcosystemRelease, EcosystemResolution,
};
use crate::error::{CloudError, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

/// Default RubyGems registry base (no trailing slash).
pub const DEFAULT_GEM_REGISTRY: &str = "https://rubygems.org";

/// Hard ceiling on a single decompressed gem archive.
const MAX_GEM_UNCOMPRESSED: u64 = 64 * 1024 * 1024;
/// Hard ceiling on the compressed `.gem` download.
const MAX_GEM_COMPRESSED: u64 = 32 * 1024 * 1024;

/// A resolved + extracted gem. Type alias for the shared type so external
/// callers keep the same API.
pub type GemPackage = EcosystemPackage;

/// The full resolved gem closure for a package's `[gem]` section.
pub type GemResolution = EcosystemResolution;

/// A registry client for RubyGems over `ureq`. `base` lets tests point at a mock.
pub struct GemClient {
    agent: ureq::Agent,
    base: String,
}

impl GemClient {
    /// Create a client pointed at `base` (e.g. `"https://rubygems.org"` or a mock URL).
    pub fn new(base: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(60))
            .build();
        Self {
            agent,
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    /// Create a client pointed at the public RubyGems registry.
    pub fn public() -> Self {
        Self::new(DEFAULT_GEM_REGISTRY)
    }

    /// Resolve a `[gem]` section (name -> requirement string) and its full
    /// transitive runtime-dependency closure into extracted, integrity-checked
    /// packages. Delegates to the shared [`ecosystem::resolve_all`] walk.
    pub fn resolve_all(&self, roots: &BTreeMap<String, String>) -> Result<GemResolution> {
        ecosystem::resolve_all(self, roots)
    }
}

// ---- EcosystemClient impl --------------------------------------------------

impl EcosystemClient for GemClient {
    fn versions(&self, name: &str) -> Result<Vec<EcosystemRelease>> {
        let releases = self.fetch_versions(name)?;
        // Filter to the `ruby` platform (the portable, pure-Ruby platform).
        // Native-platform variants (`x86_64-linux`, etc.) are refused at the
        // native-artifact gate; filtering to `ruby` here is the first line of
        // defense and avoids fetching artifacts we will always reject.
        let mut out: Vec<EcosystemRelease> = releases
            .into_iter()
            .filter(|r| {
                let p = r.platform.as_deref().unwrap_or("ruby");
                p == "ruby" || p.is_empty()
            })
            .map(|r| {
                let artifact_url = format!(
                    "{}/gems/{}-{}.gem",
                    self.base,
                    r.name.as_deref().unwrap_or(name),
                    r.number
                );
                let deps = r
                    .dependencies
                    .runtime
                    .into_iter()
                    .map(|d| (d.name, d.requirements))
                    .collect();
                EcosystemRelease {
                    version: r.number,
                    artifact_url,
                    integrity: r.sha.unwrap_or_default(),
                    deps,
                }
            })
            .collect();
        // Sort ascending by version so pick_release (which takes the last
        // satisfying) picks the highest satisfying version.
        out.sort_by(|a, b| version_cmp(&a.version, &b.version));
        Ok(out)
    }

    fn fetch_artifact(&self, rel: &EcosystemRelease) -> Result<Vec<u8>> {
        let bytes = ecosystem::download_capped(
            &self.agent,
            &rel.artifact_url,
            MAX_GEM_COMPRESSED,
            &rel.artifact_url,
        )?;
        verify_sha256(&rel.artifact_url, &rel.integrity, &bytes)?;
        Ok(bytes)
    }

    fn satisfies(&self, version: &str, spec: &str) -> bool {
        satisfies(version, spec)
    }

    fn extract(&self, name: &str, bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
        extract_gem(name, bytes)
    }

    fn cache_key(&self, name: &str, version: &str) -> String {
        format!("{name}@{version}")
    }

    fn cache_root(&self) -> Result<PathBuf> {
        gem_cache_root()
    }

    fn ecosystem_name(&self) -> &'static str {
        "gem"
    }
}

// ---- private gem fetch helpers --------------------------------------------

impl GemClient {
    fn fetch_versions(&self, name: &str) -> Result<Vec<VersionEntry>> {
        let url = format!("{}/api/v1/versions/{}.json", self.base, name);
        let resp = self
            .agent
            .get(&url)
            .set("accept", "application/json")
            .call()
            .map_err(|e| ecosystem::map_ureq(name, e))?;
        let mut body = String::new();
        resp.into_reader()
            .take(MAX_GEM_COMPRESSED)
            .read_to_string(&mut body)
            .map_err(CloudError::Io)?;
        serde_json::from_str(&body)
            .map_err(|e| CloudError::Decode(format!("gem versions for {name}: {e}")))
    }
}

// ---- RubyGems versions API model ------------------------------------------

#[derive(serde::Deserialize)]
struct VersionEntry {
    number: String,
    #[serde(default)]
    platform: Option<String>,
    // The gem name may appear in each version entry.
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    sha: Option<String>,
    #[serde(default)]
    dependencies: DepsEntry,
}

#[derive(serde::Deserialize, Default)]
struct DepsEntry {
    #[serde(default)]
    runtime: Vec<DepSpec>,
}

#[derive(serde::Deserialize)]
struct DepSpec {
    name: String,
    requirements: String,
}

// ---- gem requirement parser -----------------------------------------------

/// Whether `version` satisfies the RubyGems requirement `spec`.
///
/// Handles:
/// * `*` or empty - any version.
/// * `~> X.Y` - compatible with X: `>= X.Y, < (X+1)`.
/// * `~> X.Y.Z` - compatible with X.Y: `>= X.Y.Z, < X.(Y+1)`.
/// * `>= X`, `> X`, `<= X`, `< X`, `= X`, `!= X` - plain comparators.
/// * Comma-separated AND of any of the above.
pub fn satisfies(version: &str, spec: &str) -> bool {
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" {
        return true;
    }
    let v = match parse_parts(version) {
        Some(v) => v,
        None => return false,
    };
    spec.split(',')
        .all(|clause| satisfies_clause(&v, clause.trim()))
}

/// Satisfy one bare comparator (no comma).
fn satisfies_clause(v: &[u64], clause: &str) -> bool {
    let clause = clause.trim();
    if let Some(bound) = clause.strip_prefix("~>") {
        let bound = bound.trim();
        satisfies_twiddle_wakka(v, bound)
    } else if let Some(rest) = clause.strip_prefix("!=") {
        let rest = rest.trim();
        parse_parts(rest).is_some_and(|r| v != r.as_slice())
    } else if let Some(rest) = clause.strip_prefix(">=") {
        let rest = rest.trim();
        parse_parts(rest).is_some_and(|r| cmp_versions(v, &r) != std::cmp::Ordering::Less)
    } else if let Some(rest) = clause.strip_prefix("<=") {
        let rest = rest.trim();
        parse_parts(rest).is_some_and(|r| cmp_versions(v, &r) != std::cmp::Ordering::Greater)
    } else if let Some(rest) = clause.strip_prefix('>') {
        let rest = rest.trim();
        parse_parts(rest).is_some_and(|r| cmp_versions(v, &r) == std::cmp::Ordering::Greater)
    } else if let Some(rest) = clause.strip_prefix('<') {
        let rest = rest.trim();
        parse_parts(rest).is_some_and(|r| cmp_versions(v, &r) == std::cmp::Ordering::Less)
    } else if let Some(rest) = clause.strip_prefix('=') {
        let rest = rest.trim();
        parse_parts(rest).is_some_and(|r| v == r.as_slice())
    } else {
        // Bare version: exact match (same as `= X`).
        parse_parts(clause).is_some_and(|r| v == r.as_slice())
    }
}

/// Pessimistic constraint operator `~> X.Y[.Z...]`.
///
/// The RubyGems spec: increment the second-to-last component and require
/// strictly less than that, while requiring >= the given bound.
///
/// Examples:
/// * `~> 2.0`   -> `>= 2.0, < 3`    (major pinned)
/// * `~> 2.0.1` -> `>= 2.0.1, < 2.1` (minor pinned)
/// * `~> 1`     -> `>= 1, < 2`      (single digit: same as `~> 1.0` by convention)
fn satisfies_twiddle_wakka(v: &[u64], bound: &str) -> bool {
    let parts = match parse_parts(bound) {
        Some(p) => p,
        None => return false,
    };
    // Must be >= bound.
    if cmp_versions(v, &parts) == std::cmp::Ordering::Less {
        return false;
    }
    // Upper bound: increment the second-to-last component.
    if parts.len() < 2 {
        // Single-component bound like `~> 1`: upper is next integer.
        let mut upper = parts.clone();
        upper[0] += 1;
        return cmp_versions(v, &upper) == std::cmp::Ordering::Less;
    }
    let mut upper: Vec<u64> = parts[..parts.len() - 1].to_vec();
    *upper.last_mut().unwrap() += 1;
    cmp_versions(v, &upper) == std::cmp::Ordering::Less
}

/// Parse a version string into numeric components, ignoring any pre-release
/// suffix after the last `.` if it is non-numeric (e.g. `1.0.0.pre`).
fn parse_parts(v: &str) -> Option<Vec<u64>> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    let parts: Vec<&str> = v.split('.').collect();
    let mut out = Vec::with_capacity(parts.len());
    for p in &parts {
        match p.parse::<u64>() {
            Ok(n) => out.push(n),
            Err(_) => {
                // A non-numeric component (prerelease). Stop here: the numeric
                // prefix is the comparable version; it is less than any
                // same-prefix release (conservative, correct for `~>` math).
                break;
            }
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Lexicographic comparison of two version component slices, shorter pads with 0.
fn cmp_versions(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let ai = a.get(i).copied().unwrap_or(0);
        let bi = b.get(i).copied().unwrap_or(0);
        match ai.cmp(&bi) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Version comparison for sort order (ascending).
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    match (parse_parts(a), parse_parts(b)) {
        (Some(pa), Some(pb)) => cmp_versions(&pa, &pb),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => a.cmp(b),
    }
}

// ---- integrity + extraction -----------------------------------------------

/// Verify a downloaded `.gem` against the registry's `sha` field (SHA-256 hex).
fn verify_sha256(ctx: &str, sha: &str, bytes: &[u8]) -> Result<()> {
    if sha.is_empty() {
        return Err(CloudError::Package(format!(
            "gem {ctx}: registry returned no sha256 integrity"
        )));
    }
    // The RubyGems API `sha` field is a raw hex SHA-256 (64 hex chars).
    let got = sha256_hex(bytes);
    if !got.eq_ignore_ascii_case(sha) {
        return Err(CloudError::DigestMismatch {
            expected: sha.to_string(),
            got,
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extensions that mark a host-native artifact inside a gem's data archive.
/// A pure-Ruby gem never contains these. The Ruby runtime in the sandbox
/// cannot `dlopen` host-native code.
const NATIVE_GEM_EXTS: &[&str] = &[
    ".so",     // ELF shared object (Linux native extension)
    ".bundle", // macOS native extension
    ".dll",    // Windows native extension
    ".dylib",  // macOS dynamic library
    ".o",      // object file
    ".a",      // static archive
];

/// Build-descriptor files that signal a native extension will be compiled.
/// Stored lowercased; matched against the lowercased basename.
const NATIVE_BUILD_FILES: &[&str] = &[
    "extconf.rb", // standard Ruby C extension build script
    "makefile",   // generated by extconf.rb
];

/// Inspect a data archive path for native extension markers.
fn is_native_gem_artifact(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    // Check versioned shared objects (e.g. `libssl.so.3`).
    if lower.contains(".so.") {
        return Some(format!("native shared object '{path}'"));
    }
    for suf in NATIVE_GEM_EXTS {
        if lower.ends_with(suf) {
            return Some(format!("native artifact '{path}' ({suf})"));
        }
    }
    for name in NATIVE_BUILD_FILES {
        if base == *name {
            return Some(format!(
                "native build descriptor '{path}' - this gem requires a C compiler; \
                 only pre-built pure-Ruby gems are supported in the Ruby runtime sandbox"
            ));
        }
    }
    None
}

/// Extract a `.gem` archive into a file tree.
///
/// A `.gem` is a tar containing `metadata.gz` and `data.tar.gz`. We unpack
/// `data.tar.gz` and return its contents as the gem's file tree keyed by
/// their paths relative to the gem root. Native artifacts cause a clear error.
fn extract_gem(name: &str, gem_bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    // The outer `.gem` is an uncompressed tar.
    let mut outer = tar::Archive::new(std::io::Cursor::new(gem_bytes));
    let mut data_tar_gz: Option<Vec<u8>> = None;

    for entry in outer
        .entries()
        .map_err(|e| CloudError::Package(format!("gem {name}: outer tar: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| CloudError::Package(format!("gem {name}: outer tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| CloudError::Package(format!("gem {name}: path: {e}")))?
            .to_string_lossy()
            .replace('\\', "/");
        if path == "data.tar.gz" {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| CloudError::Package(format!("gem {name}: read data.tar.gz: {e}")))?;
            if buf.len() as u64 > MAX_GEM_UNCOMPRESSED {
                return Err(CloudError::Package(format!(
                    "gem {name}: data.tar.gz exceeds the {MAX_GEM_UNCOMPRESSED}-byte limit"
                )));
            }
            data_tar_gz = Some(buf);
            break;
        }
    }

    let data_gz = data_tar_gz.ok_or_else(|| {
        CloudError::Package(format!("gem {name}: missing data.tar.gz in .gem archive"))
    })?;

    // Decompress and untar `data.tar.gz`.
    let dec = flate2::read::GzDecoder::new(std::io::Cursor::new(&data_gz));
    let mut inner = tar::Archive::new(dec.take(MAX_GEM_UNCOMPRESSED));
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;

    for entry in inner
        .entries()
        .map_err(|e| CloudError::Package(format!("gem {name}: data.tar.gz: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| CloudError::Package(format!("gem {name}: data entry: {e}")))?;
        let etype = entry.header().entry_type();
        if etype.is_symlink() || etype.is_hard_link() {
            return Err(CloudError::Package(format!(
                "gem {name}: refusing link entry in data.tar.gz"
            )));
        }
        if !etype.is_file() {
            continue;
        }
        let raw_path = entry
            .path()
            .map_err(|e| CloudError::Package(format!("gem {name}: data path: {e}")))?
            .to_string_lossy()
            .replace('\\', "/");
        // Normalize the path: strip a leading `./` that tar sometimes emits.
        let rel = raw_path.strip_prefix("./").unwrap_or(&raw_path).to_string();
        if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
            return Err(CloudError::Package(format!(
                "gem {name}: unsafe path {raw_path:?} in data.tar.gz"
            )));
        }
        // Native-artifact gate: refuse host-native code loudly.
        if let Some(reason) = is_native_gem_artifact(&rel) {
            return Err(CloudError::Package(format!(
                "gem {name}: {reason} - the Ruby runtime sandbox cannot load \
                 host-native C extensions; only pre-built pure-Ruby gems are \
                 supported. Use a pure-Ruby alternative or a gem that ships a \
                 pre-built WASI/Ruby-runtime binary."
            )));
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(CloudError::Io)?;
        total += data.len() as u64;
        if total > MAX_GEM_UNCOMPRESSED {
            return Err(CloudError::Package(format!(
                "gem {name}: data.tar.gz exceeds the {MAX_GEM_UNCOMPRESSED}-byte unpacked limit"
            )));
        }
        out.insert(rel, data);
    }

    if out.is_empty() {
        return Err(CloudError::Package(format!(
            "gem {name}: data.tar.gz is empty"
        )));
    }
    Ok(out)
}

// ---- on-disk gem cache (thin wrappers over ecosystem cache) ----------------

/// `~/.cache/burn/gem`.
pub fn gem_cache_root() -> Result<PathBuf> {
    let dir = dirs::cache_dir().ok_or(CloudError::NoCacheDir)?;
    Ok(dir.join("burn").join("gem"))
}

/// Directory for an extracted gem `name@version`.
pub fn gem_cache_dir(name: &str, version: &str) -> Result<PathBuf> {
    Ok(gem_cache_root()?.join(format!("{name}@{version}")))
}

/// Write a resolved gem's files into the cache.
pub fn store_gem(pkg: &GemPackage) -> Result<PathBuf> {
    let client = GemClient::new(DEFAULT_GEM_REGISTRY);
    ecosystem::store_artifact(&client, pkg)
}

/// Load a cached gem's files. Returns `None` if not cached.
pub fn load_gem(name: &str, version: &str) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    let client = GemClient::new(DEFAULT_GEM_REGISTRY);
    ecosystem::load_artifact(&client, name, version)
}

// ---- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- satisfies: `~>` pessimistic operator --

    #[test]
    fn twiddle_wakka_major_pin() {
        // `~> 2.0` means `>= 2.0, < 3`.
        assert!(satisfies("2.0.0", "~> 2.0"));
        assert!(satisfies("2.9.9", "~> 2.0"));
        assert!(!satisfies("3.0.0", "~> 2.0"));
        assert!(!satisfies("1.9.9", "~> 2.0"));
    }

    #[test]
    fn twiddle_wakka_minor_pin() {
        // `~> 2.0.1` means `>= 2.0.1, < 2.1`.
        assert!(satisfies("2.0.1", "~> 2.0.1"));
        assert!(satisfies("2.0.9", "~> 2.0.1"));
        assert!(!satisfies("2.1.0", "~> 2.0.1"));
        assert!(!satisfies("2.0.0", "~> 2.0.1"));
        assert!(!satisfies("1.9.9", "~> 2.0.1"));
    }

    #[test]
    fn twiddle_wakka_single_component() {
        // `~> 1` means `>= 1, < 2`.
        assert!(satisfies("1.0.0", "~> 1"));
        assert!(satisfies("1.9.9", "~> 1"));
        assert!(!satisfies("2.0.0", "~> 1"));
        assert!(!satisfies("0.9.0", "~> 1"));
    }

    // -- satisfies: plain comparators --

    #[test]
    fn plain_gte() {
        assert!(satisfies("2.7.0", ">= 2.7"));
        assert!(satisfies("3.0.0", ">= 2.7"));
        assert!(!satisfies("2.6.9", ">= 2.7"));
    }

    #[test]
    fn plain_gt() {
        assert!(satisfies("2.8.0", "> 2.7"));
        assert!(!satisfies("2.7.0", "> 2.7"));
    }

    #[test]
    fn plain_lte() {
        assert!(satisfies("2.7.0", "<= 2.7"));
        assert!(!satisfies("2.8.0", "<= 2.7"));
    }

    #[test]
    fn plain_lt() {
        assert!(satisfies("2.6.9", "< 2.7"));
        assert!(!satisfies("2.7.0", "< 2.7"));
    }

    #[test]
    fn plain_eq() {
        assert!(satisfies("1.4.0", "= 1.4.0"));
        assert!(!satisfies("1.4.1", "= 1.4.0"));
    }

    #[test]
    fn plain_neq() {
        assert!(satisfies("1.4.1", "!= 1.4.0"));
        assert!(!satisfies("1.4.0", "!= 1.4.0"));
    }

    // -- satisfies: comma-AND --

    #[test]
    fn comma_and_range() {
        // `>= 2.7, < 3` - typical sinatra-style range.
        assert!(satisfies("2.7.0", ">= 2.7, < 3"));
        assert!(satisfies("2.9.9", ">= 2.7, < 3"));
        assert!(!satisfies("3.0.0", ">= 2.7, < 3"));
        assert!(!satisfies("2.6.9", ">= 2.7, < 3"));
    }

    #[test]
    fn wildcard_matches_anything() {
        assert!(satisfies("1.2.3", "*"));
        assert!(satisfies("99.0.0", ""));
    }

    // -- native artifact detection --

    #[test]
    fn native_so_detected() {
        assert!(is_native_gem_artifact("lib/foo/native.so").is_some());
        assert!(is_native_gem_artifact("lib/foo.bundle").is_some());
        assert!(is_native_gem_artifact("ext/foo/libssl.so.3").is_some());
    }

    #[test]
    fn extconf_rb_detected() {
        assert!(is_native_gem_artifact("ext/foo/extconf.rb").is_some());
        assert!(is_native_gem_artifact("extconf.rb").is_some());
    }

    #[test]
    fn makefile_detected() {
        assert!(is_native_gem_artifact("ext/foo/Makefile").is_some());
    }

    #[test]
    fn pure_ruby_allowed() {
        for p in [
            "lib/foo.rb",
            "lib/foo/bar.rb",
            "README.md",
            "Gemfile",
            "LICENSE",
            "foo.gemspec",
            "lib/foo/version.rb",
        ] {
            assert!(is_native_gem_artifact(p).is_none(), "{p} must be allowed");
        }
    }

    // -- gem extraction --

    /// Build a minimal valid `.gem` archive in memory and return the bytes.
    fn make_gem(files: &[(&str, &[u8])]) -> Vec<u8> {
        // Build `data.tar.gz`.
        let mut data_tar = Vec::new();
        {
            let mut b = tar::Builder::new(&mut data_tar);
            for (rel, body) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, rel, &body[..]).unwrap();
            }
            b.finish().unwrap();
        }
        let mut data_tar_gz = Vec::new();
        {
            use flate2::write::GzEncoder;
            use std::io::Write;
            let mut e = GzEncoder::new(&mut data_tar_gz, flate2::Compression::default());
            e.write_all(&data_tar).unwrap();
            e.finish().unwrap();
        }
        // Build the outer `.gem` tar.
        let mut gem = Vec::new();
        {
            let mut b = tar::Builder::new(&mut gem);
            let meta = b"--- !ruby/object:Gem::Specification\nname: test\n";
            let mut mh = tar::Header::new_gnu();
            mh.set_size(meta.len() as u64);
            mh.set_mode(0o644);
            mh.set_cksum();
            b.append_data(&mut mh, "metadata.gz", &meta[..]).unwrap();
            let mut dh = tar::Header::new_gnu();
            dh.set_size(data_tar_gz.len() as u64);
            dh.set_mode(0o644);
            dh.set_cksum();
            b.append_data(&mut dh, "data.tar.gz", &data_tar_gz[..])
                .unwrap();
            b.finish().unwrap();
        }
        gem
    }

    #[test]
    fn extract_pure_ruby_gem() {
        let gem = make_gem(&[("lib/foo.rb", b"module Foo; end"), ("README.md", b"# Foo")]);
        let files = extract_gem("foo", &gem).unwrap();
        assert_eq!(
            files.get("lib/foo.rb").map(|v| v.as_slice()),
            Some(&b"module Foo; end"[..])
        );
        assert!(files.contains_key("README.md"));
    }

    #[test]
    fn extract_native_extension_gem_is_refused() {
        let gem = make_gem(&[
            ("lib/foo.rb", b"require 'foo/foo'"),
            ("ext/foo/foo.c", b"#include <ruby.h>"),
            ("ext/foo/extconf.rb", b"require 'mkmf'"),
        ]);
        let err = extract_gem("foo", &gem).unwrap_err();
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("native") || msg.contains("extconf"),
            "native extension must be rejected: {err}"
        );
    }

    #[test]
    fn extract_native_so_is_refused() {
        let gem = make_gem(&[
            ("lib/foo.rb", b"require 'foo/foo'"),
            ("lib/foo/foo.so", b"\x7fELF\x00native"),
        ]);
        let err = extract_gem("foo", &gem).unwrap_err();
        assert!(
            format!("{err}").to_lowercase().contains("native"),
            "native .so must be rejected: {err}"
        );
    }

    #[test]
    fn sha256_mismatch_is_rejected() {
        let err = verify_sha256(
            "foo-1.0.0",
            "deadbeef00000000deadbeef00000000deadbeef00000000deadbeef00000000",
            b"hello",
        )
        .unwrap_err();
        assert!(
            matches!(err, CloudError::DigestMismatch { .. }),
            "digest mismatch must be DigestMismatch: {err}"
        );
    }

    #[test]
    fn empty_sha_is_rejected() {
        let err = verify_sha256("foo-1.0.0", "", b"hello").unwrap_err();
        assert!(
            matches!(err, CloudError::Package(_)),
            "empty sha must be Package error: {err}"
        );
    }

    // -- resolve: mock server integration --

    #[test]
    fn resolve_pure_gem_with_transitive_dep() {
        use httpmock::prelude::*;
        use std::collections::BTreeMap;

        let server = MockServer::start();

        // Build `dep-1.0.0.gem` (pure Ruby).
        let dep_gem = make_gem(&[("lib/dep.rb", b"module Dep; end")]);
        let dep_sha = sha256_hex(&dep_gem);
        let dep_gem_path = "/gems/dep-1.0.0.gem";
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/versions/dep.json");
            then.status(200).json_body(serde_json::json!([
                {
                    "number": "1.0.0",
                    "platform": "ruby",
                    "sha": dep_sha,
                    "dependencies": { "runtime": [], "development": [] }
                }
            ]));
        });
        server.mock(|when, then| {
            when.method(GET).path(dep_gem_path);
            then.status(200).body(dep_gem);
        });

        // Build `widget-2.0.0.gem` depending on `dep ~> 1.0`.
        let widget_gem = make_gem(&[("lib/widget.rb", b"require 'dep'; module Widget; end")]);
        let widget_sha = sha256_hex(&widget_gem);
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/versions/widget.json");
            then.status(200).json_body(serde_json::json!([
                {
                    "number": "1.5.0",
                    "platform": "ruby",
                    "sha": "0000000000000000000000000000000000000000000000000000000000000000",
                    "dependencies": { "runtime": [{"name": "dep", "requirements": "~> 1.0"}] }
                },
                {
                    "number": "2.0.0",
                    "platform": "ruby",
                    "sha": widget_sha,
                    "dependencies": { "runtime": [{"name": "dep", "requirements": "~> 1.0"}] }
                }
            ]));
        });
        server.mock(|when, then| {
            when.method(GET).path("/gems/widget-2.0.0.gem");
            then.status(200).body(widget_gem);
        });

        let client = GemClient::new(server.base_url());
        let mut roots = BTreeMap::new();
        roots.insert("widget".to_string(), ">= 2.0".to_string());
        let res = client.resolve_all(&roots).expect("resolve");

        let widget = res.by_name("widget").expect("widget resolved");
        assert_eq!(widget.version, "2.0.0");
        assert!(widget.files.contains_key("lib/widget.rb"));

        let dep = res.by_name("dep").expect("transitive dep resolved");
        assert_eq!(dep.version, "1.0.0");
        assert!(dep.files.contains_key("lib/dep.rb"));
    }

    #[test]
    fn corrupt_gem_fails_integrity() {
        use httpmock::prelude::*;
        use std::collections::BTreeMap;

        let server = MockServer::start();
        let real_gem = make_gem(&[("lib/x.rb", b"# x")]);
        let real_sha = sha256_hex(&real_gem);
        let bad_gem = make_gem(&[("lib/x.rb", b"# TAMPERED")]);

        server.mock(|when, then| {
            when.method(GET).path("/api/v1/versions/x.json");
            then.status(200).json_body(serde_json::json!([{
                "number": "1.0.0", "platform": "ruby",
                "sha": real_sha,
                "dependencies": { "runtime": [] }
            }]));
        });
        server.mock(|when, then| {
            when.method(GET).path("/gems/x-1.0.0.gem");
            then.status(200).body(bad_gem);
        });

        let client = GemClient::new(server.base_url());
        let mut roots = BTreeMap::new();
        roots.insert("x".to_string(), "= 1.0.0".to_string());
        let err = client.resolve_all(&roots).unwrap_err();
        assert!(
            format!("{err}").contains("integrity")
                || matches!(err, CloudError::DigestMismatch { .. }),
            "tampered gem must fail integrity: {err}"
        );
    }

    #[test]
    fn native_gem_from_registry_is_rejected() {
        use httpmock::prelude::*;
        use std::collections::BTreeMap;

        let server = MockServer::start();
        let native_gem = make_gem(&[
            ("lib/bcrypt.rb", b"require 'bcrypt/bcrypt_ext'"),
            ("lib/bcrypt/bcrypt_ext.so", b"\x7fELF\x00native"),
        ]);
        let sha = sha256_hex(&native_gem);

        server.mock(|when, then| {
            when.method(GET).path("/api/v1/versions/bcrypt.json");
            then.status(200).json_body(serde_json::json!([{
                "number": "3.1.19", "platform": "ruby",
                "sha": sha,
                "dependencies": { "runtime": [] }
            }]));
        });
        server.mock(|when, then| {
            when.method(GET).path("/gems/bcrypt-3.1.19.gem");
            then.status(200).body(native_gem);
        });

        let client = GemClient::new(server.base_url());
        let mut roots = BTreeMap::new();
        roots.insert("bcrypt".to_string(), "~> 3.1".to_string());
        let err = client.resolve_all(&roots).unwrap_err();
        assert!(
            format!("{err}").to_lowercase().contains("native"),
            "native gem must be rejected: {err}"
        );
    }
}
