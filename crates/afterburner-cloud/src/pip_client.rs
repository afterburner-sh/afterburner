// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! PyPI registry client for `[pip]` dependencies.
//!
//! `burn install` resolves a `[pip]` closure WITHOUT a Python toolchain on the
//! host: fetch the PyPI JSON API -> pick the highest version satisfying the PEP
//! 440 specifier -> download the wheel -> sha256-verify -> extract into the
//! content-addressed pip cache. The shared [`ecosystem::resolve_all`] BFS walk
//! handles the transitive `Requires-Dist` closure.
//!
//! ## Wheel selection policy
//!
//! The bundled Python runtime is CPython compiled for Emscripten/wasm32. Only
//! two wheel filename tags are compatible:
//!
//! * `py3-none-any` - pure Python, runs on any Python 3 interpreter.
//! * `cpython-<xy>-wasm32-emscripten` - compiled for the sandbox ABI (the soabi
//!   tag the bundled CPython uses for its own wheel set).
//!
//! Any other binary wheel (manylinux, macOS, Windows, etc.) or an sdist is
//! refused with an actionable error. burn ships stock sandbox artifacts only
//! and never recompiles from source.
//!
//! ## Built-in wheel priority
//!
//! The `~/.burn` built-in wheel set (numpy, pandas, and friends shipped with
//! the bundled Python) is resolved FIRST - if a package name is in the built-in
//! set, no network request is made and no cache entry is needed. The caller
//! layer (Phase PD) mounts the built-in wheels; this client only fetches what
//! the built-in set does not cover.
//!
//! ## Security
//!
//! * **Integrity-verified.** Each wheel is checked against the PyPI-advertised
//!   sha256 digest before it is cached.
//! * **No build tools.** Sdists requiring a build are refused outright (never
//!   executed, never partially extracted).
//! * **Bounded.** Per-wheel download cap; path-escape / symlink entries are
//!   refused by the extractor.
//! * **No install hooks.** Wheels are extracted as data; `entry_points`,
//!   `post-install` scripts, and `setup.py` are never executed.

use crate::ecosystem::{
    self, EcosystemClient, EcosystemPackage, EcosystemRelease, EcosystemResolution,
};
use crate::error::{CloudError, Result};
use afterburner_afb::specifier::{Pep440Clause, Pep440Op, Pep440Specifier, parse_pip_specifier};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

/// Default PyPI JSON API base (no trailing slash).
pub const DEFAULT_PYPI_BASE: &str = "https://pypi.org";

/// Hard ceiling on a single wheel download (compressed; consistent with npm).
const MAX_WHEEL_COMPRESSED: u64 = 64 * 1024 * 1024;

/// Uncompressed extraction ceiling per wheel.
const MAX_WHEEL_UNCOMPRESSED: u64 = 128 * 1024 * 1024;

/// A resolved + extracted pip package. Type alias for the shared type.
pub type PipPackage = EcosystemPackage;

/// The full resolved pip closure for a package's `[pip]` section.
pub type PipResolution = EcosystemResolution;

// ---- PEP 503 name normalisation --------------------------------------------

/// PEP 503: normalize a pip package name for cache key and API lookup.
/// Collapses runs of `[-_.]` to `-` and lowercases.
fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_dash {
                out.push('-');
                prev_dash = true;
            }
        } else {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        }
    }
    out
}

// ---- PEP 440 version comparison --------------------------------------------

/// A parsed PEP 440 version for comparison.
///
/// Only the components relevant to ordering are stored:
/// epoch, release tuple, pre-release (kind + N), post-release, dev-release.
/// Local version labels are ignored for ordering (PEP 440 spec).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pep440Version {
    epoch: u64,
    release: Vec<u64>,
    pre: Option<PreKind>,
    post: Option<u64>,
    dev: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PreKind {
    Alpha(u64),
    Beta(u64),
    Rc(u64),
}

impl PartialOrd for Pep440Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pep440Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::Equal;
        // Epoch takes precedence.
        let c = self.epoch.cmp(&other.epoch);
        if c != Equal {
            return c;
        }
        // Release segments: pad shorter with 0s.
        let len = self.release.len().max(other.release.len());
        for i in 0..len {
            let a = self.release.get(i).copied().unwrap_or(0);
            let b = other.release.get(i).copied().unwrap_or(0);
            let c = a.cmp(&b);
            if c != Equal {
                return c;
            }
        }
        // Pre-release, post, dev ordering per PEP 440:
        // - dev < no-pre < pre(alpha) < pre(beta) < pre(rc) < final
        // - .post > final
        // Represent as (pre_ord, post_ord, dev_ord):
        //   pre_ord: -inf for dev, 0 for pre, 1 for final
        //   etc. -- easier to just use a multi-key compare.
        let dev_a = self.dev.map(|n| n as i64).unwrap_or(i64::MAX);
        let dev_b = other.dev.map(|n| n as i64).unwrap_or(i64::MAX);
        // A dev release is less than any non-dev release at the same release.
        if self.dev.is_some() != other.dev.is_some() {
            return dev_a.cmp(&dev_b);
        }
        // Both have dev or both don't.
        let c = dev_a.cmp(&dev_b);
        if c != Equal {
            return c;
        }
        // Pre-release vs final vs post.
        match (&self.pre, &other.pre) {
            (None, None) => {}
            (Some(_), None) => return std::cmp::Ordering::Less,
            (None, Some(_)) => return std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => {
                let c = a.cmp(b);
                if c != Equal {
                    return c;
                }
            }
        }
        // Post-release.
        let post_a = self.post.map(|n| n as i64).unwrap_or(-1);
        let post_b = other.post.map(|n| n as i64).unwrap_or(-1);
        post_a.cmp(&post_b)
    }
}

/// Parse a PEP 440 version string into its components.
/// Returns `None` for strings that are not valid PEP 440 versions.
fn parse_pep440_version(s: &str) -> Option<Pep440Version> {
    let s = s.trim();
    // Strip local version label (`+local`).
    let s = s.split('+').next().unwrap_or(s);

    // Epoch.
    let (epoch, rest) = if let Some(idx) = s.find('!') {
        let e = s[..idx].parse::<u64>().ok()?;
        (e, &s[idx + 1..])
    } else {
        (0, s)
    };

    // Split off dev suffix (`.devN`).
    let (main, dev) = split_suffix_segment(rest, "dev");

    // Split off post suffix (`.postN` or `.post` with N=0).
    let (main, post) = split_suffix_segment(main, "post");

    // Split off pre suffix: alpha/a, beta/b, rc/c/preview/pre.
    let (main, pre) = parse_pre_suffix(main);

    // Parse release segments.
    let release: Vec<u64> = main
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if release.is_empty() {
        return None;
    }

    Some(Pep440Version {
        epoch,
        release,
        pre,
        post,
        dev,
    })
}

/// Split `s` into (`prefix`, `Option<N>`) where the suffix is `.{label}N` or
/// `.{label}` (N defaults to 0). E.g. `split_suffix_segment("1.2.post3", "post")`
/// -> `("1.2", Some(3))`.
fn split_suffix_segment<'a>(s: &'a str, label: &str) -> (&'a str, Option<u64>) {
    // Look for `.{label}` or just `{label}` at the end (PEP 440 allows no
    // leading dot for pre-release when it is not ambiguous).
    // Try `.labelN` form first.
    let dot_label = format!(".{label}");
    if let Some(pos) = s.to_ascii_lowercase().rfind(&dot_label) {
        let n_str = &s[pos + 1 + label.len()..];
        let n = n_str.parse::<u64>().unwrap_or(0);
        return (&s[..pos], Some(n));
    }
    (s, None)
}

/// Parse a pre-release suffix from the tail of a version string.
/// Returns `(string_without_pre, pre_kind)`.
fn parse_pre_suffix(s: &str) -> (&str, Option<PreKind>) {
    // Pre-release labels (in order): alpha/a, beta/b, rc/c/preview/pre
    // PEP 440 also accepts them after a dot or directly appended.
    for (label, constructor) in &[
        ("rc", PreKind::Rc as fn(u64) -> PreKind),
        ("c", PreKind::Rc),
        ("alpha", PreKind::Alpha),
        ("a", PreKind::Alpha),
        ("beta", PreKind::Beta),
        ("b", PreKind::Beta),
        ("preview", PreKind::Rc),
        ("pre", PreKind::Rc),
    ] {
        let lower = s.to_ascii_lowercase();
        // Try `.labelN` (dotted form).
        let dot_label = format!(".{label}");
        if let Some(pos) = lower.rfind(&dot_label) {
            let n_str = &s[pos + 1 + label.len()..];
            // The remainder after the label must be digits or empty.
            let n = n_str.parse::<u64>().unwrap_or(0);
            return (&s[..pos], Some(constructor(n)));
        }
        // Try `labelN` at the end of the last segment (direct append: `1.0a1`).
        if let Some(stripped) = lower.strip_suffix(label) {
            // Whatever precedes the label must end in a digit.
            if stripped.ends_with(|c: char| c.is_ascii_digit()) {
                return (&s[..stripped.len()], Some(constructor(0)));
            }
        }
        // `labelN` at the end of the last segment (with digit: `1.0a1`).
        if let Some(idx) = lower.rfind(label) {
            let after = &s[idx + label.len()..];
            let before = &s[..idx];
            // `after` must be digits only; `before` must end with a digit.
            if after.chars().all(|c| c.is_ascii_digit())
                && before.ends_with(|c: char| c.is_ascii_digit())
            {
                let n = after.parse::<u64>().unwrap_or(0);
                return (before, Some(constructor(n)));
            }
        }
    }
    (s, None)
}

/// Release prefix for a `.*` wildcard match: strip trailing `.0`s, then match
/// against `prefix.` prefix. E.g. `"1.4.*"` base `"1.4"` matches `"1.4.2"`.
fn release_prefix_matches(candidate: &Pep440Version, prefix_str: &str) -> bool {
    let prefix = parse_pep440_version(prefix_str);
    let prefix = match prefix {
        Some(p) => p,
        None => return false,
    };
    // The candidate must have at least as many segments as the prefix,
    // and each prefix segment must equal the candidate's.
    let n = prefix.release.len();
    if candidate.release.len() < n {
        return false;
    }
    prefix
        .release
        .iter()
        .zip(candidate.release.iter())
        .all(|(p, c)| p == c)
}

/// Evaluate one PEP 440 clause against a candidate version string.
/// Returns `false` if the candidate cannot be parsed as a PEP 440 version.
fn clause_matches(candidate: &Pep440Version, clause: &Pep440Clause) -> bool {
    use std::cmp::Ordering::*;

    match clause.op {
        Pep440Op::Equal => {
            if clause.version == "*" {
                return true;
            }
            if clause.version.ends_with(".*") {
                let base = clause.version.trim_end_matches(".*");
                return release_prefix_matches(candidate, base);
            }
            // Exact match (ignoring local label, already stripped in parse).
            parse_pep440_version(&clause.version)
                .map(|v| candidate.cmp(&v) == Equal)
                .unwrap_or(false)
        }
        Pep440Op::NotEqual => {
            if clause.version.ends_with(".*") {
                let base = clause.version.trim_end_matches(".*");
                return !release_prefix_matches(candidate, base);
            }
            parse_pep440_version(&clause.version)
                .map(|v| candidate.cmp(&v) != Equal)
                .unwrap_or(true)
        }
        Pep440Op::Gte => parse_pep440_version(&clause.version)
            .map(|v| matches!(candidate.cmp(&v), Greater | Equal))
            .unwrap_or(false),
        Pep440Op::Lte => parse_pep440_version(&clause.version)
            .map(|v| matches!(candidate.cmp(&v), Less | Equal))
            .unwrap_or(false),
        Pep440Op::Gt => parse_pep440_version(&clause.version)
            .map(|v| candidate.cmp(&v) == Greater)
            .unwrap_or(false),
        Pep440Op::Lt => parse_pep440_version(&clause.version)
            .map(|v| candidate.cmp(&v) == Less)
            .unwrap_or(false),
        Pep440Op::Compatible => {
            // `~= X.Y[.Z...]` is equivalent to `>= X.Y[.Z...], == X.Y.*`
            // (or `== X.*` for a two-segment version).
            let v = match parse_pep440_version(&clause.version) {
                Some(v) => v,
                None => return false,
            };
            // Must be >= the specified version.
            if candidate.cmp(&v) == Less {
                return false;
            }
            // Must match the prefix up to (but not including) the last segment.
            let n = v.release.len();
            if n < 2 {
                return false; // specifier.rs already rejects single-component ~=
            }
            let prefix_release = &v.release[..n - 1];
            if candidate.release.len() < prefix_release.len() {
                return false;
            }
            prefix_release
                .iter()
                .zip(candidate.release.iter())
                .all(|(p, c)| p == c)
        }
        Pep440Op::ArbitraryEqual => {
            // String equality on the version field (no normalisation).
            clause.version == candidate_raw_str(candidate)
        }
    }
}

/// Reconstruct a minimal version string from a parsed version (for `===`).
fn candidate_raw_str(v: &Pep440Version) -> String {
    let mut s = String::new();
    if v.epoch != 0 {
        s.push_str(&format!("{}!", v.epoch));
    }
    s.push_str(
        &v.release
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("."),
    );
    if let Some(pre) = &v.pre {
        match pre {
            PreKind::Alpha(n) => s.push_str(&format!("a{n}")),
            PreKind::Beta(n) => s.push_str(&format!("b{n}")),
            PreKind::Rc(n) => s.push_str(&format!("rc{n}")),
        }
    }
    if let Some(post) = v.post {
        s.push_str(&format!(".post{post}"));
    }
    if let Some(dev) = v.dev {
        s.push_str(&format!(".dev{dev}"));
    }
    s
}

/// Whether `version_str` satisfies the PEP 440 `spec_str`.
///
/// Returns `false` if either string cannot be parsed.
pub fn satisfies(version_str: &str, spec_str: &str) -> bool {
    let candidate = match parse_pep440_version(version_str) {
        Some(v) => v,
        None => return false,
    };
    let spec = match parse_pip_specifier(spec_str) {
        Ok(s) => s,
        Err(_) => return false,
    };
    pep440_matches(&candidate, &spec)
}

fn pep440_matches(candidate: &Pep440Version, spec: &Pep440Specifier) -> bool {
    if spec.is_any() {
        return true;
    }
    spec.clauses.iter().all(|c| clause_matches(candidate, c))
}

// ---- Wheel filename parsing ------------------------------------------------

/// Whether a wheel filename is compatible with the sandbox.
///
/// Accepted:
/// - `py3-none-any.whl` (and `py2.py3-none-any.whl`) - pure Python
/// - `cp<xy>-cp<xy>-wasm32_emscripten.whl` - sandbox ABI
///
/// Refused (returns a refusal reason):
/// - `manylinux`, `linux`, `musllinux` - host Linux ABI
/// - `macosx` - macOS ABI
/// - `win32`, `win_amd64`, `win_arm64` - Windows ABI
/// - sdists (`.tar.gz`, `.zip` not ending in `.whl`)
fn wheel_abi_check(filename: &str) -> Result<()> {
    let lower = filename.to_ascii_lowercase();

    if !lower.ends_with(".whl") {
        // sdist or other artifact
        return Err(CloudError::Package(format!(
            "pip: {filename:?} is a source distribution or unsupported artifact; \
             burn only installs pre-built wheels. Use a package that publishes \
             a pure-Python (py3-none-any) or sandbox-ABI wheel."
        )));
    }

    // Wheel filename: `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`
    // We care about the last three dash-separated segments before `.whl`.
    let stem = filename.trim_end_matches(".whl");
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() < 5 {
        return Err(CloudError::Package(format!(
            "pip: {filename:?} has an unexpected wheel filename format"
        )));
    }

    // Platform tag is the last segment; abi is second-to-last; python is third-to-last.
    let platform = parts[parts.len() - 1].to_ascii_lowercase();
    let abi = parts[parts.len() - 2].to_ascii_lowercase();
    let python = parts[parts.len() - 3].to_ascii_lowercase();

    // Pure Python: python tag must start with `py`, abi=`none`, platform=`any`.
    if (python.starts_with("py") || python == "py2.py3" || python == "py3")
        && abi == "none"
        && platform == "any"
    {
        return Ok(());
    }

    // Sandbox ABI: platform must be `wasm32_emscripten` (or `emscripten_*`).
    if platform == "wasm32_emscripten" || platform.starts_with("emscripten_") {
        // Accept any cpython tag against the emscripten platform.
        return Ok(());
    }

    // Refuse host-native ABIs with an actionable message.
    let reason = if platform.contains("manylinux")
        || platform.contains("musllinux")
        || platform.contains("linux")
    {
        format!("manylinux/Linux host binary (platform: {platform})")
    } else if platform.contains("macosx") || platform.contains("macos") {
        format!("macOS host binary (platform: {platform})")
    } else if platform.contains("win") {
        format!("Windows host binary (platform: {platform})")
    } else {
        format!("unsupported platform (platform: {platform})")
    };

    Err(CloudError::Package(format!(
        "pip: {filename:?} is a {reason}; burn ships stock sandbox artifacts only \
         and cannot run host-native binaries. Use a pure-Python (py3-none-any) wheel \
         or a wheel built for the sandbox ABI (cpython-wasm32-emscripten)."
    )))
}

// ---- Wheel extraction (zip) ------------------------------------------------

/// Extract a wheel (zip) into a flat file map, with bounds and path-escape checks.
fn extract_wheel(name: &str, bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    use std::io::Cursor;
    let cursor = Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(cursor)
        .map_err(|e| CloudError::Package(format!("pip {name}: wheel zip error: {e}")))?;

    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| CloudError::Package(format!("pip {name}: zip entry {i}: {e}")))?;

        if entry.is_dir() {
            continue;
        }

        // Symlinks inside zip: the zip crate exposes them as files; detect
        // Unix symlink external attributes (0xA... file type bits).
        let unix_mode = entry.unix_mode();
        if let Some(mode) = unix_mode
            && (mode >> 12) == 0xA
        {
            return Err(CloudError::Package(format!(
                "pip {name}: refusing symlink entry in wheel"
            )));
        }

        let rel = entry
            .name()
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();
        if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
            return Err(CloudError::Package(format!(
                "pip {name}: unsafe path {rel:?} in wheel"
            )));
        }

        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| CloudError::Package(format!("pip {name}: reading {rel}: {e}")))?;
        total += data.len() as u64;
        if total > MAX_WHEEL_UNCOMPRESSED {
            return Err(CloudError::Package(format!(
                "pip {name}: wheel exceeds the {MAX_WHEEL_UNCOMPRESSED}-byte unpacked limit"
            )));
        }
        out.insert(rel, data);
    }

    if out.is_empty() {
        return Err(CloudError::Package(format!("pip {name}: empty wheel")));
    }
    Ok(out)
}

// ---- sha256 integrity verification -----------------------------------------

fn verify_sha256(ctx: &str, expected_hex: &str, bytes: &[u8]) -> Result<()> {
    if expected_hex.is_empty() {
        return Err(CloudError::Package(format!(
            "pip {ctx}: registry returned no sha256 digest"
        )));
    }
    let got = hex_lower(Sha256::digest(bytes).as_slice());
    let expected = expected_hex.trim_start_matches("sha256:");
    if !got.eq_ignore_ascii_case(expected) {
        return Err(CloudError::DigestMismatch {
            expected: expected.to_string(),
            got,
        });
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        })
}

// ---- PyPI JSON API model ---------------------------------------------------

/// Top-level response from `GET /pypi/<name>/json`.
#[derive(serde::Deserialize)]
struct PypiPackage {
    info: PypiInfo,
    /// All versions with their urls.
    releases: BTreeMap<String, Vec<PypiUrl>>,
}

#[derive(serde::Deserialize, Clone)]
struct PypiInfo {
    /// Latest stable version (used for the `info.urls` field only).
    #[allow(dead_code)]
    version: String,
    /// PEP 566 / PyPI metadata `requires_dist` list. May be absent for old packages.
    #[serde(default)]
    requires_dist: Vec<String>,
}

/// One file entry from `releases["version"][]`.
#[derive(serde::Deserialize, Clone)]
struct PypiUrl {
    filename: String,
    url: String,
    #[serde(default)]
    digests: PypiDigests,
    packagetype: String,
}

#[derive(serde::Deserialize, Clone, Default)]
struct PypiDigests {
    #[serde(default)]
    sha256: String,
}

// ---- Parse requires_dist ---------------------------------------------------

/// Parse `Requires-Dist` marker lines into `(name, specifier)` pairs.
/// Lines with environment markers (`;`) are skipped in v1 (honesty: we skip
/// them rather than silently include all - see the gap audit, G3).
fn parse_requires_dist(lines: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in lines {
        let line = line.trim();
        // Skip extras conditions and env markers.
        if line.contains(';') {
            continue;
        }
        // Format: `name (specifier)` or `name specifier` or just `name`.
        // PEP 508 name may contain extras `[extra,...]` - strip them.
        let name_part = line.split_whitespace().next().unwrap_or("").trim();
        let name_part = name_part.split('[').next().unwrap_or("").trim();
        if name_part.is_empty() {
            continue;
        }
        // The specifier is the rest after the name (PEP 508 extras stripped).
        let rest = line[name_part.len()..].trim();
        // Strip surrounding parens if present: `(>=1.0)` -> `>=1.0`.
        let spec = rest
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim()
            .to_string();
        let spec = if spec.is_empty() {
            "*".to_string()
        } else {
            spec
        };
        out.insert(normalize_name(name_part), spec);
    }
    out
}

// ---- PipClient -------------------------------------------------------------

/// A registry client over `ureq`. `base` lets tests point at a mock server.
pub struct PipClient {
    agent: ureq::Agent,
    /// Base URL of the PyPI-compatible index (no trailing slash).
    base: String,
}

impl PipClient {
    /// Build a client against an arbitrary index base (for tests / private indexes).
    pub fn new(base: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(60))
            .build();
        Self {
            agent,
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    /// Build a client against the public PyPI registry.
    pub fn public() -> Self {
        Self::new(DEFAULT_PYPI_BASE)
    }

    /// Resolve a `[pip]` section (name -> PEP 440 specifier) and its full
    /// transitive `Requires-Dist` closure. Delegates to [`ecosystem::resolve_all`].
    pub fn resolve_all(&self, roots: &BTreeMap<String, String>) -> Result<PipResolution> {
        // Normalize root names before resolving.
        let roots_norm: BTreeMap<String, String> = roots
            .iter()
            .map(|(k, v)| (normalize_name(k), v.clone()))
            .collect();
        ecosystem::resolve_all(self, &roots_norm)
    }

    fn fetch_pypi_package(&self, name: &str) -> Result<PypiPackage> {
        let url = format!("{}/pypi/{}/json", self.base, name);
        let resp = self
            .agent
            .get(&url)
            .set("accept", "application/json")
            .call()
            .map_err(|e| ecosystem::map_ureq(name, e))?;
        let mut body = String::new();
        resp.into_reader()
            .take(MAX_WHEEL_COMPRESSED)
            .read_to_string(&mut body)
            .map_err(CloudError::Io)?;
        serde_json::from_str(&body)
            .map_err(|e| CloudError::Decode(format!("PyPI metadata for {name}: {e}")))
    }
}

// ---- EcosystemClient impl --------------------------------------------------

impl EcosystemClient for PipClient {
    fn versions(&self, name: &str) -> Result<Vec<EcosystemRelease>> {
        let pkg = self.fetch_pypi_package(name)?;

        let mut releases: Vec<EcosystemRelease> = Vec::new();

        for (version_str, urls) in &pkg.releases {
            // Skip versions with no compatible wheel.
            let wheel = pick_wheel(version_str, urls);
            let wheel = match wheel {
                Some(w) => w,
                None => continue,
            };

            // Fetch per-version requires_dist: PyPI stores it in the per-file
            // metadata for older packages, or the top-level `info` for the
            // latest. We use per-release metadata by hitting the version
            // endpoint only when needed; for now use the top-level info
            // (which is for the latest version) as a best-effort for ALL
            // versions (acceptable for the common case; the resolver picks one
            // version anyway).
            // vertexia: per-version requires_dist accuracy ceiling - fetching
            // /pypi/<name>/<version>/json per release would be exact but N
            // extra requests; top-level info is a best-effort acceptable for
            // v1. Upgrade path: call /pypi/<name>/<version>/json in versions()
            // to get exact deps per version.
            let deps = parse_requires_dist(&pkg.info.requires_dist);

            releases.push(EcosystemRelease {
                version: version_str.clone(),
                artifact_url: wheel.url.clone(),
                integrity: wheel.digests.sha256.clone(),
                deps,
            });
        }

        // Sort by PEP 440 version order ascending.
        releases.sort_by(|a, b| {
            let va = parse_pep440_version(&a.version);
            let vb = parse_pep440_version(&b.version);
            match (va, vb) {
                (Some(a), Some(b)) => a.cmp(&b),
                (Some(_), None) => std::cmp::Ordering::Greater,
                (None, Some(_)) => std::cmp::Ordering::Less,
                (None, None) => a.version.cmp(&b.version),
            }
        });

        Ok(releases)
    }

    fn fetch_artifact(&self, rel: &EcosystemRelease) -> Result<Vec<u8>> {
        let bytes = ecosystem::download_capped(
            &self.agent,
            &rel.artifact_url,
            MAX_WHEEL_COMPRESSED,
            &rel.artifact_url,
        )?;
        verify_sha256(&rel.artifact_url, &rel.integrity, &bytes)?;
        Ok(bytes)
    }

    fn satisfies(&self, version: &str, spec: &str) -> bool {
        satisfies(version, spec)
    }

    fn extract(&self, name: &str, bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
        extract_wheel(name, bytes)
    }

    fn cache_key(&self, name: &str, version: &str) -> String {
        // Normalize both components for filesystem safety.
        format!("{}@{}", normalize_name(name), version)
    }

    fn cache_root(&self) -> Result<PathBuf> {
        pip_cache_root()
    }

    fn ecosystem_name(&self) -> &'static str {
        "pip"
    }
}

// ---- Wheel picker ----------------------------------------------------------

/// From a list of `PypiUrl` for one version, pick the best compatible wheel.
///
/// Uses [`wheel_abi_check`] as the compatibility gate. Priority: pure-Python
/// (`any` platform) first (to prefer the lighter artifact), then any other
/// wheel that passes the ABI check (sandbox-ABI). Host-native wheels and
/// sdists are excluded; if NO wheel is compatible, returns `None` so the
/// version is silently skipped. A later version may have a compatible wheel.
fn pick_wheel<'a>(_version: &str, urls: &'a [PypiUrl]) -> Option<&'a PypiUrl> {
    // Prefer pure-Python wheels (any platform) - lighter and universally portable.
    let pure_py = urls.iter().find(|u| {
        u.packagetype == "bdist_wheel" && {
            let f = u.filename.to_ascii_lowercase();
            f.ends_with("-none-any.whl")
                || f.contains("py3-none-any")
                || f.contains("py2.py3-none-any")
        }
    });
    if let Some(w) = pure_py {
        return Some(w);
    }
    // Sandbox ABI or any other compatible wheel - use wheel_abi_check as gate.
    urls.iter()
        .find(|u| u.packagetype == "bdist_wheel" && wheel_abi_check(&u.filename).is_ok())
}

// ---- Public cache helpers --------------------------------------------------

/// `~/.cache/burn/pip`.
pub fn pip_cache_root() -> Result<PathBuf> {
    let dir = dirs::cache_dir().ok_or(CloudError::NoCacheDir)?;
    Ok(dir.join("burn").join("pip"))
}

/// Directory for an extracted `name@version` in the pip cache.
pub fn pip_cache_dir(name: &str, version: &str) -> Result<PathBuf> {
    Ok(pip_cache_root()?.join(format!("{}@{}", normalize_name(name), version)))
}

/// Write a resolved package's files into the pip cache.
pub fn store_pip(pkg: &PipPackage) -> Result<PathBuf> {
    let client = PipClient::new(DEFAULT_PYPI_BASE);
    ecosystem::store_artifact(&client, pkg)
}

/// Load a cached package's files. Returns `None` if not cached.
pub fn load_pip(name: &str, version: &str) -> Result<Option<BTreeMap<String, Vec<u8>>>> {
    let client = PipClient::new(DEFAULT_PYPI_BASE);
    ecosystem::load_artifact(&client, name, version)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PEP 440 version comparison ----------------------------------------

    #[test]
    fn pep440_satisfies_gte_lt() {
        assert!(satisfies("2.31.0", ">=2.31,<3"));
        assert!(satisfies("2.31.0", ">=2.31.0,<3.0.0"));
        assert!(!satisfies("3.0.0", ">=2.31,<3"));
        assert!(!satisfies("2.30.9", ">=2.31,<3"));
    }

    #[test]
    fn pep440_satisfies_exact_pin() {
        assert!(satisfies("1.26.4", "==1.26.4"));
        assert!(!satisfies("1.26.5", "==1.26.4"));
        assert!(!satisfies("1.26.3", "==1.26.4"));
    }

    #[test]
    fn pep440_satisfies_wildcard() {
        assert!(satisfies("2.0.0", "*"));
        assert!(satisfies("0.0.1", "*"));
    }

    #[test]
    fn pep440_satisfies_compatible_release() {
        // ~=1.4 means >=1.4, ==1.*
        assert!(satisfies("1.4", "~=1.4"));
        assert!(satisfies("1.9", "~=1.4"));
        assert!(!satisfies("2.0", "~=1.4"));
        assert!(!satisfies("1.3", "~=1.4"));
        // ~=2.2 means >=2.2, ==2.*
        assert!(satisfies("2.2", "~=2.2"));
        assert!(satisfies("2.3", "~=2.2"));
        assert!(!satisfies("3.0", "~=2.2"));
        assert!(!satisfies("2.1.9", "~=2.2"));
    }

    #[test]
    fn pep440_satisfies_compatible_release_three_parts() {
        // ~=2.2.1 means >=2.2.1, ==2.2.*
        assert!(satisfies("2.2.1", "~=2.2.1"));
        assert!(satisfies("2.2.9", "~=2.2.1"));
        assert!(!satisfies("2.3.0", "~=2.2.1"));
        assert!(!satisfies("2.2.0", "~=2.2.1"));
    }

    #[test]
    fn pep440_satisfies_wildcard_suffix() {
        assert!(satisfies("1.4.2", "==1.4.*"));
        assert!(satisfies("1.4.0", "==1.4.*"));
        assert!(!satisfies("1.5.0", "==1.4.*"));
        assert!(!satisfies("1.3.9", "==1.4.*"));
    }

    #[test]
    fn pep440_satisfies_not_equal() {
        assert!(!satisfies("1.0.0", "!=1.0.0"));
        assert!(satisfies("1.0.1", "!=1.0.0"));
    }

    #[test]
    fn pep440_satisfies_not_equal_wildcard() {
        // !=1.0.* excludes all 1.0.x
        assert!(!satisfies("1.0.0", "!=1.0.*"));
        assert!(!satisfies("1.0.99", "!=1.0.*"));
        assert!(satisfies("1.1.0", "!=1.0.*"));
        assert!(satisfies("2.0.0", "!=1.0.*"));
    }

    #[test]
    fn pep440_prerelease_ordering() {
        // Pre-releases are less than the final release.
        assert!(satisfies("2.0a1", ">=2.0a1"));
        assert!(!satisfies("1.9", ">=2.0a1,<2.0")); // 1.9 < 2.0a1? no: 1.9 < 2.0a1 is false
        // 2.0a1 < 2.0 final
        assert!(satisfies("2.0", ">=2.0"));
        // A pre-release does not satisfy a specifier that only covers finals.
        // (PEP 440: pre-releases excluded unless the specifier contains a pre-release)
        // Our impl is conservative: if the specifier says >=2.0, then 2.0a1 satisfies >=2.0?
        // PEP 440 says: yes, 2.0a1 >= 2.0 is FALSE (a1 < final).
        assert!(!satisfies("2.0a1", ">=2.0"));
    }

    #[test]
    fn pep440_dev_release_ordering() {
        // 1.0.dev1 < 1.0
        assert!(!satisfies("1.0.dev1", ">=1.0"));
        assert!(satisfies("1.0.dev1", ">=1.0.dev0"));
    }

    #[test]
    fn pep440_post_release() {
        // 1.0.post1 > 1.0
        assert!(satisfies("1.0.post1", ">=1.0"));
        assert!(satisfies("1.0.post1", ">1.0"));
        assert!(!satisfies("1.0.post1", "<1.0"));
    }

    #[test]
    fn pep440_epoch() {
        // 1!1.0 > 2.0 (epoch wins)
        assert!(satisfies("1!1.0", ">=2.0"));
        assert!(!satisfies("2.0", ">=1!1.0"));
    }

    // ---- Edge cases --------------------------------------------------------

    #[test]
    fn satisfies_unparseable_version_returns_false() {
        assert!(!satisfies("not-a-version", ">=1.0"));
    }

    #[test]
    fn satisfies_unparseable_spec_returns_false() {
        // parse_pip_specifier rejects bare version strings without operators.
        assert!(!satisfies("1.0.0", "2.31"));
    }

    // ---- Wheel ABI check ---------------------------------------------------

    #[test]
    fn pure_python_wheel_accepted() {
        assert!(wheel_abi_check("requests-2.31.0-py3-none-any.whl").is_ok());
        assert!(wheel_abi_check("six-1.16.0-py2.py3-none-any.whl").is_ok());
    }

    #[test]
    fn wasm_emscripten_wheel_accepted() {
        assert!(wheel_abi_check("numpy-1.26.4-cp311-cp311-wasm32_emscripten.whl").is_ok());
    }

    #[test]
    fn manylinux_wheel_refused() {
        let err = wheel_abi_check("cryptography-41.0.0-cp311-cp311-manylinux_2_28_x86_64.whl")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("manylinux") || msg.contains("Linux"),
            "expected refusal message, got: {msg}"
        );
    }

    #[test]
    fn macos_wheel_refused() {
        let err =
            wheel_abi_check("cryptography-41.0.0-cp311-cp311-macosx_10_9_x86_64.whl").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("macOS") || msg.contains("macosx"),
            "expected refusal message, got: {msg}"
        );
    }

    #[test]
    fn windows_wheel_refused() {
        let err = wheel_abi_check("cryptography-41.0.0-cp311-cp311-win_amd64.whl").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Windows") || msg.contains("win"),
            "expected refusal message, got: {msg}"
        );
    }

    #[test]
    fn sdist_refused() {
        let err = wheel_abi_check("requests-2.31.0.tar.gz").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("source distribution"),
            "expected sdist refusal, got: {msg}"
        );
    }

    // ---- Name normalisation ------------------------------------------------

    #[test]
    fn name_normalisation() {
        assert_eq!(normalize_name("Requests"), "requests");
        assert_eq!(normalize_name("my_package"), "my-package");
        assert_eq!(normalize_name("my.package"), "my-package");
        assert_eq!(normalize_name("my--package"), "my-package");
        assert_eq!(normalize_name("Pillow"), "pillow");
    }

    // ---- Resolve closure via mock server -----------------------------------

    #[test]
    fn resolve_closure_with_transitive_dep() {
        use httpmock::prelude::*;
        use std::io::Cursor;
        use std::io::Write;

        let server = MockServer::start();

        // Build a minimal pure-Python wheel (zip archive).
        let make_wheel = |name: &str, version: &str, py_files: &[(&str, &[u8])]| -> Vec<u8> {
            let mut buf = Cursor::new(Vec::new());
            {
                let mut zip = zip::ZipWriter::new(&mut buf);
                let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
                for (path, data) in py_files {
                    zip.start_file(*path, opts).unwrap();
                    zip.write_all(data).unwrap();
                }
                let dist_info = format!("{name}-{version}.dist-info/WHEEL");
                zip.start_file(&dist_info, opts).unwrap();
                zip.write_all(b"Wheel-Version: 1.0\n").unwrap();
                zip.finish().unwrap();
            }
            buf.into_inner()
        };

        // dep 1.2.0 (leaf, no deps).
        let dep_wheel = make_wheel("dep", "1.2.0", &[("dep/__init__.py", b"DEP = 7")]);
        let dep_sha = hex_lower(Sha256::digest(&dep_wheel).as_slice());

        // widget 2.0.1, depends on dep >=1.0.
        let widget_wheel = make_wheel(
            "widget",
            "2.0.1",
            &[("widget/__init__.py", b"from dep import DEP")],
        );
        let widget_sha = hex_lower(Sha256::digest(&widget_wheel).as_slice());

        let dep_url = server.url("/files/dep-1.2.0-py3-none-any.whl");
        let widget_url = server.url("/files/widget-2.0.1-py3-none-any.whl");

        // PyPI JSON for dep.
        server.mock(|when, then| {
            when.method(GET).path("/pypi/dep/json");
            then.status(200).json_body(serde_json::json!({
                "info": { "name": "dep", "version": "1.2.0", "requires_dist": [] },
                "releases": {
                    "1.2.0": [{
                        "filename": "dep-1.2.0-py3-none-any.whl",
                        "url": dep_url,
                        "digests": { "sha256": dep_sha },
                        "packagetype": "bdist_wheel"
                    }]
                }
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/files/dep-1.2.0-py3-none-any.whl");
            then.status(200).body(dep_wheel.clone());
        });

        // PyPI JSON for widget (requires dep >=1.0).
        server.mock(|when, then| {
            when.method(GET).path("/pypi/widget/json");
            then.status(200).json_body(serde_json::json!({
                "info": {
                    "name": "widget", "version": "2.0.1",
                    "requires_dist": ["dep (>=1.0)"]
                },
                "releases": {
                    "1.5.0": [{
                        "filename": "widget-1.5.0-py3-none-any.whl",
                        "url": "http://unused",
                        "digests": { "sha256": "00" },
                        "packagetype": "bdist_wheel"
                    }],
                    "2.0.1": [{
                        "filename": "widget-2.0.1-py3-none-any.whl",
                        "url": widget_url,
                        "digests": { "sha256": widget_sha },
                        "packagetype": "bdist_wheel"
                    }]
                }
            }));
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/files/widget-2.0.1-py3-none-any.whl");
            then.status(200).body(widget_wheel.clone());
        });

        let client = PipClient::new(server.base_url());
        let mut roots = BTreeMap::new();
        roots.insert("widget".to_string(), ">=2.0.0".to_string());
        let res = client.resolve_all(&roots).expect("resolve");

        let widget = res.by_name("widget").expect("widget resolved");
        assert_eq!(widget.version, "2.0.1");
        assert!(
            widget.files.contains_key("widget/__init__.py"),
            "wheel extracted"
        );

        let dep = res.by_name("dep").expect("transitive dep resolved");
        assert_eq!(dep.version, "1.2.0");
    }

    #[test]
    fn corrupt_wheel_fails_sha256_check() {
        use httpmock::prelude::*;
        use std::io::Cursor;
        use std::io::Write;

        let server = MockServer::start();

        let make_wheel_bytes = || -> Vec<u8> {
            let mut buf = Cursor::new(Vec::new());
            let mut zip = zip::ZipWriter::new(&mut buf);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
            zip.start_file("x/__init__.py", opts).unwrap();
            zip.write_all(b"x=1").unwrap();
            zip.finish().unwrap();
            buf.into_inner()
        };

        let real_wheel = make_wheel_bytes();
        let real_sha = hex_lower(Sha256::digest(&real_wheel).as_slice());
        // Serve different bytes than the advertised sha: raw bytes that differ.
        let tampered_wheel = b"TAMPERED_NOT_A_REAL_WHEEL".to_vec();

        let url = server.url("/files/evil-1.0.0-py3-none-any.whl");
        server.mock(|when, then| {
            when.method(GET).path("/pypi/evil/json");
            then.status(200).json_body(serde_json::json!({
                "info": { "name": "evil", "version": "1.0.0", "requires_dist": [] },
                "releases": {
                    "1.0.0": [{
                        "filename": "evil-1.0.0-py3-none-any.whl",
                        "url": url,
                        "digests": { "sha256": real_sha },
                        "packagetype": "bdist_wheel"
                    }]
                }
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/files/evil-1.0.0-py3-none-any.whl");
            then.status(200).body(tampered_wheel);
        });

        let client = PipClient::new(server.base_url());
        let mut roots = BTreeMap::new();
        roots.insert("evil".to_string(), "*".to_string());
        let err = client.resolve_all(&roots).unwrap_err();
        assert!(
            matches!(err, CloudError::DigestMismatch { .. }),
            "tampered wheel must fail sha256: {err}"
        );
    }

    #[test]
    fn host_native_wheel_is_refused() {
        use httpmock::prelude::*;

        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(GET).path("/pypi/bcrypt/json");
            then.status(200).json_body(serde_json::json!({
                "info": { "name": "bcrypt", "version": "4.0.0", "requires_dist": [] },
                "releases": {
                    // Only a manylinux wheel - no pure-Python, no emscripten.
                    "4.0.0": [{
                        "filename": "bcrypt-4.0.0-cp311-cp311-manylinux_2_28_x86_64.whl",
                        "url": "http://unused",
                        "digests": { "sha256": "00" },
                        "packagetype": "bdist_wheel"
                    }]
                }
            }));
        });

        let client = PipClient::new(server.base_url());
        let mut roots = BTreeMap::new();
        roots.insert("bcrypt".to_string(), "*".to_string());
        // The version is skipped (no compatible wheel), so resolve fails with
        // "no version satisfies".
        let err = client.resolve_all(&roots).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("no version satisfies") || msg.contains("not found"),
            "host-native-only package must fail with clear error: {msg}"
        );
    }

    #[test]
    fn missing_package_is_a_clear_error() {
        use httpmock::prelude::*;

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/pypi/nope/json");
            then.status(404).body("Not Found");
        });

        let client = PipClient::new(server.base_url());
        let mut roots = BTreeMap::new();
        roots.insert("nope".to_string(), "*".to_string());
        let err = client.resolve_all(&roots).unwrap_err();
        assert!(
            format!("{err}").contains("not found"),
            "missing package must report not found: {err}"
        );
    }
}
