// SPDX-License-Identifier: Apache-2.0
//! Version-specifier parsers for `[pip]` (PEP 440) and `[gem]` (RubyGems).
//!
//! Neither ecosystem uses semver, so the `semver` crate is not used here:
//! - PEP 440 has epochs (`1!2.0`), pre/post/dev labels, the `~=` compatible
//!   operator, and the arbitrary `===` operator.
//! - RubyGems has the pessimistic `~>` operator and comma-joined requirements.
//!
//! ## Scope for Phase PA
//!
//! This phase parses and validates specifiers at manifest-read time (the same
//! point `[npm]` semver ranges are validated). No resolve or network. The
//! parsed types carry enough information for the resolver in Phase PB to compare
//! a candidate version against the specifier; the comparison logic is NOT
//! implemented here (it belongs in the resolver client, alongside the actual
//! version strings from the registry).
//!
//! ## Non-registry refusal
//!
//! Both parsers refuse non-registry forms (git/URL/path/sdist) with an
//! actionable [`AfbError::ManifestParse`] message, mirroring `[npm]`'s flat
//! refusal of non-registry forms.

use crate::error::{AfbError, Result};

// ============================================================================
// PEP 440 specifier parser
// ============================================================================

/// A single PEP 440 version comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pep440Op {
    /// `~=` - compatible release (e.g. `~=2.2` means `>= 2.2, == 2.*`)
    Compatible,
    /// `==` - version matching (supports trailing `.*` wildcard)
    Equal,
    /// `!=` - version exclusion (supports trailing `.*` wildcard)
    NotEqual,
    /// `<=` - inclusive ordered comparison
    Lte,
    /// `>=` - inclusive ordered comparison
    Gte,
    /// `<` - exclusive ordered comparison
    Lt,
    /// `>` - exclusive ordered comparison
    Gt,
    /// `===` - arbitrary equality (string equality, never recommended)
    ArbitraryEqual,
}

/// One `op version` clause within a PEP 440 specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pep440Clause {
    pub op: Pep440Op,
    /// The version string as written (e.g. `"2.31"`, `"1.26.4"`, `"1.4.0a1"`).
    /// May end with `".*"` for `==` and `!=` operators.
    pub version: String,
}

/// A parsed PEP 440 version specifier, which is a comma-joined conjunction of
/// clauses (e.g. `">=2.31,<3"` -> two [`Pep440Clause`]s).
///
/// The wildcard `"*"` is represented as a single `==` clause with version
/// `"*"`, which matches any version. This is not the same as the `.*` suffix
/// form (e.g. `== 1.4.*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pep440Specifier {
    pub clauses: Vec<Pep440Clause>,
}

impl Pep440Specifier {
    /// Returns `true` if the specifier is the unconstrained wildcard `"*"`.
    pub fn is_any(&self) -> bool {
        matches!(
            self.clauses.as_slice(),
            [Pep440Clause { op: Pep440Op::Equal, version }] if version == "*"
        )
    }
}

/// Refuse non-registry pip specifier forms before the operator parse.
///
/// PEP 508 extras and environment markers are not supported in Phase PA
/// (only the core specifier grammar is); they are refused with an honest
/// error, not silently ignored.
fn refuse_pip_non_registry(s: &str) -> Result<()> {
    let lower = s.trim().to_lowercase();
    // git+https://, git+ssh://, git+git://
    if lower.starts_with("git+") {
        return Err(AfbError::ManifestParse(format!(
            "[pip] value {s:?}: git requirements are not supported in v1; \
             use a registry specifier (e.g. \">=2.31,<3\")"
        )));
    }
    // Direct URL: http://, https://, ftp://
    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
    {
        return Err(AfbError::ManifestParse(format!(
            "[pip] value {s:?}: URL requirements are not supported in v1; \
             use a registry specifier (e.g. \">=2.31,<3\")"
        )));
    }
    // Editable: -e ...
    if lower.starts_with("-e ") || lower == "-e" {
        return Err(AfbError::ManifestParse(format!(
            "[pip] value {s:?}: editable requirements (-e) are not supported; \
             use a registry specifier"
        )));
    }
    // Local path: starts with . or / or a Windows drive letter
    if lower.starts_with("./")
        || lower.starts_with("../")
        || lower.starts_with('/')
        || (lower.len() >= 2 && lower.as_bytes()[1] == b':')
    {
        return Err(AfbError::ManifestParse(format!(
            "[pip] value {s:?}: local path requirements are not supported in v1; \
             use a registry specifier"
        )));
    }
    // .tar.gz / .zip / .whl direct sdist/wheel URL
    if lower.ends_with(".tar.gz")
        || lower.ends_with(".zip")
        || lower.ends_with(".whl")
        || lower.ends_with(".tar.bz2")
    {
        return Err(AfbError::ManifestParse(format!(
            "[pip] value {s:?}: sdist/wheel file paths are not supported in v1; \
             use a registry specifier"
        )));
    }
    // PEP 508 environment markers (`;` separator)
    if s.contains(';') {
        return Err(AfbError::ManifestParse(format!(
            "[pip] value {s:?}: environment markers are not supported in v1; \
             remove the marker or split into separate entries"
        )));
    }
    // PEP 508 extras ([extra,...])
    if s.contains('[') {
        return Err(AfbError::ManifestParse(format!(
            "[pip] value {s:?}: extras ([extra]) are not supported in v1; \
             declare the base package name and specifier only"
        )));
    }
    Ok(())
}

/// Parse a PEP 440 version string (the part after the operator) lightly,
/// just enough to reject clearly malformed inputs and store for the resolver.
///
/// Accepts: digits, `.`, letters (for pre/post/dev labels), `!` (epoch
/// separator), `+` (local segment), `*` (as the whole string or a `.*` suffix
/// on `==`/`!=`). Rejects obvious garbage.
fn validate_pep440_version(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(AfbError::ManifestParse(
            "PEP 440 version string is empty".to_string(),
        ));
    }
    // Allow: digits, '.', '-', letters (a-zA-Z), '!', '+', '_', '*'
    // '*' is only meaningful as a standalone or trailing '.*'; the clause
    // parser already enforces that structurally.
    if s.bytes().any(|b| {
        !matches!(b, b'0'..=b'9' | b'.' | b'-' | b'a'..=b'z' | b'A'..=b'Z' | b'!' | b'+' | b'_' | b'*')
    }) {
        return Err(AfbError::ManifestParse(format!(
            "PEP 440 version {s:?} contains an unexpected character"
        )));
    }
    Ok(())
}

/// Parse one `op version` clause from a trimmed string slice.
fn parse_pep440_clause(s: &str) -> Result<Pep440Clause> {
    let s = s.trim();
    // Match the longest operator first to avoid `>=` being parsed as `>`.
    let (op, rest) = if let Some(r) = s.strip_prefix("===") {
        (Pep440Op::ArbitraryEqual, r)
    } else if let Some(r) = s.strip_prefix("~=") {
        (Pep440Op::Compatible, r)
    } else if let Some(r) = s.strip_prefix("==") {
        (Pep440Op::Equal, r)
    } else if let Some(r) = s.strip_prefix("!=") {
        (Pep440Op::NotEqual, r)
    } else if let Some(r) = s.strip_prefix("<=") {
        (Pep440Op::Lte, r)
    } else if let Some(r) = s.strip_prefix(">=") {
        (Pep440Op::Gte, r)
    } else if let Some(r) = s.strip_prefix('<') {
        (Pep440Op::Lt, r)
    } else if let Some(r) = s.strip_prefix('>') {
        (Pep440Op::Gt, r)
    } else {
        return Err(AfbError::ManifestParse(format!(
            "PEP 440 clause {s:?}: expected an operator \
             (~=, ==, !=, <=, >=, <, >, ===)"
        )));
    };
    let version = rest.trim();

    // Structural constraints on the `.*` wildcard suffix.
    if version.ends_with(".*") {
        if !matches!(op, Pep440Op::Equal | Pep440Op::NotEqual) {
            return Err(AfbError::ManifestParse(format!(
                "PEP 440 clause {s:?}: the `.*` suffix is only valid with `==` and `!=`"
            )));
        }
        let base = version.trim_end_matches(".*");
        validate_pep440_version(base)?;
    } else if version == "*" {
        // Bare `*` is only valid with `==`.
        if op != Pep440Op::Equal {
            return Err(AfbError::ManifestParse(format!(
                "PEP 440 clause {s:?}: bare `*` is only valid as `== *` (any version)"
            )));
        }
    } else {
        validate_pep440_version(version)?;
    }

    // `~=` requires at least two dot-separated components in the version.
    if op == Pep440Op::Compatible && !version.contains('.') {
        return Err(AfbError::ManifestParse(format!(
            "PEP 440 clause {s:?}: `~=` requires a version with at least two components \
             (e.g. `~=2.2`, not `~=2`)"
        )));
    }

    Ok(Pep440Clause {
        op,
        version: version.to_string(),
    })
}

/// Parse a PEP 440 version specifier string as it appears in the `[pip]` table.
///
/// The specifier is a comma-joined conjunction of clauses. The bare `"*"` means
/// any version (equivalent to `== *`). Non-registry forms (git URLs, local
/// paths, sdists) are refused with an actionable error.
///
/// # Errors
///
/// Returns [`AfbError::ManifestParse`] for any non-registry form, invalid
/// operator, malformed version string, or structural violation.
pub fn parse_pip_specifier(s: &str) -> Result<Pep440Specifier> {
    refuse_pip_non_registry(s)?;

    let trimmed = s.trim();

    // Bare wildcard - any version.
    if trimmed == "*" {
        return Ok(Pep440Specifier {
            clauses: vec![Pep440Clause {
                op: Pep440Op::Equal,
                version: "*".to_string(),
            }],
        });
    }

    if trimmed.is_empty() {
        return Err(AfbError::ManifestParse(
            "[pip] specifier is empty; use \"*\" for any version".to_string(),
        ));
    }

    let clauses: Result<Vec<Pep440Clause>> = trimmed
        .split(',')
        .map(|part| parse_pep440_clause(part.trim()))
        .collect();

    Ok(Pep440Specifier { clauses: clauses? })
}

// ============================================================================
// RubyGems requirement parser
// ============================================================================

/// A single RubyGems version comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemOp {
    /// `~>` - pessimistic version constraint (compatible patch/minor)
    Pessimistic,
    /// `=` - exact version
    Equal,
    /// `!=` - version exclusion
    NotEqual,
    /// `<=` - inclusive upper bound
    Lte,
    /// `>=` - inclusive lower bound
    Gte,
    /// `<` - exclusive upper bound
    Lt,
    /// `>` - exclusive lower bound
    Gt,
}

/// One `op version` clause within a RubyGems requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GemClause {
    pub op: GemOp,
    /// The version string as written (e.g. `"3.1"`, `"2.7.1"`).
    pub version: String,
}

/// A parsed RubyGems requirement, which is a comma-joined conjunction of
/// clauses (e.g. `">= 2.7, < 3"` -> two [`GemClause`]s, `"~> 3.1"` -> one).
///
/// The bare `">= 0"` form (the default Bundler wildcard) is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GemRequirement {
    pub clauses: Vec<GemClause>,
}

impl GemRequirement {
    /// Returns `true` if the requirement is the unconstrained `">= 0"` form.
    pub fn is_any(&self) -> bool {
        matches!(
            self.clauses.as_slice(),
            [GemClause { op: GemOp::Gte, version }] if version == "0"
        )
    }
}

/// Refuse non-registry gem requirement forms.
fn refuse_gem_non_registry(s: &str) -> Result<()> {
    let lower = s.trim().to_lowercase();
    // git: prefix (Bundler DSL)
    if lower.starts_with("git:") || lower.starts_with("git@") {
        return Err(AfbError::ManifestParse(format!(
            "[gem] value {s:?}: git requirements are not supported in v1; \
             use a registry requirement (e.g. \"~> 3.1\")"
        )));
    }
    // https:// or http:// direct URL
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Err(AfbError::ManifestParse(format!(
            "[gem] value {s:?}: URL requirements are not supported in v1; \
             use a registry requirement"
        )));
    }
    // Local path: starts with . or /
    if lower.starts_with("./") || lower.starts_with("../") || lower.starts_with('/') {
        return Err(AfbError::ManifestParse(format!(
            "[gem] value {s:?}: local path requirements are not supported in v1; \
             use a registry requirement"
        )));
    }
    Ok(())
}

/// Validate a RubyGems version number string lightly (digits and dots only).
fn validate_gem_version(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(AfbError::ManifestParse(
            "RubyGems version string is empty".to_string(),
        ));
    }
    // RubyGems version strings are dot-separated integer segments (may have
    // a prerelease letter suffix on the last segment, e.g. "3.0.0.pre1").
    if s.bytes()
        .any(|b| !matches!(b, b'0'..=b'9' | b'.' | b'a'..=b'z' | b'A'..=b'Z' | b'-' | b'_'))
    {
        return Err(AfbError::ManifestParse(format!(
            "RubyGems version {s:?} contains an unexpected character"
        )));
    }
    Ok(())
}

/// Parse one `op version` clause from a trimmed string slice.
fn parse_gem_clause(s: &str) -> Result<GemClause> {
    let s = s.trim();
    // Match longest operators first.
    let (op, rest) = if let Some(r) = s.strip_prefix("~>") {
        (GemOp::Pessimistic, r)
    } else if let Some(r) = s.strip_prefix("!=") {
        (GemOp::NotEqual, r)
    } else if let Some(r) = s.strip_prefix("<=") {
        (GemOp::Lte, r)
    } else if let Some(r) = s.strip_prefix(">=") {
        (GemOp::Gte, r)
    } else if let Some(r) = s.strip_prefix('=') {
        (GemOp::Equal, r)
    } else if let Some(r) = s.strip_prefix('<') {
        (GemOp::Lt, r)
    } else if let Some(r) = s.strip_prefix('>') {
        (GemOp::Gt, r)
    } else {
        return Err(AfbError::ManifestParse(format!(
            "RubyGems clause {s:?}: expected an operator (~>, =, !=, <=, >=, <, >)"
        )));
    };
    let version = rest.trim();
    validate_gem_version(version)?;

    // `~>` requires at least two dot-separated components only when the
    // version has no letters (pre-release versions like "3.0.0.pre1" are
    // accepted as-is since they carry implicit precision).
    if op == GemOp::Pessimistic
        && version.bytes().all(|b| matches!(b, b'0'..=b'9' | b'.'))
        && !version.contains('.')
    {
        return Err(AfbError::ManifestParse(format!(
            "RubyGems clause {s:?}: `~>` requires a version with at least two components \
             (e.g. `~> 3.1`, not `~> 3`)"
        )));
    }

    Ok(GemClause {
        op,
        version: version.to_string(),
    })
}

/// Parse a RubyGems requirement string as it appears in the `[gem]` table.
///
/// The requirement is a comma-joined conjunction of clauses. The conventional
/// "any version" form is `">= 0"`. Non-registry forms (git, path, URL) are
/// refused with an actionable error.
///
/// # Errors
///
/// Returns [`AfbError::ManifestParse`] for any non-registry form, invalid
/// operator, or malformed version string.
pub fn parse_gem_requirement(s: &str) -> Result<GemRequirement> {
    refuse_gem_non_registry(s)?;

    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(AfbError::ManifestParse(
            "[gem] requirement is empty; use \">= 0\" for any version".to_string(),
        ));
    }

    let clauses: Result<Vec<GemClause>> = trimmed
        .split(',')
        .map(|part| parse_gem_clause(part.trim()))
        .collect();

    Ok(GemRequirement { clauses: clauses? })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- PEP 440 happy path -------------------------------------------------

    #[test]
    fn pip_bare_wildcard() {
        let s = parse_pip_specifier("*").unwrap();
        assert!(s.is_any());
        assert_eq!(s.clauses.len(), 1);
        assert_eq!(s.clauses[0].op, Pep440Op::Equal);
        assert_eq!(s.clauses[0].version, "*");
    }

    #[test]
    fn pip_single_gte() {
        let s = parse_pip_specifier(">=2.31").unwrap();
        assert_eq!(s.clauses.len(), 1);
        assert_eq!(s.clauses[0].op, Pep440Op::Gte);
        assert_eq!(s.clauses[0].version, "2.31");
    }

    #[test]
    fn pip_conjunction() {
        let s = parse_pip_specifier(">=2.31,<3").unwrap();
        assert_eq!(s.clauses.len(), 2);
        assert_eq!(s.clauses[0].op, Pep440Op::Gte);
        assert_eq!(s.clauses[0].version, "2.31");
        assert_eq!(s.clauses[1].op, Pep440Op::Lt);
        assert_eq!(s.clauses[1].version, "3");
    }

    #[test]
    fn pip_exact_pin() {
        let s = parse_pip_specifier("==1.26.4").unwrap();
        assert_eq!(s.clauses[0].op, Pep440Op::Equal);
        assert_eq!(s.clauses[0].version, "1.26.4");
    }

    #[test]
    fn pip_compatible_release() {
        let s = parse_pip_specifier("~=1.4").unwrap();
        assert_eq!(s.clauses[0].op, Pep440Op::Compatible);
        assert_eq!(s.clauses[0].version, "1.4");
    }

    #[test]
    fn pip_wildcard_suffix_equal() {
        let s = parse_pip_specifier("== 1.4.*").unwrap();
        assert_eq!(s.clauses[0].op, Pep440Op::Equal);
        assert_eq!(s.clauses[0].version, "1.4.*");
    }

    #[test]
    fn pip_wildcard_suffix_not_equal() {
        let s = parse_pip_specifier("!= 1.4.*").unwrap();
        assert_eq!(s.clauses[0].op, Pep440Op::NotEqual);
        assert_eq!(s.clauses[0].version, "1.4.*");
    }

    #[test]
    fn pip_not_equal() {
        let s = parse_pip_specifier("!=1.0.0").unwrap();
        assert_eq!(s.clauses[0].op, Pep440Op::NotEqual);
    }

    #[test]
    fn pip_arbitrary_equal() {
        let s = parse_pip_specifier("===1.0.0+local").unwrap();
        assert_eq!(s.clauses[0].op, Pep440Op::ArbitraryEqual);
    }

    #[test]
    fn pip_pre_release_version() {
        let s = parse_pip_specifier(">=1.0a1").unwrap();
        assert_eq!(s.clauses[0].version, "1.0a1");
    }

    #[test]
    fn pip_whitespace_around_comma() {
        let s = parse_pip_specifier(" >= 2.31 , < 3 ").unwrap();
        assert_eq!(s.clauses.len(), 2);
        assert_eq!(s.clauses[0].version, "2.31");
        assert_eq!(s.clauses[1].version, "3");
    }

    // --- PEP 440 rejection paths -------------------------------------------

    #[test]
    fn pip_rejects_git_url() {
        assert!(matches!(
            parse_pip_specifier("git+https://github.com/psf/requests.git"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_http_url() {
        assert!(matches!(
            parse_pip_specifier("https://example.com/pkg.whl"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_local_path() {
        assert!(matches!(
            parse_pip_specifier("./local_pkg"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_absolute_path() {
        assert!(matches!(
            parse_pip_specifier("/usr/local/pkg"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_sdist_tarball() {
        assert!(matches!(
            parse_pip_specifier("pkg-1.0.tar.gz"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_env_marker() {
        assert!(matches!(
            parse_pip_specifier(">=2.31; python_version >= \"3.8\""),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_extras() {
        assert!(matches!(
            parse_pip_specifier("requests[security]>=2.31"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_empty() {
        assert!(matches!(
            parse_pip_specifier(""),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_no_operator() {
        assert!(matches!(
            parse_pip_specifier("2.31"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_wildcard_with_non_equal_op() {
        // `>= *` does not make sense; only `== *` is accepted as any-version.
        assert!(matches!(
            parse_pip_specifier(">= *"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_wildcard_suffix_on_gte() {
        assert!(matches!(
            parse_pip_specifier(">= 1.4.*"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn pip_rejects_compatible_release_single_component() {
        // `~=2` has no dot, which is invalid for `~=`.
        assert!(matches!(
            parse_pip_specifier("~=2"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    // --- RubyGems happy path -----------------------------------------------

    #[test]
    fn gem_pessimistic() {
        let r = parse_gem_requirement("~> 3.1").unwrap();
        assert_eq!(r.clauses.len(), 1);
        assert_eq!(r.clauses[0].op, GemOp::Pessimistic);
        assert_eq!(r.clauses[0].version, "3.1");
    }

    #[test]
    fn gem_gte() {
        let r = parse_gem_requirement(">= 2.7").unwrap();
        assert_eq!(r.clauses[0].op, GemOp::Gte);
        assert_eq!(r.clauses[0].version, "2.7");
    }

    #[test]
    fn gem_exact() {
        let r = parse_gem_requirement("= 1.4.0").unwrap();
        assert_eq!(r.clauses[0].op, GemOp::Equal);
        assert_eq!(r.clauses[0].version, "1.4.0");
    }

    #[test]
    fn gem_any_version_convention() {
        let r = parse_gem_requirement(">= 0").unwrap();
        assert!(r.is_any());
    }

    #[test]
    fn gem_conjunction() {
        let r = parse_gem_requirement(">= 2.7, < 3").unwrap();
        assert_eq!(r.clauses.len(), 2);
        assert_eq!(r.clauses[0].op, GemOp::Gte);
        assert_eq!(r.clauses[0].version, "2.7");
        assert_eq!(r.clauses[1].op, GemOp::Lt);
        assert_eq!(r.clauses[1].version, "3");
    }

    #[test]
    fn gem_not_equal() {
        let r = parse_gem_requirement("!= 1.0.0").unwrap();
        assert_eq!(r.clauses[0].op, GemOp::NotEqual);
    }

    #[test]
    fn gem_pessimistic_three_parts() {
        let r = parse_gem_requirement("~> 2.7.1").unwrap();
        assert_eq!(r.clauses[0].op, GemOp::Pessimistic);
        assert_eq!(r.clauses[0].version, "2.7.1");
    }

    #[test]
    fn gem_whitespace_tolerance() {
        let r = parse_gem_requirement("  ~>  3.1  ").unwrap();
        assert_eq!(r.clauses[0].version, "3.1");
    }

    // --- RubyGems rejection paths ------------------------------------------

    #[test]
    fn gem_rejects_git_url() {
        assert!(matches!(
            parse_gem_requirement("git:https://github.com/sinatra/sinatra.git"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn gem_rejects_http_url() {
        assert!(matches!(
            parse_gem_requirement("https://example.com/pkg.gem"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn gem_rejects_local_path() {
        assert!(matches!(
            parse_gem_requirement("./local_gem"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn gem_rejects_empty() {
        assert!(matches!(
            parse_gem_requirement(""),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn gem_rejects_no_operator() {
        assert!(matches!(
            parse_gem_requirement("3.1"),
            Err(AfbError::ManifestParse(_))
        ));
    }

    #[test]
    fn gem_rejects_pessimistic_single_component() {
        // `~> 3` has no dot, invalid for `~>`.
        assert!(matches!(
            parse_gem_requirement("~> 3"),
            Err(AfbError::ManifestParse(_))
        ));
    }
}
