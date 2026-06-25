// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Native-manifest interop for `[pip]` and `[gem]` (design section 13.5).
//!
//! When `[pip]` is absent in `afb.toml`, `burn install` reads
//! `requirements.txt` or `pyproject.toml [project].dependencies` (PEP 621) as
//! the source of truth for pip dependencies and populates `[pip]` from them.
//!
//! When `[gem]` is absent in `afb.toml`, `burn install` reads the `Gemfile` (or
//! uses `Gemfile.lock` for the resolved pins) as the source of truth for gem
//! dependencies.
//!
//! **Canonical source rule (E3):** `[pip]`/`[gem]` in `afb.toml` are the
//! declared source when present. If a native manifest is ALSO present and
//! disagrees with `afb.toml`, the result is a LOUD error, never a silent
//! reconcile. The error names the first disagreeing package and tells the user
//! which file to fix.
//!
//! ## Pip source precedence
//!
//! 1. `[pip]` in `afb.toml` - canonical when present (non-empty).
//! 2. `requirements.txt` next to `afb.toml`.
//! 3. `pyproject.toml [project].dependencies` (PEP 621).
//! 4. If none of the above, `[pip]` stays empty.
//!
//! When BOTH a native source and `[pip]` are present: loud error if they
//! disagree on any package name.
//!
//! ## Gem source precedence
//!
//! 1. `[gem]` in `afb.toml` - canonical when present.
//! 2. `Gemfile` next to `afb.toml`.
//! 3. `Gemfile.lock` `GEM/specs` section (pinned versions from bundler).
//!
//! `Gemfile.lock` is used only to READ resolved pins when `[gem]` is absent; it
//! is not a replacement for the `Gemfile` specifier source. When a `Gemfile.lock`
//! is present alongside a `Gemfile`, the lock's pins are used for the packages
//! the Gemfile declares (more deterministic, mirrors bundler behaviour).

use crate::error::{CloudError, Result};
use std::collections::BTreeMap;
use std::path::Path;

// ---- public types -----------------------------------------------------------

/// The result of loading pip dependencies from all available sources.
///
/// `deps` is the merged `name -> specifier` map ready for resolution.
/// `source_name` names which file was authoritative (for user messages).
#[derive(Debug, Clone)]
pub struct PipDeps {
    /// Resolved `name -> specifier` map, PEP 503-normalised names.
    pub deps: BTreeMap<String, String>,
    /// Which source was authoritative (`"[pip] in afb.toml"`,
    /// `"requirements.txt"`, or `"pyproject.toml [project].dependencies"`).
    pub source_name: &'static str,
}

/// The result of loading gem dependencies from all available sources.
#[derive(Debug, Clone)]
pub struct GemDeps {
    /// Resolved `name -> specifier` map.
    pub deps: BTreeMap<String, String>,
    /// Which source was authoritative.
    pub source_name: &'static str,
}

// ---- public entrypoints -----------------------------------------------------

/// Load pip dependencies for a package directory.
///
/// When `afb_pip` is non-empty, it is the declared canonical source. If a
/// native manifest is found AND disagrees on any package, the error is LOUD
/// (names the first disagreement and tells the user which file to fix).
///
/// When `afb_pip` is empty, `requirements.txt` (then `pyproject.toml`) are
/// tried in order; the first one found wins.
///
/// `-r`/`-c` includes, URL requirements, and editable installs are refused
/// with an honest "unsupported in v1" error, never silently dropped.
/// `pyproject.toml` git/URL deps are refused the same way.
pub fn load_pip_deps(dir: &Path, afb_pip: &BTreeMap<String, String>) -> Result<PipDeps> {
    let req_path = dir.join("requirements.txt");
    let pyproject_path = dir.join("pyproject.toml");

    let native_req: Option<(BTreeMap<String, String>, &'static str)> = if req_path.exists() {
        let text = std::fs::read_to_string(&req_path).map_err(CloudError::Io)?;
        let parsed = parse_requirements_txt(&text)?;
        Some((parsed, "requirements.txt"))
    } else if pyproject_path.exists() {
        let text = std::fs::read_to_string(&pyproject_path).map_err(CloudError::Io)?;
        if let Some(parsed) = parse_pyproject_deps(&text)? {
            Some((parsed, "pyproject.toml [project].dependencies"))
        } else {
            None
        }
    } else {
        None
    };

    if afb_pip.is_empty() {
        // No [pip] in afb.toml - use native source if present.
        match native_req {
            Some((deps, src)) => Ok(PipDeps {
                deps,
                source_name: src,
            }),
            None => Ok(PipDeps {
                deps: BTreeMap::new(),
                source_name: "[pip] in afb.toml",
            }),
        }
    } else {
        // [pip] is present - it is canonical. Check for disagreement.
        if let Some((native, src)) = native_req {
            check_pip_disagree(afb_pip, &native, src)?;
        }
        Ok(PipDeps {
            deps: afb_pip.clone(),
            source_name: "[pip] in afb.toml",
        })
    }
}

/// Load gem dependencies for a package directory.
///
/// When `afb_gem` is non-empty, it is the declared canonical source. If a
/// `Gemfile` is ALSO present and disagrees, the error is LOUD.
///
/// When `afb_gem` is empty, `Gemfile` is tried; if a `Gemfile.lock` is also
/// present, its pinned versions are used for the packages the Gemfile declares.
pub fn load_gem_deps(dir: &Path, afb_gem: &BTreeMap<String, String>) -> Result<GemDeps> {
    let gemfile_path = dir.join("Gemfile");
    let gemfile_lock_path = dir.join("Gemfile.lock");

    // Parse Gemfile if present.
    let native_gemfile: Option<BTreeMap<String, String>> = if gemfile_path.exists() {
        let text = std::fs::read_to_string(&gemfile_path).map_err(CloudError::Io)?;
        Some(parse_gemfile(&text)?)
    } else {
        None
    };

    // Parse Gemfile.lock if present.
    let lock_pins: Option<BTreeMap<String, String>> = if gemfile_lock_path.exists() {
        let text = std::fs::read_to_string(&gemfile_lock_path).map_err(CloudError::Io)?;
        Some(parse_gemfile_lock(&text))
    } else {
        None
    };

    if afb_gem.is_empty() {
        // No [gem] in afb.toml - use native source if available.
        let Some(gemfile_deps) = native_gemfile else {
            return Ok(GemDeps {
                deps: BTreeMap::new(),
                source_name: "[gem] in afb.toml",
            });
        };
        // When a Gemfile.lock is present, use its pinned versions for the
        // packages the Gemfile declares (more deterministic).
        let deps = if let Some(pins) = lock_pins {
            // For each gem in the Gemfile, if the lock has an exact pin, use
            // `= <version>` as the specifier (reproducible). Otherwise keep the
            // Gemfile specifier.
            gemfile_deps
                .into_iter()
                .map(|(name, spec)| {
                    let pinned = pins.get(&name).map(|v| format!("= {v}")).unwrap_or(spec);
                    (name, pinned)
                })
                .collect()
        } else {
            gemfile_deps
        };
        Ok(GemDeps {
            deps,
            source_name: "Gemfile",
        })
    } else {
        // [gem] is present - check for disagreement with Gemfile.
        if let Some(native) = native_gemfile {
            check_gem_disagree(afb_gem, &native, "Gemfile")?;
        }
        Ok(GemDeps {
            deps: afb_gem.clone(),
            source_name: "[gem] in afb.toml",
        })
    }
}

// ---- requirements.txt parser ------------------------------------------------

/// Parse a `requirements.txt` file into a `name -> specifier` map.
///
/// Accepts: `name`, `name>=1.0`, `name>=1.0,<2`, `name==1.2.3`.
/// Refuses: `-r other.txt`, `-c constraints.txt`, URL requirements
/// (`pkg @ https://...`), editable installs (`-e path`), `#` comments (stripped).
/// Environment markers (`;`) are refused with an honest "unsupported" error.
fn parse_requirements_txt(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (lineno, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // Reject include/constraint flags.
        if line.starts_with("-r ") || line.starts_with("--requirement") {
            return Err(CloudError::Package(format!(
                "requirements.txt:{}: `-r` includes are not supported in v1; \
                 list all dependencies directly in requirements.txt or in \
                 [pip] in afb.toml",
                lineno + 1
            )));
        }
        if line.starts_with("-c ") || line.starts_with("--constraint") {
            return Err(CloudError::Package(format!(
                "requirements.txt:{}: `-c` constraint files are not supported in v1; \
                 pin versions directly in [pip] in afb.toml instead",
                lineno + 1
            )));
        }
        if line.starts_with("-e ") || line.starts_with("--editable") {
            return Err(CloudError::Package(format!(
                "requirements.txt:{}: editable installs (`-e`) are not supported; \
                 only registry packages are supported in v1",
                lineno + 1
            )));
        }
        // Reject URL / VCS requirements.
        if line.contains("://") {
            return Err(CloudError::Package(format!(
                "requirements.txt:{}: URL and VCS requirements are not supported in v1; \
                 only registry packages are supported",
                lineno + 1
            )));
        }
        // Reject PEP 508 direct references (`pkg @ url`).
        if line.contains(" @ ") {
            return Err(CloudError::Package(format!(
                "requirements.txt:{}: PEP 508 direct references (`@`) are not supported in v1",
                lineno + 1
            )));
        }
        // Reject environment markers.
        if line.contains(';') {
            return Err(CloudError::Package(format!(
                "requirements.txt:{}: environment markers (`;`) are not supported in v1; \
                 remove the marker or move the dependency to [pip] in afb.toml",
                lineno + 1
            )));
        }
        // Parse `name[extras]specifier` or just `name`.
        let (name, spec) = split_pip_name_spec(line);
        if name.is_empty() {
            continue;
        }
        let name = normalize_pip_name(name);
        let spec = spec.trim().to_string();
        let spec = if spec.is_empty() {
            "*".to_string()
        } else {
            spec
        };
        out.insert(name, spec);
    }
    Ok(out)
}

/// Parse `pyproject.toml [project].dependencies` (PEP 621).
///
/// Returns `None` when the file does not have a `[project].dependencies` key
/// (e.g. it is a setuptools or hatch config without PEP 621). Returns an error
/// for unsupported forms (URL/VCS deps, extras with environment markers).
fn parse_pyproject_deps(toml_text: &str) -> Result<Option<BTreeMap<String, String>>> {
    let table: toml::Table = toml::from_str(toml_text)
        .map_err(|e| CloudError::Package(format!("parsing pyproject.toml: {e}")))?;
    let project = match table.get("project").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => return Ok(None),
    };
    let deps = match project.get("dependencies").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Ok(None),
    };
    let mut out = BTreeMap::new();
    for (i, item) in deps.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            CloudError::Package(format!(
                "pyproject.toml [project].dependencies[{i}]: expected a string"
            ))
        })?;
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        // Refuse URL/VCS forms.
        if s.contains("://") || s.contains(" @ ") {
            return Err(CloudError::Package(format!(
                "pyproject.toml [project].dependencies[{i}]: URL/VCS dependencies \
                 ({s:?}) are not supported in v1; only registry specifiers are accepted"
            )));
        }
        // Refuse environment markers for now (same as requirements.txt).
        if s.contains(';') {
            return Err(CloudError::Package(format!(
                "pyproject.toml [project].dependencies[{i}]: environment markers \
                 are not supported in v1; move the dependency to [pip] in afb.toml"
            )));
        }
        let (name, spec) = split_pip_name_spec(s);
        if name.is_empty() {
            continue;
        }
        let name = normalize_pip_name(name);
        let spec = spec.trim().to_string();
        let spec = if spec.is_empty() {
            "*".to_string()
        } else {
            spec
        };
        out.insert(name, spec);
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

/// Split `name[extras]specifier` into `(name_without_extras, specifier)`.
///
/// PEP 508: extras are bracketed after the name and before the version
/// specifier. We strip them since we do not resolve extras in v1.
fn split_pip_name_spec(s: &str) -> (&str, &str) {
    // Find where the specifier starts: the first occurrence of a comparator
    // character (>, <, =, !, ~) or an extras `[`.
    let s = s.trim();
    // Strip extras: `name[extra1,extra2]specifier` -> `name` + `specifier`
    // Find the name end (first non-name char ignoring `[...]`).
    let name_end = s
        .char_indices()
        .find(|(_, c)| matches!(c, '>' | '<' | '=' | '!' | '~' | '['))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    let name = s[..name_end].trim();
    let rest = &s[name_end..];
    // Skip extras block `[...]`.
    let spec_start = if rest.starts_with('[') {
        rest.find(']').map(|i| i + 1).unwrap_or(rest.len())
    } else {
        0
    };
    let spec = rest[spec_start..].trim();
    (name, spec)
}

/// PEP 503 name normalization: lowercase, collapse `[-_.]` runs to `-`.
fn normalize_pip_name(name: &str) -> String {
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

// ---- Gemfile parser ---------------------------------------------------------

/// Parse a `Gemfile` into a `name -> requirement` map.
///
/// Accepts: `gem "name"`, `gem "name", "req"`, `gem 'name', '>= X'`.
/// Accepts: a leading `source "https://rubygems.org"` line (single default source).
/// Refuses: `group` blocks (outside the default group), `git:`/`path:` options,
/// additional `source` calls, `gemspec` declarations.
fn parse_gemfile(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut source_count = 0u32;

    for (lineno, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // Allow a single `source "https://rubygems.org"` declaration.
        if line.starts_with("source ") {
            source_count += 1;
            if source_count > 1 {
                return Err(CloudError::Package(format!(
                    "Gemfile:{}: multiple source declarations are not supported in v1; \
                     use a single `source \"https://rubygems.org\"`",
                    lineno + 1
                )));
            }
            continue;
        }
        // Refuse group blocks and git/path/gemspec.
        if line.starts_with("group ") || line.starts_with("group(") {
            return Err(CloudError::Package(format!(
                "Gemfile:{}: `group` blocks are not supported in v1; \
                 list all runtime dependencies at the top level",
                lineno + 1
            )));
        }
        if line.starts_with("gemspec") {
            return Err(CloudError::Package(format!(
                "Gemfile:{}: `gemspec` is not supported in v1; \
                 list dependencies directly in [gem] in afb.toml",
                lineno + 1
            )));
        }
        // A `gem "name"[, "req"[, options...]]` line.
        if line.starts_with("gem ") || line.starts_with("gem\t") {
            // Refuse git/path options (both `git:` keyword-arg and `:git =>` hash-rocket).
            if line.contains("git:")
                || line.contains(":git")
                || line.contains("path:")
                || line.contains(":path")
            {
                return Err(CloudError::Package(format!(
                    "Gemfile:{}: git and path dependencies are not supported in v1; \
                     only registry gems are accepted",
                    lineno + 1
                )));
            }
            let (name, req) = parse_gem_line(line).ok_or_else(|| {
                CloudError::Package(format!(
                    "Gemfile:{}: could not parse gem declaration: {raw_line:?}",
                    lineno + 1
                ))
            })?;
            out.insert(name, req);
        }
        // `ruby "version"` and other DSL keywords are silently tolerated (they
        // are not dependency declarations and are safe to skip).
    }
    Ok(out)
}

/// Parse a single `gem "name"[, "req"]` line from a Gemfile.
///
/// Returns `(name, requirement)` or `None` if the line does not parse cleanly.
fn parse_gem_line(line: &str) -> Option<(String, String)> {
    // Strip leading `gem ` keyword.
    let rest = line.trim_start_matches("gem").trim();
    // Split on comma to separate name from requirements; we want all
    // quote-delimited tokens.
    let tokens = extract_quoted_strings(rest);
    let name = tokens.first()?.clone();
    if name.is_empty() {
        return None;
    }
    // Join remaining requirement strings with `, ` (bundler accepts multi-string reqs).
    let req = tokens[1..]
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let req = if req.is_empty() { "*".to_string() } else { req };
    Some((name.to_ascii_lowercase(), req))
}

/// Extract all single- or double-quoted string literals from a Gemfile token list.
fn extract_quoted_strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            let q = c;
            let mut token = String::new();
            for inner in chars.by_ref() {
                if inner == q {
                    break;
                }
                token.push(inner);
            }
            out.push(token);
        }
    }
    out
}

// ---- Gemfile.lock parser ----------------------------------------------------

/// Parse the `GEM/specs` section of a `Gemfile.lock`.
///
/// Returns `name -> version` for the pinned gems. Version is the bare version
/// string from the lock (e.g. `"2.7.12"`), not a requirement specifier.
fn parse_gemfile_lock(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut in_specs = false;

    for line in text.lines() {
        let trimmed = line.trim();
        // Detect section headers.
        if trimmed == "GEM" {
            in_specs = false;
            continue;
        }
        if trimmed == "specs:" && line.starts_with("  specs:") {
            in_specs = true;
            continue;
        }
        // Any unindented section header ends the specs block.
        if !line.starts_with(' ') && !line.is_empty() {
            in_specs = false;
            continue;
        }
        if !in_specs {
            continue;
        }
        // Top-level spec entry (4 spaces indent): `    name (version)`.
        if line.starts_with("    ")
            && !line.starts_with("      ")
            && let Some((name, ver)) = parse_lock_spec_line(trimmed)
        {
            out.insert(name.to_ascii_lowercase(), ver);
        }
        // Deeper indented lines are sub-dependency declarations; skip them.
    }
    out
}

/// Parse `name (version)` from a Gemfile.lock spec line.
fn parse_lock_spec_line(line: &str) -> Option<(&str, String)> {
    let paren = line.find('(')?;
    let close = line.find(')')?;
    if close <= paren {
        return None;
    }
    let name = line[..paren].trim();
    let version = line[paren + 1..close].trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version.to_string()))
}

// ---- disagree-check helpers -------------------------------------------------

/// Check that `afb_pip` and `native_deps` agree on every package they share.
///
/// Two entries disagree when the SAME normalised package name appears in both
/// but with DIFFERENT specifiers. A package present in only one source is fine
/// (the canonical `[pip]` table wins; extra native entries are no-ops).
fn check_pip_disagree(
    afb_pip: &BTreeMap<String, String>,
    native_deps: &BTreeMap<String, String>,
    native_source: &str,
) -> Result<()> {
    for (name, native_spec) in native_deps {
        if let Some(afb_spec) = afb_pip.get(name)
            && afb_spec != native_spec
        {
            return Err(CloudError::Package(format!(
                "afb.toml [pip] and {native_source} disagree on `{name}`: \
                 afb.toml says {afb_spec:?}, {native_source} says {native_spec:?}. \
                 Fix one of the two files, or delete {native_source} and use \
                 [pip] in afb.toml as the sole source of truth."
            )));
        }
    }
    Ok(())
}

/// Check that `afb_gem` and `native_deps` agree on every package they share.
fn check_gem_disagree(
    afb_gem: &BTreeMap<String, String>,
    native_deps: &BTreeMap<String, String>,
    native_source: &str,
) -> Result<()> {
    for (name, native_spec) in native_deps {
        if let Some(afb_spec) = afb_gem.get(name)
            && afb_spec != native_spec
        {
            return Err(CloudError::Package(format!(
                "afb.toml [gem] and {native_source} disagree on `{name}`: \
                 afb.toml says {afb_spec:?}, {native_source} says {native_spec:?}. \
                 Fix one of the two files, or delete {native_source} and use \
                 [gem] in afb.toml as the sole source of truth."
            )));
        }
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ---- requirements.txt parser -------------------------------------------

    #[test]
    fn parse_requirements_txt_basic() {
        let text = "requests>=2.31,<3\nnumpy==1.26.4\nrich\n";
        let deps = parse_requirements_txt(text).unwrap();
        assert_eq!(deps.get("requests").map(String::as_str), Some(">=2.31,<3"));
        assert_eq!(deps.get("numpy").map(String::as_str), Some("==1.26.4"));
        assert_eq!(deps.get("rich").map(String::as_str), Some("*"));
    }

    #[test]
    fn parse_requirements_txt_strips_comments() {
        let text = "# top-level comment\nrequests>=2.31  # inline\n";
        let deps = parse_requirements_txt(text).unwrap();
        assert_eq!(deps.get("requests").map(String::as_str), Some(">=2.31"));
    }

    #[test]
    fn parse_requirements_txt_strips_extras() {
        // `requests[security]>=2.31` - extras are stripped, specifier kept.
        let text = "requests[security]>=2.31\n";
        let deps = parse_requirements_txt(text).unwrap();
        // After extras strip: name="requests", spec=">=2.31"
        assert_eq!(deps.get("requests").map(String::as_str), Some(">=2.31"));
    }

    #[test]
    fn parse_requirements_txt_normalises_name() {
        let text = "Pillow>=10.0\nmy_package>=1.0\n";
        let deps = parse_requirements_txt(text).unwrap();
        assert!(
            deps.contains_key("pillow"),
            "Pillow must be normalised to pillow"
        );
        assert!(
            deps.contains_key("my-package"),
            "my_package must be normalised to my-package"
        );
    }

    #[test]
    fn parse_requirements_txt_refuses_include() {
        let err = parse_requirements_txt("-r base.txt\n").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("-r") || msg.contains("includes"),
            "must mention -r: {msg}"
        );
    }

    #[test]
    fn parse_requirements_txt_refuses_constraint() {
        let err = parse_requirements_txt("-c constraints.txt\n").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("-c") || msg.contains("constraint"), "{msg}");
    }

    #[test]
    fn parse_requirements_txt_refuses_editable() {
        let err = parse_requirements_txt("-e ./mylib\n").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("-e") || msg.contains("editable"), "{msg}");
    }

    #[test]
    fn parse_requirements_txt_refuses_url() {
        let err = parse_requirements_txt("git+https://github.com/x/y.git\n").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("URL") || msg.contains("VCS") || msg.contains("://"),
            "{msg}"
        );
    }

    #[test]
    fn parse_requirements_txt_refuses_env_marker() {
        let err =
            parse_requirements_txt("requests>=2.31; python_version >= \"3.8\"\n").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("marker") || msg.contains(";"), "{msg}");
    }

    // ---- pyproject.toml parser ---------------------------------------------

    #[test]
    fn parse_pyproject_deps_basic() {
        let text = r#"
[project]
name = "myapp"
dependencies = [
  "requests>=2.31,<3",
  "rich",
]
"#;
        let deps = parse_pyproject_deps(text).unwrap().unwrap();
        assert_eq!(deps.get("requests").map(String::as_str), Some(">=2.31,<3"));
        assert_eq!(deps.get("rich").map(String::as_str), Some("*"));
    }

    #[test]
    fn parse_pyproject_no_project_section_returns_none() {
        let text = "[tool.pytest]\naddopts = \"-v\"\n";
        assert!(
            parse_pyproject_deps(text).unwrap().is_none(),
            "no [project] = no deps"
        );
    }

    #[test]
    fn parse_pyproject_no_dependencies_returns_none() {
        let text = "[project]\nname = \"x\"\nversion = \"1.0\"\n";
        assert!(
            parse_pyproject_deps(text).unwrap().is_none(),
            "no dependencies key = None"
        );
    }

    #[test]
    fn parse_pyproject_refuses_url_dep() {
        let text = r#"
[project]
dependencies = ["mypkg @ https://example.com/mypkg-1.0.whl"]
"#;
        let err = parse_pyproject_deps(text).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("URL") || msg.contains("VCS") || msg.contains("@"),
            "{msg}"
        );
    }

    #[test]
    fn parse_pyproject_refuses_env_marker() {
        let text = r#"
[project]
dependencies = ["requests>=2.0; python_version >= \"3.8\""]
"#;
        let err = parse_pyproject_deps(text).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("marker") || msg.contains(";"), "{msg}");
    }

    // ---- Gemfile parser ----------------------------------------------------

    #[test]
    fn parse_gemfile_basic() {
        let text = r#"
source "https://rubygems.org"

gem "sinatra", "~> 3.1"
gem "faraday", ">= 2.7"
gem "rack"
"#;
        let deps = parse_gemfile(text).unwrap();
        assert_eq!(deps.get("sinatra").map(String::as_str), Some("~> 3.1"));
        assert_eq!(deps.get("faraday").map(String::as_str), Some(">= 2.7"));
        assert_eq!(deps.get("rack").map(String::as_str), Some("*"));
    }

    #[test]
    fn parse_gemfile_strips_comments() {
        let text = "source \"https://rubygems.org\"\ngem \"rails\", \"~> 7.0\" # comment\n";
        let deps = parse_gemfile(text).unwrap();
        assert_eq!(deps.get("rails").map(String::as_str), Some("~> 7.0"));
    }

    #[test]
    fn parse_gemfile_refuses_group_block() {
        let text = "source \"https://rubygems.org\"\ngroup :development do\ngem \"rspec\"\nend\n";
        let err = parse_gemfile(text).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("group"), "{msg}");
    }

    #[test]
    fn parse_gemfile_refuses_git_dep() {
        let text =
            "source \"https://rubygems.org\"\ngem \"mygem\", git: \"https://github.com/x/y\"\n";
        let err = parse_gemfile(text).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("git") || msg.contains("path"), "{msg}");
    }

    #[test]
    fn parse_gemfile_refuses_multiple_sources() {
        let text =
            "source \"https://rubygems.org\"\nsource \"https://gems.example.com\"\ngem \"x\"\n";
        let err = parse_gemfile(text).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "{msg}");
    }

    // ---- Gemfile.lock parser -----------------------------------------------

    #[test]
    fn parse_gemfile_lock_basic() {
        let text = "GEM\n  remote: https://rubygems.org/\n  specs:\n    faraday (2.7.12)\n      faraday-net_http (>= 2.0, < 3.2)\n    faraday-net_http (3.1.0)\n\nBUNDLED WITH\n   2.4.0\n";
        let pins = parse_gemfile_lock(text);
        assert_eq!(pins.get("faraday").map(String::as_str), Some("2.7.12"));
        assert_eq!(
            pins.get("faraday-net_http").map(String::as_str),
            Some("3.1.0")
        );
    }

    #[test]
    fn parse_gemfile_lock_empty_input() {
        let pins = parse_gemfile_lock("");
        assert!(pins.is_empty());
    }

    // ---- load_pip_deps (integration of all sources) ------------------------

    fn write_file(dir: &Path, name: &str, content: &str) {
        fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn load_pip_from_requirements_txt_when_afb_pip_absent() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "requirements.txt", "requests>=2.31,<3\n");
        let result = load_pip_deps(tmp.path(), &BTreeMap::new()).unwrap();
        assert_eq!(result.source_name, "requirements.txt");
        assert_eq!(
            result.deps.get("requests").map(String::as_str),
            Some(">=2.31,<3")
        );
    }

    #[test]
    fn load_pip_from_pyproject_when_no_requirements_txt() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "pyproject.toml",
            "[project]\ndependencies = [\"rich>=12\"]\n",
        );
        let result = load_pip_deps(tmp.path(), &BTreeMap::new()).unwrap();
        assert_eq!(result.source_name, "pyproject.toml [project].dependencies");
        assert_eq!(result.deps.get("rich").map(String::as_str), Some(">=12"));
    }

    #[test]
    fn load_pip_afb_wins_over_requirements_txt_when_agree() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "requirements.txt", "requests>=2.31,<3\n");
        let mut afb_pip = BTreeMap::new();
        afb_pip.insert("requests".to_string(), ">=2.31,<3".to_string());
        let result = load_pip_deps(tmp.path(), &afb_pip).unwrap();
        assert_eq!(result.source_name, "[pip] in afb.toml");
    }

    #[test]
    fn load_pip_loud_on_disagree_with_requirements_txt() {
        let tmp = TempDir::new().unwrap();
        write_file(tmp.path(), "requirements.txt", "requests>=2.31,<3\n");
        let mut afb_pip = BTreeMap::new();
        // afb.toml says ==2.28.0, requirements.txt says >=2.31,<3
        afb_pip.insert("requests".to_string(), "==2.28.0".to_string());
        let err = load_pip_deps(tmp.path(), &afb_pip).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("disagree") && msg.contains("requests"),
            "must name the disagreeing package: {msg}"
        );
        assert!(
            msg.contains("afb.toml") && msg.contains("requirements.txt"),
            "must name both files: {msg}"
        );
    }

    #[test]
    fn load_pip_loud_on_disagree_with_pyproject() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "pyproject.toml",
            "[project]\ndependencies = [\"rich>=12\"]\n",
        );
        let mut afb_pip = BTreeMap::new();
        // afb.toml says ==11.0, pyproject.toml says >=12
        afb_pip.insert("rich".to_string(), "==11.0".to_string());
        let err = load_pip_deps(tmp.path(), &afb_pip).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("disagree") && msg.contains("rich"),
            "must name the disagreeing package: {msg}"
        );
        assert!(
            msg.contains("pyproject.toml"),
            "must name the native file: {msg}"
        );
    }

    // ---- load_gem_deps (integration of all sources) ------------------------

    #[test]
    fn load_gem_from_gemfile_when_afb_gem_absent() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"sinatra\", \"~> 3.1\"\n",
        );
        let result = load_gem_deps(tmp.path(), &BTreeMap::new()).unwrap();
        assert_eq!(result.source_name, "Gemfile");
        assert_eq!(
            result.deps.get("sinatra").map(String::as_str),
            Some("~> 3.1")
        );
    }

    #[test]
    fn load_gem_from_gemfile_lock_when_present() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"sinatra\", \"~> 3.1\"\n",
        );
        // Gemfile.lock pins sinatra at 3.1.0
        write_file(
            tmp.path(),
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    sinatra (3.1.0)\n\nBUNDLED WITH\n   2.4.0\n",
        );
        let result = load_gem_deps(tmp.path(), &BTreeMap::new()).unwrap();
        // Gemfile.lock pin must override the Gemfile range.
        assert_eq!(
            result.deps.get("sinatra").map(String::as_str),
            Some("= 3.1.0"),
            "Gemfile.lock pin must be honoured"
        );
    }

    #[test]
    fn load_gem_afb_wins_over_gemfile_when_agree() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"sinatra\", \"~> 3.1\"\n",
        );
        let mut afb_gem = BTreeMap::new();
        afb_gem.insert("sinatra".to_string(), "~> 3.1".to_string());
        let result = load_gem_deps(tmp.path(), &afb_gem).unwrap();
        assert_eq!(result.source_name, "[gem] in afb.toml");
    }

    #[test]
    fn load_gem_loud_on_disagree_with_gemfile() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"sinatra\", \"~> 3.1\"\n",
        );
        let mut afb_gem = BTreeMap::new();
        // afb.toml says = 2.0.0, Gemfile says ~> 3.1
        afb_gem.insert("sinatra".to_string(), "= 2.0.0".to_string());
        let err = load_gem_deps(tmp.path(), &afb_gem).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("disagree") && msg.contains("sinatra"),
            "must name the disagreeing gem: {msg}"
        );
        assert!(msg.contains("Gemfile"), "must name the native file: {msg}");
    }
}
