// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Package coordinates: `namespace/name[@version]` (the `burn` analogue of
//! cargo's `name@version`).

use crate::error::{CloudError, Result};

/// A parsed package coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coord {
    pub namespace: String,
    pub name: String,
    /// `None` means "the latest non-yanked version".
    pub version: Option<String>,
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

impl Coord {
    /// Parse `namespace/name`, optionally suffixed with `@version`.
    ///
    /// A bare `name` (no `/`) is rejected — the namespace is required for
    /// registry operations. Use [`Coord::parse_or_default_ns`] when a fallback
    /// namespace (e.g. the logged-in username) is available.
    pub fn parse(spec: &str) -> Result<Self> {
        Self::parse_or_default_ns(spec, None)
    }

    /// Like [`Coord::parse`], but a bare `name` adopts `default_ns` if provided.
    pub fn parse_or_default_ns(spec: &str, default_ns: Option<&str>) -> Result<Self> {
        let (path, version) = match spec.split_once('@') {
            Some((p, v)) => (p, Some(v.trim().to_string())),
            None => (spec, None),
        };

        let (namespace, name) = match path.split_once('/') {
            Some((ns, nm)) => (ns.trim().to_string(), nm.trim().to_string()),
            None => match default_ns {
                Some(ns) => (ns.to_string(), path.trim().to_string()),
                None => {
                    return Err(CloudError::BadCoord(format!(
                        "{spec:?} must be `namespace/name` (with optional `@version`)"
                    )));
                }
            },
        };

        if !is_ident(&namespace) || !is_ident(&name) {
            return Err(CloudError::BadCoord(format!(
                "namespace and name must be lowercase [a-z0-9-_]: got {namespace:?}/{name:?}"
            )));
        }
        if let Some(v) = &version {
            semver::Version::parse(v)
                .map_err(|e| CloudError::BadCoord(format!("version {v:?} is not semver: {e}")))?;
        }
        Ok(Coord {
            namespace,
            name,
            version,
        })
    }

    /// `namespace/name` (without any version suffix).
    pub fn qualified(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_coordinate() {
        let c = Coord::parse("burn/anthropic@0.1.0").unwrap();
        assert_eq!(c.namespace, "burn");
        assert_eq!(c.name, "anthropic");
        assert_eq!(c.version.as_deref(), Some("0.1.0"));
        assert_eq!(c.qualified(), "burn/anthropic");
    }

    #[test]
    fn parses_without_version() {
        let c = Coord::parse("burn/anthropic").unwrap();
        assert!(c.version.is_none());
    }

    #[test]
    fn bare_name_needs_a_default_namespace() {
        assert!(matches!(
            Coord::parse("anthropic"),
            Err(CloudError::BadCoord(_))
        ));
        let c = Coord::parse_or_default_ns("anthropic", Some("burn")).unwrap();
        assert_eq!(c.namespace, "burn");
        assert_eq!(c.name, "anthropic");
    }

    #[test]
    fn rejects_bad_identifiers_and_versions() {
        assert!(Coord::parse("Burn/Anthropic").is_err());
        assert!(Coord::parse("burn/anthropic@not-semver").is_err());
        assert!(Coord::parse("burn/").is_err());
    }
}
