// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Typed mirrors of the registry's `/api/v1` JSON responses.
//!
//! Fields are `#[serde(default)]` wherever the server may add or omit them, so
//! a newer registry never breaks an older `burn` (the same additive contract
//! the `.afb` format itself follows).

use serde::Deserialize;

/// `POST /api/v1/login`.
#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub username: String,
    #[serde(default)]
    pub is_admin: bool,
}

/// `GET /api/v1/me`.
#[derive(Debug, Clone, Deserialize)]
pub struct Me {
    pub username: String,
    #[serde(default)]
    pub is_admin: bool,
}

/// `POST /api/v1/publish`.
#[derive(Debug, Clone, Deserialize)]
pub struct PublishResponse {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub digest: String,
    #[serde(default)]
    pub size_bytes: u64,
}

/// `POST …/{ver}/yank`.
#[derive(Debug, Clone, Deserialize)]
pub struct YankResponse {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub yanked: bool,
}

/// `GET /api/v1/packages?q=`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SearchResults {
    #[serde(default)]
    pub count: usize,
    #[serde(default)]
    pub packages: Vec<PackageSummary>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackageSummary {
    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub latest: Option<String>,
}

/// `GET /api/v1/packages/{ns}/{name}`.
#[derive(Debug, Clone, Deserialize)]
pub struct PackageMeta {
    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub latest: Option<String>,
    #[serde(default)]
    pub versions: Vec<VersionSummary>,
}

impl PackageMeta {
    /// The digest the registry advertises for `version` (used to verify a
    /// download), if that version is present.
    pub fn digest_for(&self, version: &str) -> Option<&str> {
        self.versions
            .iter()
            .find(|v| v.version == version)
            .map(|v| v.digest.as_str())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionSummary {
    pub version: String,
    pub digest: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub runtime_min: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
}

/// `GET /api/v1/packages/{ns}/{name}/{ver}`.
#[derive(Debug, Clone, Deserialize)]
pub struct VersionMeta {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub digest: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub runtime_min: Option<String>,
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub downloads: u64,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub published_by: Option<String>,
    /// The serialized [`afterburner_core::Manifold`]; kept as raw JSON so a
    /// future manifold field never breaks `burn info`.
    #[serde(default)]
    pub manifold: serde_json::Value,
    /// Human-readable capability summary computed server-side.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Digest-pinned dependency map (`"ns/name" -> "sha256:…"`).
    #[serde(default)]
    pub dependencies: serde_json::Value,
    #[serde(default)]
    pub download: Option<String>,
}
