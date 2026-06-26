// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Typed errors for the registry client. Each HTTP failure maps to a precise
//! variant so the CLI can print an actionable message (e.g. 401 → "run
//! `burn login`", 409 → "version already exists").

use thiserror::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, CloudError>;

#[derive(Debug, Error)]
pub enum CloudError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Transport-level failure (DNS, connect, TLS, timeout) - no HTTP status.
    #[error("could not reach the registry: {0}")]
    Transport(String),

    /// 401 - no/invalid token.
    #[error("authentication failed: run `burn login` (or pass --token / set BURN_REGISTRY_TOKEN)")]
    Unauthorized,

    /// 403 - authenticated but not the owner/admin.
    #[error("you are not an owner of this package (or not an admin)")]
    Forbidden,

    /// 404.
    #[error("not found on the registry")]
    NotFound,

    /// 409 - immutable-version conflict on publish.
    #[error("conflict: {0}")]
    Conflict(String),

    /// 400.
    #[error("the registry rejected the request: {0}")]
    BadRequest(String),

    /// Any other non-2xx status.
    #[error("registry returned HTTP {code}: {message}")]
    Status { code: u16, message: String },

    /// Response body did not match the expected JSON shape.
    #[error("could not decode the registry response: {0}")]
    Decode(String),

    /// No credentials are configured for the active registry.
    #[error("not logged in: run `burn login` first")]
    NotLoggedIn,

    /// `--registry NAME` referenced a registry not present in the credentials file.
    #[error(
        "unknown registry {0:?}: add it under [registries.{0}] in the credentials file or `burn login --registry {0}`"
    )]
    UnknownRegistry(String),

    #[error("could not locate a config directory for the credentials file")]
    NoConfigDir,

    #[error("could not locate a cache directory for downloaded packages")]
    NoCacheDir,

    #[error("credentials file error: {0}")]
    Config(String),

    /// Downloaded bytes did not hash to the digest the registry advertised.
    #[error("integrity check failed: expected sha256:{expected}, got sha256:{got}")]
    DigestMismatch { expected: String, got: String },

    #[error("downloaded archive exceeds the 32 MiB package limit")]
    TooLarge,

    #[error(transparent)]
    Afb(#[from] afterburner_afb::error::AfbError),

    #[error("invalid package coordinate: {0}")]
    BadCoord(String),

    /// Dependency resolution failed (version conflict, dependency cycle, …).
    #[error("dependency resolution failed: {0}")]
    Resolve(String),

    #[error("local package error: {0}")]
    Package(String),

    #[error("cache error: {0}")]
    Cache(String),
}

impl CloudError {
    /// Map an HTTP status + (best-effort) server message to a variant.
    pub fn from_status(code: u16, message: String) -> Self {
        match code {
            400 => CloudError::BadRequest(message),
            401 => CloudError::Unauthorized,
            403 => CloudError::Forbidden,
            404 => CloudError::NotFound,
            409 => CloudError::Conflict(if message.is_empty() {
                "this version already exists with different bytes (versions are immutable)".into()
            } else {
                message
            }),
            _ => CloudError::Status { code, message },
        }
    }
}
