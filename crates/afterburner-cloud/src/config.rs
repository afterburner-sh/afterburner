// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Registry selection + cargo-style credential storage.
//!
//! Tokens live in `~/.config/burn/credentials.toml` (never in the project):
//!
//! ```toml
//! [registry]
//! token = "afbpat_…"
//! username = "you"
//!
//! [registries.mycorp]
//! index = "https://registry.mycorp.example"
//! token = "afbpat_…"
//! ```
//!
//! Resolution order for the active registry + token (highest first):
//! `--registry`/`--token` flags → `BURN_REGISTRY`/`BURN_REGISTRY_TOKEN` env →
//! credentials file → the default registry `https://registry.afterburner.sh`.

use crate::error::{CloudError, Result};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Default registry when nothing else selects one.
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.afterburner.sh";
/// Env override for the default registry's base URL.
pub const ENV_REGISTRY: &str = "BURN_REGISTRY";
/// Env override for the default registry's token.
pub const ENV_TOKEN: &str = "BURN_REGISTRY_TOKEN";

/// The resolved registry the client should talk to.
///
/// Not `Clone`: the token is a [`SecretString`] (intentionally non-cloneable
/// and zeroized on drop). Move it into a [`crate::RegistryClient`].
#[derive(Debug)]
pub struct Resolved {
    pub base_url: String,
    pub token: Option<SecretString>,
    /// The username last stored for this registry (for scaffolding's default
    /// namespace), if known locally.
    pub username: Option<String>,
    /// The named registry this resolved to (`None` = the default registry).
    pub name: Option<String>,
}

// ── credentials file model ──────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
struct CredentialsFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registry: Option<RegistryEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    registries: BTreeMap<String, NamedRegistryEntry>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct RegistryEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedRegistryEntry {
    index: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

/// `~/.config/burn/credentials.toml`.
pub fn credentials_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().ok_or(CloudError::NoConfigDir)?;
    Ok(dir.join("burn").join("credentials.toml"))
}

fn load_file() -> Result<CredentialsFile> {
    let path = credentials_path()?;
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            toml::from_str(&s).map_err(|e| CloudError::Config(format!("{}: {e}", path.display())))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CredentialsFile::default()),
        Err(e) => Err(CloudError::Io(e)),
    }
}

fn save_file(f: &CredentialsFile) -> Result<PathBuf> {
    let path = credentials_path()?;
    let body = toml::to_string_pretty(f).map_err(|e| CloudError::Config(e.to_string()))?;
    write_private(&path, body.as_bytes())?;
    Ok(path)
}

/// Atomically write `bytes` to `path` with `0600` permissions (best effort on
/// non-unix). Credentials must never be world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CloudError::Config("credentials path has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("toml.tmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Resolve the active registry + token from flags, env, and the credentials file.
pub fn resolve(registry_flag: Option<&str>, token_flag: Option<&str>) -> Result<Resolved> {
    let file = load_file()?;

    if let Some(name) = registry_flag {
        let entry = file
            .registries
            .get(name)
            .ok_or_else(|| CloudError::UnknownRegistry(name.to_string()))?;
        let token = token_flag
            .map(str::to_string)
            .or_else(|| entry.token.clone());
        return Ok(Resolved {
            base_url: entry.index.trim_end_matches('/').to_string(),
            token: token.map(SecretString::from),
            username: entry.username.clone(),
            name: Some(name.to_string()),
        });
    }

    let base_url = env_nonempty(ENV_REGISTRY).unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string());
    let token = token_flag
        .map(str::to_string)
        .or_else(|| env_nonempty(ENV_TOKEN))
        .or_else(|| file.registry.as_ref().and_then(|r| r.token.clone()));
    let username = file.registry.as_ref().and_then(|r| r.username.clone());

    Ok(Resolved {
        base_url: base_url.trim_end_matches('/').to_string(),
        token: token.map(SecretString::from),
        username,
        name: None,
    })
}

/// Store a token (and the username it belongs to) for the given registry,
/// returning the path written.
pub fn store_token(
    registry_flag: Option<&str>,
    base_url: &str,
    token: &str,
    username: Option<&str>,
) -> Result<PathBuf> {
    let mut file = load_file()?;
    match registry_flag {
        Some(name) => {
            let entry =
                file.registries
                    .entry(name.to_string())
                    .or_insert_with(|| NamedRegistryEntry {
                        index: base_url.trim_end_matches('/').to_string(),
                        token: None,
                        username: None,
                    });
            entry.index = base_url.trim_end_matches('/').to_string();
            entry.token = Some(token.to_string());
            entry.username = username.map(str::to_string);
        }
        None => {
            let entry = file.registry.get_or_insert_with(RegistryEntry::default);
            entry.token = Some(token.to_string());
            entry.username = username.map(str::to_string);
        }
    }
    save_file(&file)
}

/// Remove a stored token. Returns whether a token was actually present.
pub fn remove_token(registry_flag: Option<&str>) -> Result<bool> {
    let mut file = load_file()?;
    let had = match registry_flag {
        Some(name) => match file.registries.get_mut(name) {
            Some(e) => {
                let had = e.token.take().is_some();
                e.username = None;
                had
            }
            None => false,
        },
        None => match file.registry.as_mut() {
            Some(e) => {
                let had = e.token.take().is_some();
                e.username = None;
                had
            }
            None => false,
        },
    };
    save_file(&file)?;
    Ok(had)
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}
