// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! A thin, synchronous HTTP client over the registry's `/api/v1` surface.
//!
//! One method per endpoint; every non-2xx maps to a typed [`CloudError`]. The
//! client is `ureq`-backed (sync) to match the CLI's blocking handler style —
//! there is no async runtime in `burn`'s command path.

use crate::error::{CloudError, Result};
use crate::types::*;
use secrecy::{ExposeSecret, SecretString};
use std::io::Read;
use std::time::Duration;

/// Mirror of `afterburner_afb::MAX_AFB_BYTES` — never buffer more than a valid
/// package could be (zip-bomb / hostile-server defense on download).
const MAX_DOWNLOAD_BYTES: u64 = afterburner_afb::MAX_AFB_BYTES as u64;

/// Speaks the registry HTTP API. Construct via [`RegistryClient::new`].
pub struct RegistryClient {
    agent: ureq::Agent,
    base: String,
    token: Option<SecretString>,
}

impl RegistryClient {
    /// `base_url` is the registry root (e.g. `https://registry.afterburner.sh`);
    /// `token` is the bearer token for authenticated writes, if any.
    pub fn new(base_url: impl Into<String>, token: Option<SecretString>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(120))
            .timeout_write(Duration::from_secs(120))
            .user_agent(concat!("burn/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent,
            base: base_url.into().trim_end_matches('/').to_string(),
            token,
        }
    }

    /// Build a client straight from a resolved registry, moving the token.
    pub fn from_resolved(r: crate::config::Resolved) -> Self {
        Self::new(r.base_url, r.token)
    }

    /// Construct with a plain-text bearer token (wrapped in a [`SecretString`]).
    /// Used to validate a pasted token before storing it.
    pub fn with_token(base_url: impl Into<String>, token: &str) -> Self {
        Self::new(base_url, Some(SecretString::from(token.to_string())))
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn bearer(&self) -> Result<String> {
        let t = self.token.as_ref().ok_or(CloudError::NotLoggedIn)?;
        Ok(format!("Bearer {}", t.expose_secret()))
    }

    // ── read (public) ───────────────────────────────────────────────────────

    /// `GET /api/v1/packages?q=` — full-text search.
    pub fn search(&self, q: &str) -> Result<SearchResults> {
        decode_json(
            self.agent
                .get(&self.url("/api/v1/packages"))
                .query("q", q)
                .call(),
        )
    }

    /// `GET /api/v1/packages/{ns}/{name}` — package metadata + all versions.
    pub fn get_package(&self, ns: &str, name: &str) -> Result<PackageMeta> {
        decode_json(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}")))
                .call(),
        )
    }

    /// `GET /api/v1/packages/{ns}/{name}/{ver}` — one version's metadata.
    pub fn get_version(&self, ns: &str, name: &str, ver: &str) -> Result<VersionMeta> {
        decode_json(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}/{ver}")))
                .call(),
        )
    }

    /// `GET …/{ver}/download` — stream the exact `.afb` bytes.
    pub fn download(&self, ns: &str, name: &str, ver: &str) -> Result<Vec<u8>> {
        read_body(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}/{ver}/download")))
                .call(),
        )
    }

    /// `GET …/{name}/download` — latest non-yanked version's bytes.
    pub fn download_latest(&self, ns: &str, name: &str) -> Result<Vec<u8>> {
        read_body(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}/download")))
                .call(),
        )
    }

    // ── write (bearer) ──────────────────────────────────────────────────────

    /// `POST /api/v1/login` — exchange credentials for a token. No bearer.
    pub fn login(&self, username: &str, password: &str) -> Result<LoginResponse> {
        decode_json(
            self.agent
                .post(&self.url("/api/v1/login"))
                .send_json(serde_json::json!({ "username": username, "password": password })),
        )
    }

    /// `GET /api/v1/me` — the user behind the current token.
    pub fn me(&self) -> Result<Me> {
        decode_json(
            self.agent
                .get(&self.url("/api/v1/me"))
                .set("Authorization", &self.bearer()?)
                .call(),
        )
    }

    /// `POST /api/v1/publish` — upload raw `.afb` bytes.
    pub fn publish(&self, afb_bytes: &[u8]) -> Result<PublishResponse> {
        decode_json(
            self.agent
                .post(&self.url("/api/v1/publish"))
                .set("Authorization", &self.bearer()?)
                .set("Content-Type", "application/octet-stream")
                .send_bytes(afb_bytes),
        )
    }

    /// `POST …/{ver}/yank[?undo=true]`.
    pub fn yank(&self, ns: &str, name: &str, ver: &str, undo: bool) -> Result<YankResponse> {
        let mut req = self
            .agent
            .post(&self.url(&format!("/api/v1/packages/{ns}/{name}/{ver}/yank")))
            .set("Authorization", &self.bearer()?);
        if undo {
            req = req.query("undo", "true");
        }
        decode_json(req.call())
    }
}

type UreqResult = std::result::Result<ureq::Response, ureq::Error>;

/// Translate a `ureq` outcome into our typed error, pulling the server's
/// `{"error": "…"}` message out of the body when present.
fn map_err(e: ureq::Error) -> CloudError {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|m| m.as_str()).map(str::to_string))
                .unwrap_or(body);
            CloudError::from_status(code, message)
        }
        ureq::Error::Transport(t) => CloudError::Transport(t.to_string()),
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(resp: UreqResult) -> Result<T> {
    match resp {
        Ok(r) => r
            .into_json::<T>()
            .map_err(|e| CloudError::Decode(e.to_string())),
        Err(e) => Err(map_err(e)),
    }
}

fn read_body(resp: UreqResult) -> Result<Vec<u8>> {
    match resp {
        Ok(r) => {
            let mut buf = Vec::new();
            r.into_reader()
                .take(MAX_DOWNLOAD_BYTES + 1)
                .read_to_end(&mut buf)
                .map_err(CloudError::Io)?;
            if buf.len() as u64 > MAX_DOWNLOAD_BYTES {
                return Err(CloudError::TooLarge);
            }
            Ok(buf)
        }
        Err(e) => Err(map_err(e)),
    }
}
