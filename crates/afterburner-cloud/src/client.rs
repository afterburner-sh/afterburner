// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! A thin, synchronous HTTP client over the registry's `/api/v1` surface.
//!
//! One method per endpoint; every non-2xx maps to a typed [`CloudError`]. The
//! client is `ureq`-backed (sync) to match the CLI's blocking handler style -
//! there is no async runtime in `burn`'s command path.

use crate::error::{CloudError, Result};
use crate::types::*;
use secrecy::{ExposeSecret, SecretString};
use std::io::Read;
use std::time::Duration;

/// Mirror of `afterburner_afb::MAX_AFB_BYTES` - never buffer more than a valid
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
        // Status-as-error is off so an error response keeps its body: the
        // registry's `{"error": "..."}` message is surfaced by `check_status`.
        // Redirects stay at ureq 2's limit of 5.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(120)))
            .timeout_recv_body(Some(Duration::from_secs(120)))
            .timeout_send_body(Some(Duration::from_secs(120)))
            .max_redirects(5)
            .http_status_as_error(false)
            .user_agent(concat!("burn/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
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

    /// `GET /api/v1/packages?q=` - full-text search.
    pub fn search(&self, q: &str) -> Result<SearchResults> {
        decode_json(
            self.agent
                .get(&self.url("/api/v1/packages"))
                .query("q", q)
                .call(),
        )
    }

    /// `GET /api/v1/packages/{ns}/{name}` - package metadata + all versions.
    pub fn get_package(&self, ns: &str, name: &str) -> Result<PackageMeta> {
        decode_json(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}")))
                .call(),
        )
    }

    /// `GET /api/v1/packages/{ns}/{name}/{ver}` - one version's metadata.
    pub fn get_version(&self, ns: &str, name: &str, ver: &str) -> Result<VersionMeta> {
        decode_json(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}/{ver}")))
                .call(),
        )
    }

    /// `GET …/{ver}/download` - stream the exact `.afb` bytes.
    pub fn download(&self, ns: &str, name: &str, ver: &str) -> Result<Vec<u8>> {
        read_body(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}/{ver}/download")))
                .call(),
        )
    }

    /// `GET …/{name}/download` - latest non-yanked version's bytes.
    pub fn download_latest(&self, ns: &str, name: &str) -> Result<Vec<u8>> {
        read_body(
            self.agent
                .get(&self.url(&format!("/api/v1/packages/{ns}/{name}/download")))
                .call(),
        )
    }

    // ── write (bearer) ──────────────────────────────────────────────────────

    /// `POST /api/v1/login` - exchange credentials for a token. No bearer.
    pub fn login(&self, username: &str, password: &str) -> Result<LoginResponse> {
        decode_json(
            self.agent
                .post(&self.url("/api/v1/login"))
                .send_json(serde_json::json!({ "username": username, "password": password })),
        )
    }

    /// `GET /api/v1/me` - the user behind the current token.
    pub fn me(&self) -> Result<Me> {
        decode_json(
            self.agent
                .get(&self.url("/api/v1/me"))
                .header("Authorization", &self.bearer()?)
                .call(),
        )
    }

    /// `POST /api/v1/publish` - upload raw `.afb` bytes.
    pub fn publish(&self, afb_bytes: &[u8]) -> Result<PublishResponse> {
        decode_json(
            self.agent
                .post(&self.url("/api/v1/publish"))
                .header("Authorization", &self.bearer()?)
                .header("Content-Type", "application/octet-stream")
                .send(afb_bytes),
        )
    }

    /// `POST …/{ver}/yank[?undo=true]`.
    pub fn yank(&self, ns: &str, name: &str, ver: &str, undo: bool) -> Result<YankResponse> {
        let mut req = self
            .agent
            .post(&self.url(&format!("/api/v1/packages/{ns}/{name}/{ver}/yank")))
            .header("Authorization", &self.bearer()?);
        if undo {
            req = req.query("undo", "true");
        }
        decode_json(req.send_empty())
    }
}

type UreqResult = std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>;

/// Turn a `ureq` outcome into a successful response or our typed error. A
/// non-2xx status pulls the server's `{"error": "..."}` message out of the
/// body when present.
fn check_status(resp: UreqResult) -> Result<ureq::http::Response<ureq::Body>> {
    let mut r = resp.map_err(|e| CloudError::Transport(e.to_string()))?;
    let status = r.status();
    if status.is_success() {
        return Ok(r);
    }
    let body = r.body_mut().read_to_string().unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("error").and_then(|m| m.as_str()).map(str::to_string))
        .unwrap_or(body);
    Err(CloudError::from_status(status.as_u16(), message))
}

fn decode_json<T: serde::de::DeserializeOwned>(resp: UreqResult) -> Result<T> {
    check_status(resp)?
        .into_body()
        .read_json::<T>()
        .map_err(|e| CloudError::Decode(e.to_string()))
}

fn read_body(resp: UreqResult) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    check_status(resp)?
        .into_body()
        .into_reader()
        .take(MAX_DOWNLOAD_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(CloudError::Io)?;
    if buf.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(CloudError::TooLarge);
    }
    Ok(buf)
}
