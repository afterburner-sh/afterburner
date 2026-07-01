// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Host function API surface exposed to JS scripts.
//!
//! This module declares the *shape* of every host function. The actual
//! WASM-side wiring (Wasmtime `Linker` registration, WASI glue) lives in
//! `afterburner-wasi`. Embedders implement `HostContext` to plug their own
//! data into `ReadColumn` / `EmitRow`.
//!
//! `Log` and `GetEnv` are the commonly-wired variants; the rest are
//! implemented by hosts that opt into richer integrations.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Log severity, mirroring `console.*` in JS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// HTTP method for `HostFunction::HttpRequest`. Present even when the
/// `host-http` feature is off so the enum shape is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
}

impl HttpMethod {
    /// The canonical uppercase method token (`"GET"`, `"POST"`, ...). Used to
    /// build the canonical HTTP effect target so every substrate spells the
    /// method identically (see [`crate::effect::http_target`]).
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
        }
    }
}

/// Response returned from `HostFunction::HttpRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// The full host-function set.
///
/// Variants map 1:1 to WASM imports that JS scripts can call. The enum is a
/// convenience for dispatch; individual hooks live on the `HostContext` trait
/// so callers only implement the pieces they need.
#[derive(Debug, Clone)]
pub enum HostFunction {
    /// `console.log` / `console.error` bridge.
    Log { level: LogLevel, message: String },

    /// Read a named column from the current row batch. Wired by hosts
    /// that run the engine in a tabular context; a no-op otherwise.
    ReadColumn { name: String },

    /// Emit a transformed row. Wired by hosts that run the engine in a
    /// tabular context.
    EmitRow { row: Value },

    /// Read an allow-listed environment variable.
    GetEnv { key: String },

    /// HTTP out-call. Gated behind the `host-http` cargo feature in
    /// `afterburner-wasi`.
    HttpRequest {
        url: String,
        method: HttpMethod,
        body: Option<String>,
    },
}

/// Callbacks the host provides to the script runtime. Implementations supply
/// whichever methods are relevant; defaults are intentionally no-ops or
/// `None` so minimal hosts (e.g. tests) don't need to stub every variant.
pub trait HostContext: Send + Sync {
    fn log(&self, _level: LogLevel, _message: &str) {}

    fn read_column(&self, _name: &str) -> Vec<Value> {
        Vec::new()
    }

    fn emit_row(&self, _row: Value) {}

    fn get_env(&self, _key: &str) -> Option<String> {
        None
    }

    #[cfg(feature = "host-http")]
    fn http_request(
        &self,
        _url: &str,
        _method: HttpMethod,
        _body: Option<&str>,
    ) -> crate::error::Result<HttpResponse> {
        Err(crate::error::AfterburnerError::Host(
            "http_request not implemented".into(),
        ))
    }

    /// The record/serve seam for a side effect the guest is about to perform.
    ///
    /// Called by a substrate *before* it executes an effect. The return value
    /// selects the mode:
    ///
    /// - `None` -> **original run**: the substrate executes the real effect,
    ///   then reports the result back via [`record_host_effect`].
    /// - `Some(record)` -> **replay**: the substrate substitutes
    ///   `record.output` and performs **no** real effect.
    ///
    /// The default is `None` (always run the real effect), so a minimal host
    /// or a test needs no override.
    ///
    /// [`record_host_effect`]: Self::record_host_effect
    fn on_host_call(
        &self,
        _effect: &crate::effect::HostEffect,
    ) -> Option<crate::effect::HostEffectRecord> {
        None
    }

    /// Append a completed effect to the host's journal, after the substrate
    /// executed the real effect on an original run. The default drops it -
    /// afterburner owns the seam, not the journal schema or its persistence
    /// (causarum owns those); a recording host overrides this.
    fn record_host_effect(&self, _record: crate::effect::HostEffectRecord) {}

    /// The full effect journal in call order. The handoff point: causarum
    /// reads the recorded effects here. The default is empty (a
    /// non-recording host).
    fn get_effect_log(&self) -> Vec<crate::effect::HostEffectRecord> {
        Vec::new()
    }
}

/// Zero-capability host context - useful as a default for tests and for the
/// minimal flow-engine path that only uses `Log`.
pub struct NullHost;

impl HostContext for NullHost {}
