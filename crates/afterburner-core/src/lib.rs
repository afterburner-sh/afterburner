// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! Afterburner core - engine trait, shared types, host-function API surface,
//! and the script registry shell.
//!
//! This crate deliberately has no runtime dependencies on Wasmtime or
//! rquickjs. It defines the contract every backend implements.

pub mod effect;
pub mod engine;
pub mod error;
pub mod frame;
pub mod host;
pub mod language;
pub mod log;
pub mod manifold;
pub mod registry;
pub mod session;
pub mod state_store;
pub mod types;

/// This crate's version, used by `afterburner-afb` to enforce a package's
/// `[runtime] min` requirement against the running engine.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use effect::{
    CallSite, EffectDetail, EffectKind, EffectStatus, FileOp, HostEffect, HostEffectRecord,
    db_target, env_target, fs_target, http_target, process_target, socket_target,
};
pub use engine::Combustor;
pub use error::{AfterburnerError, Result};
pub use frame::{
    HEADER_LEN, INTERNAL_MOUNT, MAGIC, OutputTag, VERSION as FRAME_VERSION, decode_frame,
    decode_output_value, encode_frame, encode_output_value, is_internal_capture_path,
};
pub use host::{HostContext, HostFunction, HttpMethod, HttpResponse, LogLevel, NullHost};
pub use language::Language;
pub use manifold::{EnvAccess, FsAccess, ListenAccess, Manifold, NetAccess};
pub use registry::{BurnCache, BurnCacheBackend, InProcessCacheBackend, RegistryStats, hex32};
pub use session::Session;
pub use state_store::{InMemoryStateStore, SharedStateStore, StateStore};
pub use types::{
    EngineMode, FuelGauge, OutputValue, RunResult, ScriptId, ScriptInvocation, ScriptOutcome,
    content_hash, sha256,
};
