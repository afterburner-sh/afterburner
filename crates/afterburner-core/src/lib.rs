// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! Afterburner core — engine trait, shared types, host-function API surface,
//! and the script registry shell.
//!
//! This crate deliberately has no runtime dependencies on Wasmtime or
//! rquickjs. It defines the contract every backend implements.

pub mod engine;
pub mod error;
pub mod host;
pub mod log;
pub mod manifold;
pub mod registry;
pub mod state_store;
pub mod types;

/// This crate's version, used by `afterburner-afb` to enforce a package's
/// `[runtime] min` requirement against the running engine.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use engine::Combustor;
pub use error::{AfterburnerError, Result};
pub use host::{HostContext, HostFunction, HttpMethod, HttpResponse, LogLevel, NullHost};
pub use manifold::{EnvAccess, FsAccess, Manifold, NetAccess};
pub use registry::{BurnCache, BurnCacheBackend, InProcessCacheBackend, RegistryStats, hex32};
pub use state_store::{InMemoryStateStore, SharedStateStore, StateStore};
pub use types::{EngineMode, FuelGauge, ScriptId, ScriptInvocation, ScriptOutcome, sha256};
