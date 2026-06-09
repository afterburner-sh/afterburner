// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `afterburner-cloud` — the registry client behind `burn`'s package-management
//! subcommands (`login`, `publish`, `install`, `search`, `add`, `info`,
//! `yank`, `whoami`, `new`/`init`).
//!
//! It is intentionally free of any Wasmtime/rquickjs dependency. It reuses
//! [`afterburner_afb`] for the `.afb` format (pack/unpack/manifest/digest) and
//! [`afterburner_core::Manifold`] for capability sets, and speaks the HTTP API
//! documented in the `afterburner-registry` repo (`/api/v1`).
//!
//! Layering:
//! - [`client`] — a thin, synchronous HTTP client over `/api/v1` (one method
//!   per endpoint), returning typed [`types`] responses.
//! - [`config`] — cargo-style credential storage (`~/.config/burn/credentials.toml`)
//!   and the registry/token resolution order.
//! - [`cache`] — the local content-addressed `.afb` store (`~/.cache/burn/packages`).
//! - [`pkg`] — load a local package directory and build its `.afb` (publish/package/add).
//! - [`scaffold`] — `new`/`init` project scaffolding with capability-aware templates.
//! - [`coord`] — `namespace/name[@version]` coordinate parsing.

pub mod cache;
pub mod client;
pub mod config;
pub mod coord;
pub mod error;
pub mod install;
pub mod lock;
pub mod pkg;
pub mod resolve;
pub mod scaffold;
pub mod source;
pub mod types;

pub use client::RegistryClient;
pub use config::{DEFAULT_REGISTRY_URL, Resolved};
pub use coord::Coord;
pub use error::{CloudError, Result};
pub use install::{
    CacheInstaller, InstallItem, InstallSummary, Installer, Outcome, Progress, install_concurrent,
};
pub use lock::Lockfile;
pub use resolve::{Candidate, Req, Resolution, Source, resolve, runtime_version};
pub use source::RegistrySource;

// Re-export the `.afb` surface callers most often touch so the `burn` CLI can
// depend on this crate alone.
pub use afterburner_afb::{self, Afb, Manifest, Manifold};
