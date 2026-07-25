// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! Afterburner Node.js compatibility layer.
//!
//! * The `plenum.js` bundle (`PLENUM_BUNDLE`) - `require()` resolver and
//!   every pure-JS polyfill, ready to `eval` into a QuickJS context.
//! * Host-side implementations of the capability-gated modules (`fs`,
//!   `crypto`, `os`, `http`), each taking a [`afterburner_core::Manifold`]
//!   for permission checks.
//! * `native_install::register_native_builtins` - binds every `__host_*`
//!   global on an rquickjs `Context` so the plenum glue can call through.
//! * `active_manifold` - per-thread slot the engine sets before running a
//!   user script so globals know which capability profile is active.

pub mod active_manifold;
pub mod bundle;
pub mod child_process_host;
pub mod crypto_host;
pub mod dns_host;
pub mod fs_host;
pub mod governance;
pub mod hash_handles;
pub mod host_context_active;
pub mod http_host;
pub mod native_install;
pub mod os_host;
pub mod prime_host;
pub mod sign_handles;
pub mod state_active;
pub mod subtle_aes;
pub mod subtle_ec;
pub mod subtle_host;
pub mod subtle_rsa;
pub mod v8_host;
pub mod v8_serde;
pub mod zlib_host;

/// L3 shadows - pure-Rust substitutes for popular native-addon npm
/// packages. Each sub-module is gated behind its own feature.
pub mod shadows;

pub use bundle::PLENUM_BUNDLE;
pub use governance::spawn_governed;
pub use native_install::register_native_builtins;
