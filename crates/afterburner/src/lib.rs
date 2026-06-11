// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! # Afterburner
//!
//! Sandboxed JavaScript runtime for Rust. One crate, one entry point.
//!
//! ```no_run
//! use afterburner::Afterburner;
//! use serde_json::json;
//!
//! let ab = Afterburner::new()?;
//! let id = ab.register("(d) => d.n + 1")?;
//! let out = ab.run(&id, &json!({ "n": 41 }))?;
//! assert_eq!(out, json!(42));
//! # Ok::<_, afterburner::AfterburnerError>(())
//! ```
//!
//! ## Modes
//!
//! * **Adaptive** (default): first call runs via `rquickjs` (native,
//!   sub-microsecond); a background thread compiles the same script to
//!   WASM, and subsequent calls switch to the sandboxed Wasmtime path.
//! * **Native only**: trusted code; sub-microsecond throughput, no
//!   sandbox.
//! * **WASM only**: untrusted code; Wasmtime + QuickJS, capability gates
//!   via [`Manifold`].
//! * **Threaded**: N worker threads behind a single `Afterburner`.
//!   Hash-routed with Chase-Lev-style steal-when-idle, token-bucket
//!   admission, graceful drain. Enable via [`AfterburnerBuilder::threaded`].
//!
//! ## Feature flags
//!
//! | feature      | default | unlocks                                          |
//! |--------------|:-------:|--------------------------------------------------|
//! | `wasm`       |   yes   | Wasmtime backend (`WasmCombustor`)               |
//! | `native`     |   yes   | rquickjs backend (`NativeCombustor`)             |
//! | `thrust`     |   yes   | multi-threaded scheduler (`ThrustEngine`)        |
//! | `adaptive`   |   no    | dual-tier native → wasm auto-switch              |
//! | `flow`       |   no    | flow-engine glue (multi-module bundles)          |
//! | `host-http`  |   no    | outbound HTTP host function                      |
//! | `bin`        |   no    | `burn` CLI binary deps (`clap`, `rustyline`)     |
//!
//! ## Capability gating
//!
//! Every thrust carries a [`Manifold`] (via [`FuelGauge`]) that controls
//! what host-backed modules (`fs`, `crypto`, `net`, `env`) the script can
//! reach. Default is [`Manifold::sealed`] - nothing accessible.

#![warn(missing_debug_implementations)]

mod builder;
#[cfg(feature = "bin")]
pub mod cli;
#[cfg(feature = "ts")]
pub mod esm;
pub mod prelude;
#[cfg(feature = "ts")]
pub mod ts;

// ---- Top-level re-exports of the most-used types -------------------
//
// These flatten the most common API surface so callers can write
// `use afterburner::Manifold` instead of `use afterburner::core::Manifold`.
pub use afterburner_core::{
    AfterburnerError, BurnCache, BurnCacheBackend, Combustor, EngineMode, EnvAccess, FsAccess,
    FuelGauge, HostContext, HostFunction, HttpMethod, HttpResponse, InMemoryStateStore,
    InProcessCacheBackend, ListenAccess, LogLevel, Manifold, NetAccess, NullHost, OutputValue,
    RegistryStats, Result, ScriptId, ScriptInvocation, ScriptOutcome, SharedStateStore, StateStore,
    sha256,
};

// ---- Full sibling-crate re-exports ---------------------------------
//
// Every workspace crate is also exposed as a submodule of `afterburner`
// using its canonical short name. Pick whichever feels more natural:
//
//   use afterburner::core::Manifold;        // crate-level path
//   use afterburner::Manifold;              // flattened
//   use afterburner::wasi::WasmCombustor;   // backend-specific
//
// The crate-as-module aliases give callers full access to every public
// item - re-exporting the crate avoids the maintenance toll of
// hand-curating individual `pub use` lists.

/// `afterburner-core` - the trait surface (`Combustor`, `Manifold`,
/// `BurnCache`, …) and shared error / value types.
pub use afterburner_core as core;

/// `afterburner-node-compat` - Plenum bundle source + host-side
/// implementations of every Node built-in (fs / crypto / dns / zlib / …)
/// plus the L3 shadow modules.
pub use afterburner_node_compat as node_compat;

#[cfg(feature = "wasm")]
pub use afterburner_wasi as wasi;

#[cfg(feature = "native")]
pub use afterburner_ignite as ignite;

#[cfg(feature = "adaptive")]
pub use afterburner_adaptive as adaptive_crate;

#[cfg(feature = "flow")]
pub use afterburner_flow as flow_crate;

#[cfg(feature = "thrust")]
pub use afterburner_thrust as thrust_crate;

// ---- Backend-named submodules (compat with the original API) -------
//
// The original 0.1 API exposed backends under `afterburner::wasm`,
// `afterburner::native`, etc. - keep them as thin pub-use modules so
// existing call sites keep compiling. New code should prefer the
// crate-name aliases above (`afterburner::wasi`, `afterburner::ignite`).

#[cfg(feature = "wasm")]
pub mod wasm {
    //! WASM backend - untrusted code via Wasmtime + QuickJS plugin.
    pub use afterburner_wasi::*;
}

#[cfg(feature = "native")]
pub mod native {
    //! Native backend - trusted code via rquickjs FFI.
    pub use afterburner_ignite::*;
}

#[cfg(feature = "adaptive")]
pub mod adaptive {
    //! Dual-tier adaptive combustor (first call native, subsequent WASM).
    pub use afterburner_adaptive::*;
}

#[cfg(feature = "flow")]
pub mod flow {
    //! Flow engine - compile + execute with data-chain payload support.
    pub use afterburner_flow::*;
}

#[cfg(feature = "thrust")]
pub mod thrust {
    //! Multi-threaded scheduler.
    pub use afterburner_thrust::*;
}

pub use builder::{Afterburner, AfterburnerBuilder, Mode};

#[cfg(feature = "thrust")]
pub use builder::ThreadedBuilder;
