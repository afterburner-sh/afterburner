// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/vertexclique/afterburner/master/art/svg/afterburner-square.svg"
)]
//! Afterburner WASM engine - Wasmtime runtime hosting Javy-style
//! QuickJS-in-WASM. Produces hard-sandboxed JS execution with fuel,
//! memory, and wall-clock caps.

pub mod bundle;
pub mod capture;
mod chamber;
pub mod columnar;
#[cfg(feature = "daemon")]
pub mod daemon_cluster;
#[cfg(feature = "daemon")]
pub mod daemon_dgram;
pub mod daemon_envelopes;
pub mod daemon_http;
#[cfg(feature = "http3")]
pub mod daemon_http3;
#[cfg(feature = "daemon")]
pub mod daemon_http_outbound;
#[cfg(feature = "daemon")]
pub mod daemon_inspector;
#[cfg(feature = "daemon")]
pub mod daemon_net;
#[cfg(feature = "daemon")]
pub mod daemon_port_claims;
pub mod daemon_runtime;
pub mod daemon_sab;
#[cfg(feature = "daemon")]
pub mod daemon_shard_pool;
#[cfg(feature = "daemon")]
pub mod daemon_tls;
pub mod daemon_workers;
pub mod embedder_vm;
pub mod emscripten_abi;
pub mod emscripten_dylink;
pub mod emscripten_exnref;
pub mod emscripten_ffi;
pub mod emscripten_fs;
pub mod emscripten_invoke;
pub mod emscripten_jsffi;
pub mod emscripten_mechanical;
pub mod emscripten_runtime;
pub mod emscripten_sidemodule;
pub mod emscripten_syscall;
pub mod emscripten_wasi;
pub mod host;
pub mod host_imports;
pub mod intake;
pub mod manifold_codec;
pub mod nozzle;
pub mod pyodide_bundle;
/// The embedded Python core (`include_bytes!`), present only under the
/// `embed-core` feature; basic Python then runs offline with zero download.
#[cfg(feature = "embed-core")]
pub mod pyodide_embed;
pub mod pyodide_runner;
// `pyo_trace!` is `#[macro_export]`ed (available crate-wide as `crate::pyo_trace`
// via an explicit `use`); no `#[macro_use]` needed.
pub mod pyodide_trace;
pub mod ruby_bundle;
pub mod ruby_runner;
pub mod test_support;
pub mod wasi_sdk_bundle;
pub mod wasm_engine;
pub mod wasm_loader;

pub use columnar::{
    ColumnDtype, ColumnRef, ColumnarBatch, ColumnarOutput, INLINE_SLOT_BYTES,
    INLINE_SLOT_INLINE_MAX, OwnedColumn, decode_batch, encode_batch,
};
#[cfg(feature = "daemon")]
pub use daemon_dgram::{DaemonDgram, DgramEvent};
pub use daemon_http::{DaemonHttp, ReplyEnvelope};
#[cfg(feature = "daemon")]
pub use daemon_http_outbound::{DaemonHttpOutbound, HttpOutboundResponseEvent};
#[cfg(feature = "daemon")]
pub use daemon_net::{DaemonNet, NetEvent};
#[cfg(feature = "daemon")]
pub use daemon_port_claims::{ClaimResult, SharedPortClaims};
pub use daemon_runtime::DaemonRuntime;
#[cfg(feature = "daemon")]
pub use daemon_shard_pool::{DaemonShardPool, ShardPoolConfig};
#[cfg(feature = "daemon")]
pub use daemon_tls::{DaemonTls, TlsEvent};
pub use daemon_workers::{DaemonWorkers, WorkerConfig, WorkerEvent};
pub use manifold_codec::manifold_to_cli_args;
pub use wasm_engine::{WasmCombustor, WasmConfig};

/// The Wizer-preinitialized Afterburner Javy plugin binary. Exposed for
/// build-time tools that need to pass it to `javy build -C plugin=...`
/// (e.g. `burn compile` for capability-bearing packages). The runtime
/// uses this same binary via `include_bytes!` in `wasm_engine`.
pub const AFTERBURNER_PLUGIN_BYTES: &[u8] = include_bytes!("../plugin/afterburner_plugin.wasm");
