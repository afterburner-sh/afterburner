// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Errors produced by any `Combustor` implementation or the `BurnCache`.

use thiserror::Error;

/// Every failure mode Afterburner exposes to callers. Keep the set closed:
/// callers match on it exhaustively.
#[derive(Debug, Error)]
pub enum AfterburnerError {
    /// JS source failed to compile (syntax error, unsupported construct, etc.).
    #[error("compile failed: {0}")]
    CompileFailed(String),

    /// `thrust` was invoked with a `ScriptId` the engine doesn't know about.
    /// Usually means the script was `extinguish`ed or never `ignite`d.
    #[error("script not found (hash mismatch or extinguished)")]
    ScriptNotFound,

    /// The script consumed all fuel allotted by `FuelGauge::fuel`.
    #[error("fuel exhausted")]
    FuelExhausted,

    /// The script tried to allocate past `FuelGauge::memory_bytes`.
    #[error("memory limit exceeded")]
    MemoryLimit,

    /// Wall-clock `FuelGauge::timeout_ms` elapsed before the script finished.
    #[error("execution timed out")]
    Timeout,

    /// The WASM runtime trapped for any reason not caught above (division by
    /// zero, unreachable, integer overflow, etc.).
    #[error("wasm trap: {0}")]
    WasmTrap(String),

    /// JSON could not be produced or consumed at the host boundary.
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),

    /// The script's result exceeded the per-call output ceiling
    /// (`FuelGauge::output_bytes`, default 64 MiB). Applies uniformly
    /// to the JSON result capture, raw result bytes, and script-mode
    /// stdout. Surfaces as a typed error rather than an opaque
    /// guest-side I/O trap or a JSON parse failure on truncated bytes.
    #[error("script output exceeded {limit} byte ceiling (raise FuelGauge::output_bytes)")]
    OutputTooLarge { limit: usize },

    /// The module returned raw bytes (`Uint8Array` / `ArrayBuffer`)
    /// through a `Value`-shaped API (`run` / `run_raw`). Use the
    /// `OutputValue`-returning variants (`run_out` / `run_raw_out`)
    /// to receive raw results.
    #[error(
        "script returned {len} raw bytes; use run_out / run_raw_out (OutputValue) to receive them"
    )]
    UnexpectedRawOutput { len: usize },

    /// A host function returned an error to the script.
    #[error("host error: {0}")]
    Host(String),

    /// The script requested a capability the active `Manifold` does not
    /// grant (e.g. `fs.readFileSync` with `FsAccess::None`, or an FS
    /// path outside the allowed roots). The inner string names the
    /// denied operation - useful for audit logs and error messages.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The admission layer rejected this thrust because the associated
    /// tenant's token bucket is empty. Retry after `retry_after_ms`.
    ///
    /// `tenant` is the raw `u32` from `TenantId` (or `None` for the
    /// unrestricted path). Callers can wrap back into `TenantId` if
    /// they need the newtype.
    #[error("rate limited (tenant={tenant:?}, retry after {retry_after_ms}ms)")]
    RateLimited {
        tenant: Option<u32>,
        retry_after_ms: u64,
    },

    /// The thrust engine refused the job because its global in-flight
    /// cap is reached (pooling-allocator slot exhaustion). This is a
    /// backpressure signal: slow down or provision more workers.
    #[error("engine overloaded (in-flight cap reached)")]
    Overloaded,

    /// The script called `process.exit(n)` inside daemon mode. The CLI
    /// propagates the exit code to `std::process::exit`; library callers
    /// can inspect the code and decide what to do.
    #[error("process.exit({0})")]
    ProcessExit(i32),

    /// Generic engine-internal failure that doesn't fit a specific variant.
    /// Use sparingly - prefer adding a typed variant.
    #[error("engine error: {0}")]
    Engine(String),
}

/// Convenience alias used across the workspace.
pub type Result<T> = core::result::Result<T, AfterburnerError>;
