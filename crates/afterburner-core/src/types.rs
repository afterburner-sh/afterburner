// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Core value types shared by every `Combustor` implementation.

use crate::manifold::Manifold;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Identifier returned by `Combustor::ignite` and consumed by `thrust` /
/// `extinguish`. Content-addressed: the `hash` is SHA-256 of the JS source,
/// so two identical sources produce the same `ScriptId` regardless of which
/// `Combustor` compiled them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScriptId {
    pub hash: [u8; 32],
    pub mode: EngineMode,
}

/// Which backend produced a `ScriptId`. Useful for adaptive tier switching
/// and for diagnostics; callers generally shouldn't branch on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineMode {
    /// QuickJS compiled to WASM, executed via Wasmtime. Full sandbox.
    Wasm,
    /// QuickJS via `rquickjs` FFI. Trusted code only - no WASM sandbox.
    Native,
}

/// Execution resource limits applied per call. Each field is optional;
/// `None` means "no cap on this dimension."
///
/// **Backend-portable field:** `timeout_ms` is wall-clock and behaves the
/// same on every backend. Prefer it as the primary safety knob - it is the
/// only limit whose magnitude carries the same meaning across modes.
///
/// **Backend-specific fields:** `fuel` and `memory_bytes` measure
/// backend-internal quantities and are **not** numerically comparable
/// between modes. A `fuel: Some(1_000_000)` value is reasonable in one
/// backend and absurdly small in another - see the table below. Code that
/// runs under [`crate::engine::Combustor`] without knowing the concrete
/// backend should rely on `timeout_ms` and treat `fuel` / `memory_bytes`
/// as backend-tuning hints.
///
/// | Field          | Wasm (`afterburner-wasi`)              | Native (`afterburner-ignite`)        |
/// |----------------|----------------------------------------|--------------------------------------|
/// | `fuel`         | Wasmtime instruction count (1 unit ≈   | QuickJS interrupt-handler ticks. One |
/// |                | one Wasm op). Order ~10⁹ for a long    | tick covers many bytecode ops; order |
/// |                | script.                                | ~10⁵–10⁶ for a long script.          |
/// | `memory_bytes` | Linear-memory cap enforced by          | rquickjs heap cap.                   |
/// |                | Wasmtime's `ResourceLimiter`.          |                                      |
/// | `timeout_ms`   | Wall-clock; trapped by the shared      | Wall-clock; checked in the interrupt |
/// |                | epoch ticker.                          | handler.                             |
#[derive(Debug, Clone, Default)]
pub struct FuelGauge {
    /// Backend-specific instruction budget. See type-level docs for the
    /// per-mode semantics - values are NOT comparable across modes.
    pub fuel: Option<u64>,
    /// Maximum bytes of linear memory (Wasm) or heap (native).
    pub memory_bytes: Option<usize>,
    /// Wall-clock cap. Same meaning across all backends.
    pub timeout_ms: Option<u64>,
    /// Ceiling on the bytes a single invocation may produce as its
    /// result - the host-side capture of the script's output (result
    /// JSON, raw result bytes, script-mode stdout). `None` means the
    /// engine default ([`Self::DEFAULT_OUTPUT_BYTES`], 64 MiB), **not**
    /// unlimited: the capture buffer is host RAM, so output stays a
    /// bounded resource even under [`Self::unlimited`]. Exceeding the
    /// ceiling surfaces as
    /// [`AfterburnerError::OutputTooLarge`](crate::AfterburnerError::OutputTooLarge):
    /// a structured error, never a bare trap.
    pub output_bytes: Option<usize>,
    /// Capability gate for Node-style built-in modules. Defaults to
    /// [`Manifold::sealed`] - no host-backed modules accessible.
    pub manifold: Manifold,
}

impl FuelGauge {
    /// Default result-capture ceiling applied when
    /// [`output_bytes`](Self::output_bytes) is `None`: 64 MiB.
    /// Generous enough for bulk result payloads while keeping a
    /// runaway script's host-side output capture bounded.
    pub const DEFAULT_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

    /// Unrestricted resource limits, sealed manifold. Useful for tests
    /// and for trusted code that still needs a capability-free starting
    /// point - override individual fields as needed. Output capture
    /// stays at the [`Self::DEFAULT_OUTPUT_BYTES`] ceiling (host RAM
    /// is never an unbounded resource); raise `output_bytes`
    /// explicitly for larger results.
    pub const fn unlimited() -> Self {
        Self {
            fuel: None,
            memory_bytes: None,
            timeout_ms: None,
            output_bytes: None,
            manifold: Manifold::sealed(),
        }
    }

    /// The effective output ceiling for this gauge -
    /// [`output_bytes`](Self::output_bytes) or the engine default.
    pub fn output_ceiling(&self) -> usize {
        self.output_bytes.unwrap_or(Self::DEFAULT_OUTPUT_BYTES)
    }
}

/// Input for [`crate::engine::Combustor::run_script`] - the script
/// source plus Node-style `process.argv` and `process.env` values.
///
/// Separated from [`FuelGauge`] because this is per-invocation *data*
/// flowing into the runtime, not *limits* applied to it. The active
/// [`Manifold`] still gates what the script can actually do with env
/// vars once visible; this struct only governs what the caller
/// exposes in the first place.
#[derive(Debug, Clone, Default)]
pub struct ScriptInvocation {
    /// Populated into `process.argv`. Conventionally
    /// `["burn", "/abs/path/script.js", ...user_args]` for the CLI;
    /// library callers typically pass `[]` or just a program name.
    pub argv: Vec<String>,
    /// Populated into `process.env`. For the CLI this is usually
    /// `std::env::vars()` filtered through [`Manifold::env`]; library
    /// callers pick what they want exposed.
    pub env: std::collections::BTreeMap<String, String>,
    /// Populated into `process.cwd()` and used by B6's `require()`
    /// resolver as the baseline for path-relative lookups when the
    /// entry script itself has no meaningful `__dirname` (e.g. `-e`
    /// eval mode). Empty string falls back to `"/"` inside the plugin.
    pub cwd: String,
}

/// Result of [`crate::engine::Combustor::run_script`] - top-level
/// script-mode execution (no UDF envelope).
///
/// Unlike the UDF [`thrust`](crate::engine::Combustor::thrust) path
/// where the backend returns the script's JSON return value, script
/// mode buffers whatever was written to stdout / stderr during
/// execution and surfaces them alongside the Node-style `exit_code`.
///
/// `Ok(ScriptOutcome)` means the script ran to completion - possibly
/// with `exit_code != 0` if the user code threw an uncaught exception.
/// `Err(AfterburnerError)` is reserved for infrastructural failures
/// that prevented a meaningful run: compile failure on the user
/// source, fuel/memory/timeout exhaustion, WASM traps not mapped to a
/// specific cause.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptOutcome {
    /// Everything the script wrote to fd 1 (`console.log`, `process.stdout.write`,
    /// `Javy.IO.writeSync(1, …)`). Bounded by the host's stdout capacity.
    pub stdout: Vec<u8>,
    /// Everything the script wrote to fd 2 (`console.error`, plus any
    /// plugin-emitted trap-diagnosis text when the script threw).
    pub stderr: Vec<u8>,
    /// Node-style exit code. `0` = natural completion. `1` = uncaught
    /// exception in user code. Other values come from `process.exit(N)`
    /// when that lands in a later phase.
    pub exit_code: i32,
}

/// Result of an output-framing-aware invocation
/// ([`thrust_out`](crate::engine::Combustor::thrust_out) /
/// [`thrust_raw_out`](crate::engine::Combustor::thrust_raw_out)) -
/// the output-side mirror of the input framings.
///
/// One compiled bytecode serves both shapes: the invoke wrapper
/// branches on the **module's return value**. A `Uint8Array` /
/// `ArrayBuffer` return crosses the boundary as opaque bytes through a
/// host import ([`Bytes`](Self::Bytes)) - no `JSON.stringify`, no
/// string materialization, no base64, all O(n) and fuel-metered work
/// the JSON framing pays. Every other return value takes the
/// unchanged JSON-over-stdout contract ([`Json`](Self::Json)).
#[derive(Debug, Clone, PartialEq)]
pub enum OutputValue {
    /// The module returned a JSON-serializable value.
    Json(serde_json::Value),
    /// The module returned a `Uint8Array` / `ArrayBuffer`; these are
    /// its bytes, delivered verbatim (NULs, newlines, invalid UTF-8
    /// all preserved).
    Bytes(Vec<u8>),
}

impl OutputValue {
    /// Unwrap the JSON shape; a raw-bytes result becomes
    /// [`AfterburnerError::UnexpectedRawOutput`](crate::AfterburnerError::UnexpectedRawOutput).
    /// Used by the `Value`-returning convenience APIs (`run` /
    /// `run_raw`) whose signatures predate raw output.
    pub fn into_json(self) -> crate::Result<serde_json::Value> {
        match self {
            OutputValue::Json(v) => Ok(v),
            OutputValue::Bytes(b) => {
                Err(crate::AfterburnerError::UnexpectedRawOutput { len: b.len() })
            }
        }
    }

    /// Unwrap the raw-bytes shape; a JSON result serializes to its
    /// canonical text bytes. Total - callers that want "give me bytes
    /// whatever the module returned" use this.
    pub fn into_bytes(self) -> crate::Result<Vec<u8>> {
        match self {
            OutputValue::Json(v) => Ok(serde_json::to_vec(&v)?),
            OutputValue::Bytes(b) => Ok(b),
        }
    }
}

/// SHA-256 the given bytes. Shared helper so every engine hashes sources
/// identically and `ScriptId`s round-trip between backends. This is the
/// **source**-address (a `ScriptId`); the content-address for effect and
/// output *payloads* is [`content_hash`] (BLAKE3).
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// BLAKE3 the given bytes: the canonical **content**-address for effect and
/// output payloads. The frame carrier ([`crate::frame`]) and the effect seam
/// ([`crate::effect`]) both use this one function, so a value carried as an
/// `output` and the same bytes seen as a filesystem effect content-address
/// identically (the record/replay parity crux). Distinct from [`sha256`],
/// which stays the source-address for a `ScriptId`.
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).into()
}

/// Result of [`crate::engine::Combustor::run_with_result`] - a full run that
/// also surfaces the typed return value.
///
/// The delta over [`ScriptOutcome`] is the typed `output`: captured
/// stdout/stderr and the exit code as before, plus the module's return value
/// as an [`OutputValue`]. `OutputValue::Json(Value::Null)` means "no return
/// value was surfaced". Verdict / probe outcomes stay causarum-side and are
/// deliberately not carried here.
#[derive(Debug, Clone, PartialEq)]
pub struct RunResult {
    /// Everything the run wrote to fd 1, byte-exact.
    pub stdout: Vec<u8>,
    /// Everything the run wrote to fd 2, byte-exact.
    pub stderr: Vec<u8>,
    /// Node-style exit code (`0` = clean completion).
    pub exit_code: i32,
    /// The module's typed return value, or `Json(Null)` when none surfaced.
    pub output: OutputValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_deterministic() {
        let a = sha256(b"module.exports = () => 1");
        let b = sha256(b"module.exports = () => 1");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_differs_for_different_input() {
        let a = sha256(b"module.exports = () => 1");
        let b = sha256(b"module.exports = () => 2");
        assert_ne!(a, b);
    }

    #[test]
    fn fuel_gauge_unlimited_has_no_caps() {
        let g = FuelGauge::unlimited();
        assert!(g.fuel.is_none());
        assert!(g.memory_bytes.is_none());
        assert!(g.timeout_ms.is_none());
    }
}
