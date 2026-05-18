// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

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
    /// QuickJS via `rquickjs` FFI. Trusted code only — no WASM sandbox.
    Native,
}

/// Execution resource limits applied per call. Each field is optional;
/// `None` means "no cap on this dimension."
///
/// **Backend-portable field:** `timeout_ms` is wall-clock and behaves the
/// same on every backend. Prefer it as the primary safety knob — it is the
/// only limit whose magnitude carries the same meaning across modes.
///
/// **Backend-specific fields:** `fuel` and `memory_bytes` measure
/// backend-internal quantities and are **not** numerically comparable
/// between modes. A `fuel: Some(1_000_000)` value is reasonable in one
/// backend and absurdly small in another — see the table below. Code that
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
    /// per-mode semantics — values are NOT comparable across modes.
    pub fuel: Option<u64>,
    /// Maximum bytes of linear memory (Wasm) or heap (native).
    pub memory_bytes: Option<usize>,
    /// Wall-clock cap. Same meaning across all backends.
    pub timeout_ms: Option<u64>,
    /// Capability gate for Node-style built-in modules. Defaults to
    /// [`Manifold::sealed`] — no host-backed modules accessible.
    pub manifold: Manifold,
}

impl FuelGauge {
    /// Unrestricted resource limits, sealed manifold. Useful for tests
    /// and for trusted code that still needs a capability-free starting
    /// point — override individual fields as needed.
    pub const fn unlimited() -> Self {
        Self {
            fuel: None,
            memory_bytes: None,
            timeout_ms: None,
            manifold: Manifold::sealed(),
        }
    }
}

/// Input for [`crate::engine::Combustor::run_script`] — the script
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

/// Result of [`crate::engine::Combustor::run_script`] — top-level
/// script-mode execution (no UDF envelope).
///
/// Unlike the UDF [`thrust`](crate::engine::Combustor::thrust) path
/// where the backend returns the script's JSON return value, script
/// mode buffers whatever was written to stdout / stderr during
/// execution and surfaces them alongside the Node-style `exit_code`.
///
/// `Ok(ScriptOutcome)` means the script ran to completion — possibly
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

/// SHA-256 the given bytes. Shared helper so every engine hashes sources
/// identically and `ScriptId`s round-trip between backends.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
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
