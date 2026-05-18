// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The `Combustor` trait — where fuel (JS) meets air (data).
//!
//! Two implementations live in sibling crates: `WasmCombustor`
//! (`afterburner-wasi`) for untrusted code, `NativeCombustor`
//! (`afterburner-ignite`) for trusted code. `AdaptiveCombustor`
//! (`afterburner-adaptive`) composes both.

use crate::error::{AfterburnerError, Result};
use crate::types::{FuelGauge, ScriptId, ScriptInvocation, ScriptOutcome};
use serde_json::Value;

/// The engine contract. Implementations must be `Send + Sync` so a single
/// instance can back a shared `BurnCache` across threads.
pub trait Combustor: Send + Sync {
    /// Ignition: compile JS source to an internal representation and return
    /// an opaque handle for repeated invocation. Idempotent — identical
    /// sources produce identical `ScriptId`s (content-addressed).
    fn ignite(&self, source: &str) -> Result<ScriptId>;

    /// Thrust: execute a compiled script with a JSON input value, subject to
    /// the given fuel/memory/timeout limits. Returns the JSON the script
    /// produced.
    fn thrust(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<Value>;

    /// Thrust with an optional working-directory override. Same semantics
    /// as [`thrust`](Self::thrust); `cwd` is the value backends should
    /// expose to user code as `process.cwd()` / `__host_cwd` for the
    /// duration of this invocation. Backends that don't surface cwd at
    /// runtime (or don't support per-call overrides) inherit the default
    /// implementation, which silently drops `cwd` and forwards to
    /// [`thrust`](Self::thrust).
    ///
    /// Embedders that need cwd to flow into the JS sandbox should set it
    /// at registration time via `Afterburner::builder().cwd(path)`; the
    /// builder prepends a cwd-pin prelude to the registered source so
    /// `require('foo')` resolves out of `<cwd>/node_modules/foo`. The
    /// per-call hook here exists for future backends that wire cwd into
    /// the plugin envelope; today only the registration-time path is
    /// active.
    fn thrust_with_cwd(
        &self,
        id: &ScriptId,
        input: &Value,
        limits: &FuelGauge,
        _cwd: Option<&str>,
    ) -> Result<Value> {
        self.thrust(id, input, limits)
    }

    /// Release any resources associated with a compiled script. After this
    /// call, `thrust` with the same `id` returns `ScriptNotFound`.
    fn extinguish(&self, id: &ScriptId);

    /// Columnar UDF path. The combustor receives a pre-encoded blob
    /// (host-side `BatchHeader` + `ColumnHeader[]` + per-column data)
    /// and returns a reply blob in the same shape. The encoder /
    /// decoder live in `afterburner-wasi`'s `columnar` module so this
    /// trait stays vendor-neutral; the only thing crossing the trait
    /// boundary is opaque byte slices.
    ///
    /// Default impl errors — backends that don't support the columnar
    /// path inherit it and surface a clean diagnostic. Currently only
    /// `WasmCombustor` overrides; `NativeCombustor` and
    /// `AdaptiveCombustor` route through the wasm path implicitly via
    /// their stored `WasmCombustor` reference (Adaptive) or simply
    /// error (Native — script mode + columnar are wasm-only).
    fn thrust_columnar_bytes(
        &self,
        id: &ScriptId,
        encoded: &[u8],
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        let _ = (id, encoded, limits);
        Err(AfterburnerError::Engine(
            "columnar UDF path not implemented for this backend".into(),
        ))
    }

    /// Script mode: run `source` as top-level code (no UDF envelope).
    /// `invocation` carries `process.argv` / `process.env` values that
    /// the backend wires into the JS runtime before the user code
    /// runs. Returns captured stdout / stderr plus a Node-style exit
    /// code.
    ///
    /// Default impl returns an error — backends that do not support
    /// script mode (currently only the library-facing native path when
    /// script mode is disabled) simply inherit this. WASM and adaptive
    /// combustors override with the real implementation.
    ///
    /// Semantics: `Ok(_)` means the script ran; `exit_code != 0`
    /// indicates the user code threw. `Err(_)` is reserved for
    /// infrastructure failures (compile, fuel, memory, timeout).
    fn run_script(
        &self,
        source: &str,
        invocation: &ScriptInvocation,
        limits: &FuelGauge,
    ) -> Result<ScriptOutcome> {
        let _ = (source, invocation, limits);
        Err(AfterburnerError::Engine(
            "script mode not supported by this backend".into(),
        ))
    }
}
