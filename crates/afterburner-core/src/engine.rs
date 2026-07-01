// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The `Combustor` trait - where fuel (JS) meets air (data).
//!
//! Two implementations live in sibling crates: `WasmCombustor`
//! (`afterburner-wasi`) for untrusted code, `NativeCombustor`
//! (`afterburner-ignite`) for trusted code. `AdaptiveCombustor`
//! (`afterburner-adaptive`) composes both.

use crate::error::{AfterburnerError, Result};
use crate::host::HostContext;
use crate::types::{FuelGauge, OutputValue, RunResult, ScriptId, ScriptInvocation, ScriptOutcome};
use serde_json::Value;

/// The engine contract. Implementations must be `Send + Sync` so a single
/// instance can back a shared `BurnCache` across threads.
pub trait Combustor: Send + Sync {
    /// Ignition: compile JS source to an internal representation and return
    /// an opaque handle for repeated invocation. Idempotent - identical
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

    /// Raw-input fast path: execute a compiled script with `input`
    /// delivered to the module as a `Uint8Array` instead of a JSON
    /// value. For bulk binary payloads this skips the whole
    /// input-framing tax of [`thrust`](Self::thrust) - host-side JSON
    /// serialization, guest-side string materialization, and
    /// guest-side `JSON.parse` (all O(n) in the input size, and the
    /// guest-side parts are fuel-metered). The script's return value
    /// still comes back as JSON, same output contract as `thrust`.
    ///
    /// Default impl errors - backends without a linear-memory bridge
    /// inherit it and surface a clean diagnostic, mirroring
    /// [`thrust_columnar_bytes`](Self::thrust_columnar_bytes).
    /// Currently only `WasmCombustor` overrides; `AdaptiveCombustor`
    /// routes to its wasm tier.
    fn thrust_raw(&self, id: &ScriptId, input: &[u8], limits: &FuelGauge) -> Result<Value> {
        let _ = (id, input, limits);
        Err(AfterburnerError::Engine(
            "raw input path not implemented for this backend".into(),
        ))
    }

    /// Output-framing-aware variant of [`thrust`](Self::thrust): the
    /// module's return value decides the result shape. A `Uint8Array`
    /// / `ArrayBuffer` return comes back as [`OutputValue::Bytes`]
    /// (raw bytes through a host import - no `JSON.stringify`, no
    /// guest-side string materialization, both O(n) fuel-metered
    /// work); anything else comes back as [`OutputValue::Json`] via
    /// the unchanged stdout contract. One compiled bytecode serves
    /// both shapes - the invoke wrapper branches on the return type,
    /// exactly mirroring how the input side branches on framing.
    ///
    /// Default impl forwards to [`thrust`](Self::thrust) and wraps in
    /// [`OutputValue::Json`] - correct for backends without a raw
    /// output bridge, where a bytes-shaped return would already have
    /// surfaced as that backend's JSON encoding of it.
    fn thrust_out(&self, id: &ScriptId, input: &Value, limits: &FuelGauge) -> Result<OutputValue> {
        self.thrust(id, input, limits).map(OutputValue::Json)
    }

    /// Raw input **and** output-framing-aware result: bulk bytes in
    /// (module receives a `Uint8Array`, see
    /// [`thrust_raw`](Self::thrust_raw)), and the module's return
    /// type picks the result framing (see
    /// [`thrust_out`](Self::thrust_out)). This is the full-duplex
    /// bulk-payload path: "bytes in, bytes out" crosses the boundary
    /// with zero JSON / string / base64 work in either direction.
    ///
    /// Default impl errors - backends without a linear-memory bridge
    /// inherit it, mirroring [`thrust_raw`](Self::thrust_raw).
    fn thrust_raw_out(
        &self,
        id: &ScriptId,
        input: &[u8],
        limits: &FuelGauge,
    ) -> Result<OutputValue> {
        let _ = (id, input, limits);
        Err(AfterburnerError::Engine(
            "raw input path not implemented for this backend".into(),
        ))
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
    /// Default impl errors - backends that don't support the columnar
    /// path inherit it and surface a clean diagnostic. Currently only
    /// `WasmCombustor` overrides; `NativeCombustor` and
    /// `AdaptiveCombustor` route through the wasm path implicitly via
    /// their stored `WasmCombustor` reference (Adaptive) or simply
    /// error (Native - script mode + columnar are wasm-only).
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
    /// Default impl returns an error - backends that do not support
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

    /// Script mode with a typed result and a host seam. Same run semantics as
    /// [`run_script`](Self::run_script), but the result is a
    /// [`RunResult`] that also carries the module's typed `output`
    /// ([`OutputValue`]), and `host` receives the effect seam
    /// ([`HostContext::on_host_call`])
    /// during the run.
    ///
    /// `OutputValue::Json(Value::Null)` in the result means "no return value
    /// was surfaced" - a plain script-mode run that only wrote stdout.
    ///
    /// Default impl errors - substrates wire the real capture path later; a
    /// backend that has not yet implemented it inherits a clean diagnostic
    /// rather than a silent empty result (honesty fence).
    fn run_with_result(
        &self,
        source: &[u8],
        invocation: &ScriptInvocation,
        limits: &FuelGauge,
        host: &dyn HostContext,
    ) -> Result<RunResult> {
        let _ = (source, invocation, limits, host);
        Err(AfterburnerError::Engine(
            "run_with_result not supported by this backend".into(),
        ))
    }

    /// Register a pre-compiled self-contained (SEALED) WASM module and
    /// return a [`ScriptId`] that [`thrust`](Self::thrust) dispatches
    /// through the sealed execution path. The module must read JSON from
    /// stdin and write JSON to stdout (the WASI command pattern).
    ///
    /// `target` is the `[runtime] target` string from the `.afb` manifest.
    /// Only `"wasm32-wasip1"` (sealed, self-contained) is accepted.
    /// `"wasm32-wasip1-dyn"` is explicitly rejected with a clear
    /// not-yet-supported error - there is no silent bypass of capability
    /// gating.
    ///
    /// Registration is content-addressed: calling this twice with identical
    /// `wasm` bytes returns the same `ScriptId` and skips re-compilation.
    ///
    /// Default impl returns an error - only `WasmCombustor` supports this
    /// path. Native and adaptive combustors inherit this default.
    fn register_precompiled(&self, wasm: &[u8], target: &str) -> Result<ScriptId> {
        let _ = (wasm, target);
        Err(AfterburnerError::Engine(
            "register_precompiled not supported by this backend (wasm feature required)".into(),
        ))
    }

    /// Raw-bytes in / raw-bytes out path for sealed precompiled modules.
    /// Feeds `input` directly to the module's stdin without JSON
    /// serialization, and returns the raw stdout bytes without parsing.
    /// Used by the batch and columnar precompiled paths, which encode
    /// their own wire format (JSON array or binary columnar frame) and
    /// need to read back the matching raw reply.
    ///
    /// Only `WasmCombustor` overrides this. The id must refer to a module
    /// registered via `register_precompiled` with target `"wasm32-wasip1"`.
    ///
    /// Default impl errors - non-wasm backends inherit it.
    fn thrust_sealed_raw_bytes(
        &self,
        id: &ScriptId,
        input: Vec<u8>,
        limits: &FuelGauge,
    ) -> Result<Vec<u8>> {
        let _ = (id, input, limits);
        Err(AfterburnerError::Engine(
            "thrust_sealed_raw_bytes not implemented for this backend".into(),
        ))
    }
}
