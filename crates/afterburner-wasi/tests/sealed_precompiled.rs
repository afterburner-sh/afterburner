// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Sealed precompiled-WASM path.
//!
//! Correctness proof: `register_precompiled(fixture)` + thrust produces the
//! same `serde_json::Value` as `ignite(source)` + thrust for the same inputs.
//!
//! Safety proof: `"wasm32-wasip1-dyn"` target is rejected with a clear
//! not-yet-supported error and never silently bypasses capability gating.
//!
//! The fixture (`fixtures/sealed_probe.{js,wasm}`) is a small, self-contained
//! sealed package; regenerate the wasm with `fixtures/build.sh`.

use afterburner_core::{Combustor, FuelGauge};
use afterburner_wasi::{WasmCombustor, WasmConfig};
use serde_json::{Value, json};

/// The sealed fixture module compiled to a self-contained WASM command
/// (wasi_snapshot_preview1 imports only, no `afterburner:host`).
const PROBE_SEALED_WASM: &[u8] = include_bytes!("fixtures/sealed_probe.wasm");

/// The same fixture's JS source, run through the in-process source path so the
/// two paths can be compared on identical inputs. Byte-identical to the source
/// the wasm fixture was built from.
const PROBE_SOURCE: &str = include_str!("fixtures/sealed_probe.js");

fn make_combustor() -> WasmCombustor {
    WasmCombustor::new(WasmConfig::default()).unwrap()
}

// ---- correctness: precompiled output == source output --------------------

/// Run both paths with a given input and assert the returned Values are equal.
fn assert_sealed_matches_source(input: &Value) {
    let c = make_combustor();
    let limits = FuelGauge::unlimited();

    // Source path.
    let src_id = c.ignite(PROBE_SOURCE).unwrap();
    let src_out = c.thrust(&src_id, input, &limits).unwrap();

    // Sealed (precompiled) path.
    let sealed_id = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    let sealed_out = c.thrust(&sealed_id, input, &limits).unwrap();

    assert_eq!(
        sealed_out, src_out,
        "sealed output differs from source output for input {input}\n  \
         sealed: {sealed_out}\n  source: {src_out}"
    );
}

#[test]
fn sealed_sum_op_matches_source() {
    // op:sum - an array fold, deterministic. Both paths must agree exactly.
    assert_sealed_matches_source(&json!({ "op": "sum", "values": [1, 2, 3, 4] }));
}

#[test]
fn sealed_bytelen_op_matches_source() {
    // op:bytelen - exercises TextEncoder (a builtin), deterministic.
    assert_sealed_matches_source(&json!({ "op": "bytelen", "text": "hello world" }));
}

#[test]
fn sealed_error_path_matches_source() {
    // Unknown op - both paths return { ok: false, error: "..." }.
    assert_sealed_matches_source(&json!({ "op": "nope" }));
}

#[test]
fn sealed_empty_values_matches_source() {
    // Edge case: empty values array.
    assert_sealed_matches_source(&json!({ "op": "sum", "values": [] }));
}

// ---- cache: second registration returns same ScriptId without re-compile ----

#[test]
fn register_precompiled_is_idempotent() {
    let c = make_combustor();
    let id1 = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    let id2 = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    assert_eq!(
        id1.hash, id2.hash,
        "second registration of identical bytes must return the same hash"
    );
}

// ---- safety: dyn target is explicitly rejected ---------------------------

#[test]
fn register_precompiled_dyn_target_returns_not_yet_supported_error() {
    let c = make_combustor();
    // Feed arbitrary wasm bytes - the target check fires before module
    // compilation, so we don't need a real dynamically-linked module.
    let err = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1-dyn")
        .unwrap_err();

    match err {
        afterburner_core::AfterburnerError::Engine(ref msg) => {
            assert!(
                msg.contains("wasm32-wasip1-dyn") && msg.contains("not yet supported"),
                "error message must name the target and say 'not yet supported', got: {msg}"
            );
        }
        other => panic!("expected Engine error for dyn target, got: {other:?}"),
    }
}

// ---- robustness: unknown-ScriptId on the sealed path yields ScriptNotFound -

#[test]
fn sealed_thrust_unknown_id_returns_script_not_found() {
    use afterburner_core::{AfterburnerError, EngineMode, ScriptId};

    let c = make_combustor();
    let bogus = ScriptId {
        hash: [0u8; 32],
        mode: EngineMode::Wasm,
    };
    // Register the sealed module, then thrust an unrelated (bogus) id: it is in
    // neither cache, so thrust must fail cleanly with ScriptNotFound - the same
    // contract as the source path.
    let _ = c
        .register_precompiled(PROBE_SEALED_WASM, "wasm32-wasip1")
        .unwrap();
    let err = c
        .thrust(&bogus, &json!(null), &FuelGauge::unlimited())
        .unwrap_err();
    assert!(
        matches!(err, AfterburnerError::ScriptNotFound),
        "expected ScriptNotFound for unregistered id, got {err:?}"
    );
}
