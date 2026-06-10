// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Integration tests for the result envelope: the ceiling-bounded
//! output capture (`FuelGauge::output_bytes`) and the raw-output fast
//! path (`Afterburner::run_out` / `run_raw_out` → `OutputValue`).
//!
//! Exercises the full chain on both result framings:
//!
//! * JSON: module return → `JSON.stringify` → stdout →
//!   `CapturePipe` (growable, ceiling-bounded) → `parse_output`.
//! * Raw: `Uint8Array` / `ArrayBuffer` return → `__AB_RAW_OUTPUT__` →
//!   `host_raw_output` import → `HostState::pending_raw_output` →
//!   `OutputValue::Bytes`.
//!
//! Plus the structured-overflow contract: results past the ceiling
//! fail with `AfterburnerError::OutputTooLarge`, never a bare trap.

use afterburner::{Afterburner, AfterburnerError, FuelGauge, OutputValue};
use serde_json::json;

const MIB: usize = 1024 * 1024;

fn ab() -> Afterburner {
    Afterburner::new().expect("build Afterburner")
}

fn ceiling(bytes: usize) -> FuelGauge {
    FuelGauge {
        output_bytes: Some(bytes),
        ..FuelGauge::unlimited()
    }
}

// ---- large JSON results (the old 1 MiB cliff) ---------------------------

#[test]
fn large_json_results_roundtrip() {
    // 2 / 8 / 32 MiB result strings — all dead at >1 MiB before the
    // ceiling-bounded capture (fd_write errno 29 inside
    // __ab_write_stdout → opaque trap).
    let burn = ab();
    let id = burn
        .register("module.exports = (d) => 'a'.repeat(d.n) + 'z'")
        .expect("register");
    for n in [2 * MIB, 8 * MIB, 32 * MIB] {
        let out = burn
            .run(&id, &json!({ "n": n }))
            .unwrap_or_else(|e| panic!("{n} byte result must roundtrip: {e}"));
        let s = out.as_str().expect("string result");
        assert_eq!(s.len(), n + 1);
        assert!(s.starts_with("aa"));
        assert!(s.ends_with("az"));
    }
}

#[test]
fn json_result_exactly_at_ceiling_passes() {
    // The ceiling is inclusive: a result line of exactly
    // `output_bytes` is a complete, legal result.
    let burn = ab();
    let id = burn
        .register("module.exports = (d) => 'a'.repeat(d.n)")
        .expect("register");
    // Result line = n chars + 2 quote bytes.
    let lim = ceiling(4096);
    let out = burn
        .run_with(&id, &json!({ "n": 4094 }), &lim)
        .expect("exact-fit result must pass");
    assert_eq!(out.as_str().map(str::len), Some(4094));
}

// ---- structured ceiling errors -------------------------------------------

#[test]
fn json_result_past_ceiling_is_structured_error() {
    let burn = ab();
    let id = burn
        .register("module.exports = (d) => 'a'.repeat(d.n)")
        .expect("register");
    let lim = ceiling(MIB);
    let err = burn
        .run_with(&id, &json!({ "n": 2 * MIB }), &lim)
        .expect_err("2 MiB result must exceed the 1 MiB ceiling");
    assert!(
        matches!(err, AfterburnerError::OutputTooLarge { limit } if limit == MIB),
        "expected OutputTooLarge {{ limit: 1 MiB }}, got: {err:?}"
    );
}

#[test]
fn raw_result_past_ceiling_is_structured_error() {
    let burn = ab();
    let id = burn
        .register("module.exports = (d) => new Uint8Array(d.n)")
        .expect("register");
    let lim = ceiling(MIB);
    let err = burn
        .run_out_with(&id, &json!({ "n": 2 * MIB }), &lim)
        .expect_err("2 MiB raw result must exceed the 1 MiB ceiling");
    assert!(
        matches!(err, AfterburnerError::OutputTooLarge { limit } if limit == MIB),
        "expected OutputTooLarge {{ limit: 1 MiB }}, got: {err:?}"
    );
}

#[test]
fn script_mode_stdout_past_ceiling_is_structured_error() {
    let burn = ab();
    let lim = ceiling(64 * 1024);
    let err = burn
        .run_script_with(
            "for (let i = 0; i < 1000; i++) console.log('x'.repeat(1024));",
            &afterburner::ScriptInvocation::default(),
            &lim,
        )
        .expect_err("~1 MB of console.log must exceed the 64 KiB ceiling");
    assert!(
        matches!(err, AfterburnerError::OutputTooLarge { limit } if limit == 64 * 1024),
        "expected OutputTooLarge {{ limit: 64 KiB }}, got: {err:?}"
    );
}

// ---- raw output path ------------------------------------------------------

#[test]
fn raw_bytes_out_identity() {
    // Echo: bytes in == bytes out, including 0x0A (the line framing
    // byte the JSON contract is built around), NULs, and invalid
    // UTF-8 sequences a string crossing would mangle.
    let burn = ab();
    let id = burn
        .register("module.exports = (b) => b")
        .expect("register");
    let mut payload: Vec<u8> = (0..=255u8).collect();
    payload.extend_from_slice(&[0x0a, 0x0a, 0x00, 0xff, 0xc3, 0x28, 0xe2, 0x28, 0xa1, 0x0a]);
    let out = burn.run_raw_out(&id, &payload).expect("run_raw_out");
    assert_eq!(out, OutputValue::Bytes(payload));
}

#[test]
fn raw_bytes_out_empty() {
    // Zero-length bytes are still a bytes-shaped result — distinct
    // from a JSON null.
    let burn = ab();
    let id = burn
        .register("module.exports = () => new Uint8Array(0)")
        .expect("register");
    let out = burn.run_raw_out(&id, &[1]).expect("run_raw_out");
    assert_eq!(out, OutputValue::Bytes(Vec::new()));
}

#[test]
fn arraybuffer_return_crosses_as_bytes() {
    let burn = ab();
    let id = burn
        .register(
            "module.exports = (b) => {\n\
                 const buf = new ArrayBuffer(4);\n\
                 new Uint8Array(buf).set([1, 2, 3, 10]);\n\
                 return buf;\n\
             }",
        )
        .expect("register");
    let out = burn.run_raw_out(&id, &[0]).expect("run_raw_out");
    assert_eq!(out, OutputValue::Bytes(vec![1, 2, 3, 10]));
}

#[test]
fn json_input_bytes_output() {
    // run_out: JSON-shaped input, bytes-shaped result.
    let burn = ab();
    let id = burn
        .register("module.exports = (d) => new TextEncoder().encode(d.s)")
        .expect("register");
    let out = burn
        .run_out(&id, &json!({ "s": "snÖwflake\n" }))
        .expect("run_out");
    assert_eq!(out, OutputValue::Bytes("snÖwflake\n".as_bytes().to_vec()));
}

#[test]
fn json_return_through_out_api_is_json() {
    let burn = ab();
    let id = burn
        .register("module.exports = (d) => ({ n: d.n + 1 })")
        .expect("register");
    let out = burn.run_out(&id, &json!({ "n": 41 })).expect("run_out");
    assert_eq!(out, OutputValue::Json(json!({ "n": 42 })));
}

#[test]
fn bytes_return_through_value_api_is_typed_error() {
    // The Value-shaped APIs (run / run_raw) cannot deliver raw bytes;
    // they surface the typed UnexpectedRawOutput instead of silently
    // mangling the result.
    let burn = ab();
    let id = burn
        .register("module.exports = () => new Uint8Array([1, 2, 3])")
        .expect("register");
    let err = burn
        .run(&id, &json!(null))
        .expect_err("bytes result through run() must be a typed error");
    assert!(
        matches!(err, AfterburnerError::UnexpectedRawOutput { len: 3 }),
        "expected UnexpectedRawOutput {{ len: 3 }}, got: {err:?}"
    );
}

#[test]
fn dual_framing_same_script_both_directions() {
    // One registered script (one compiled bytecode) serves all four
    // framing combinations: the input getter branches on the framing
    // flag, the result dispatch branches on the return type.
    let burn = ab();
    let id = burn
        .register(
            "module.exports = (d) =>\n\
                 (d instanceof Uint8Array) ? d\n\
                                           : { kind: 'json', n: d.n }",
        )
        .expect("register");
    let raw = burn.run_raw_out(&id, &[9, 0, 10]).expect("raw in/out");
    assert_eq!(raw, OutputValue::Bytes(vec![9, 0, 10]));
    let parsed = burn.run_out(&id, &json!({ "n": 7 })).expect("json in/out");
    assert_eq!(parsed, OutputValue::Json(json!({ "kind": "json", "n": 7 })));
}

#[test]
fn raw_result_within_ceiling_roundtrips_large() {
    // 16 MiB of patterned bytes through the full-duplex path.
    let burn = ab();
    let id = burn
        .register("module.exports = (b) => b")
        .expect("register");
    let payload: Vec<u8> = (0..16 * MIB).map(|i| (i % 251) as u8).collect();
    let out = burn.run_raw_out(&id, &payload).expect("run_raw_out 16 MiB");
    assert_eq!(out, OutputValue::Bytes(payload));
}

// ---- engine-mode coverage -------------------------------------------------

#[cfg(feature = "native")]
#[test]
fn out_api_native_mode_errors_cleanly() {
    use afterburner::Mode;
    let burn = Afterburner::builder()
        .mode(Mode::Native)
        .build()
        .expect("build native");
    let id = burn
        .register("module.exports = () => new Uint8Array(1)")
        .expect("register");
    let err = burn
        .run_raw_out(&id, &[1])
        .expect_err("native backend has no raw bridge");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("raw input"),
        "expected a raw-path diagnostic, got: {msg}"
    );
}

#[cfg(feature = "thrust")]
#[test]
fn out_api_works_on_threaded_engine() {
    let burn = Afterburner::builder()
        .threaded(2)
        .build()
        .expect("build threaded");
    let id = burn
        .register("module.exports = (b) => b")
        .expect("register");
    let out = burn.run_raw_out(&id, &[4, 5, 6]).expect("threaded raw out");
    assert_eq!(out, OutputValue::Bytes(vec![4, 5, 6]));
}

#[test]
fn builder_output_bytes_sets_default_ceiling() {
    let burn = Afterburner::builder()
        .output_bytes(8 * 1024)
        .build()
        .expect("build");
    let id = burn
        .register("module.exports = (d) => 'a'.repeat(d.n)")
        .expect("register");
    // Under the builder default ceiling: fails structured…
    let err = burn
        .run(&id, &json!({ "n": 16 * 1024 }))
        .expect_err("16 KiB result over an 8 KiB default ceiling");
    assert!(
        matches!(err, AfterburnerError::OutputTooLarge { limit } if limit == 8 * 1024),
        "expected OutputTooLarge {{ limit: 8 KiB }}, got: {err:?}"
    );
    // …and per-call limits still override upward.
    let out = burn
        .run_with(&id, &json!({ "n": 16 * 1024 }), &ceiling(64 * 1024))
        .expect("per-call ceiling override");
    assert_eq!(out.as_str().map(str::len), Some(16 * 1024));
}
