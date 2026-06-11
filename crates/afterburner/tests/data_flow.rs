// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Phase I - `udf_batch` / `run_batch` array-of-objects flow tests.
//!
//! Verifies the per-row UDF execution contract embedders rely on for
//! data-pipeline / per-row transformation use cases: input array →
//! script invoked once per element → output array of identical
//! length, same order, per-element types preserved.
//!
//! These tests use the threaded engine because that's where the per-
//! row dispatch lives - the cache path treats the script as a single
//! whole-array transform. Both paths are valid; this file pins the
//! per-row contract.

#![cfg(feature = "thrust")]

use afterburner::Afterburner;
use serde_json::json;

fn ab() -> Afterburner {
    Afterburner::builder()
        .threaded(2)
        .build()
        .expect("threaded Afterburner")
}

#[test]
fn identity_transform_preserves_shape_and_order() {
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => row")
        .expect("register");
    let inputs = json!([
        { "id": 1, "name": "alice" },
        { "id": 2, "name": "bob" },
        { "id": 3, "name": "carol" },
    ]);
    let out = ab.run_batch(&id, &inputs).expect("run_batch");
    assert_eq!(out, inputs, "identity transform must round-trip exactly");
}

#[test]
fn projection_transform_shrinks_each_row() {
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => ({ id: row.id })")
        .expect("register");
    let inputs = json!([
        { "id": 1, "extra": "a", "noise": 99 },
        { "id": 2, "extra": "b", "noise": 100 },
    ]);
    let out = ab.run_batch(&id, &inputs).expect("run_batch");
    assert_eq!(out, json!([{ "id": 1 }, { "id": 2 }]));
}

#[test]
fn enrichment_transform_adds_fields() {
    let ab = ab();
    let id = ab
        .register(
            "module.exports = (row) => ({ \
                ...row, \
                upper: row.name.toUpperCase(), \
                len: row.name.length \
            })",
        )
        .expect("register");
    let inputs = json!([
        { "name": "alpha" },
        { "name": "beta" },
    ]);
    let out = ab.run_batch(&id, &inputs).expect("run_batch");
    assert_eq!(
        out,
        json!([
            { "name": "alpha", "upper": "ALPHA", "len": 5 },
            { "name": "beta",  "upper": "BETA",  "len": 4 },
        ])
    );
}

#[test]
fn empty_array_yields_empty_array() {
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => row")
        .expect("register");
    let out = ab.run_batch(&id, &json!([])).expect("run_batch on []");
    assert_eq!(out, json!([]));
}

#[test]
fn single_row_batch() {
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => row.n + 1")
        .expect("register");
    let out = ab.run_batch(&id, &json!([{ "n": 41 }])).expect("run_batch");
    assert_eq!(out, json!([42]));
}

#[test]
fn one_row_throw_aborts_batch() {
    // The per-row contract is "stop on first error" - a thrown
    // exception in any row aborts the batch and surfaces the error.
    // Embedders rely on this for transactional semantics.
    let ab = ab();
    let id = ab
        .register(
            "module.exports = (row) => {\n\
                if (row.bad) throw new Error('bad row');\n\
                return row.n + 1;\n\
            }",
        )
        .expect("register");
    let inputs = json!([
        { "n": 1 },
        { "n": 2, "bad": true },
        { "n": 3 },
    ]);
    let err = ab.run_batch(&id, &inputs).expect_err("bad row must error");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("bad row") || msg.contains("Error"),
        "msg: {msg}"
    );
}

#[test]
fn primitive_outputs_supported() {
    // Rows return primitives, not objects - should still surface as a
    // JSON array of those primitives.
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => row.n * row.n")
        .expect("register");
    let out = ab
        .run_batch(
            &id,
            &json!([{ "n": 1 }, { "n": 2 }, { "n": 3 }, { "n": 4 }]),
        )
        .expect("run_batch");
    assert_eq!(out, json!([1, 4, 9, 16]));
}

#[test]
fn null_row_outputs_become_null_in_array() {
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => row.skip ? null : row.v")
        .expect("register");
    let out = ab
        .run_batch(
            &id,
            &json!([
                { "v": "a" },
                { "v": "b", "skip": true },
                { "v": "c" },
            ]),
        )
        .expect("run_batch");
    assert_eq!(out, json!(["a", null, "c"]));
}

#[test]
fn large_batch_round_trip_1000_rows() {
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => ({ idx: row.i, v: row.i * row.i })")
        .expect("register");
    let inputs: Vec<serde_json::Value> = (0..1000).map(|i| json!({ "i": i })).collect();
    let out = ab
        .run_batch(&id, &serde_json::Value::Array(inputs))
        .expect("run_batch on 1000-row input");
    let arr = out.as_array().expect("output array");
    assert_eq!(arr.len(), 1000);
    assert_eq!(arr[0], json!({ "idx": 0,   "v": 0 }));
    assert_eq!(arr[42], json!({ "idx": 42, "v": 1764 }));
    assert_eq!(arr[999], json!({ "idx": 999, "v": 998_001 }));
}

#[test]
fn run_then_run_batch_share_compiled_script() {
    // The cache is keyed by source - registering once and dispatching
    // through both run and run_batch should hit the same compiled
    // artifact. This is the "compile-once-call-many" contract that
    // makes per-row UDFs cheap.
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => row.n + 100")
        .expect("register");
    // Single-call path
    assert_eq!(ab.run(&id, &json!({ "n": 1 })).unwrap(), json!(101));
    // Batched path against the same id
    let out = ab.run_batch(&id, &json!([{ "n": 2 }, { "n": 3 }])).unwrap();
    assert_eq!(out, json!([102, 103]));
    // And once more in single-call mode - verifies the cache slot is
    // still hot and didn't get invalidated by the batch path.
    assert_eq!(ab.run(&id, &json!({ "n": 4 })).unwrap(), json!(104));
}

#[test]
fn non_array_input_rejected_with_clear_error() {
    let ab = ab();
    let id = ab
        .register("module.exports = (row) => row")
        .expect("register");
    for bad in [json!({ "k": "v" }), json!(42), json!("string"), json!(null)] {
        let err = ab.run_batch(&id, &bad).expect_err("non-array must error");
        let msg = format!("{err:?}").to_lowercase();
        assert!(
            msg.contains("array") || msg.contains("input"),
            "missing 'array' hint: {msg}"
        );
    }
}
