// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Integration tests exercising `FlowEngine` through its public API.

use afterburner_core::AfterburnerError;
use afterburner_flow::FlowEngine;
use afterburner_flow::chain::merge;
use serde_json::json;

fn make_engine() -> Option<FlowEngine> {
    Some(FlowEngine::new().unwrap())
}

macro_rules! engine_or_skip {
    () => {
        match make_engine() {
            Some(e) => e,
            None => return,
        }
    };
}

#[test]
fn execute_passes_full_input_to_module() {
    let engine = engine_or_skip!();
    let input = json!({
        "trigger":  { "payload": { "title": "Hello" } },
        "session":  { "user": "alice" },
        "env":      { "TZ": "UTC" },
        "$last":    { "id": 42 },
        "fetchUser":{ "name": "Alice", "active": true }
    });
    let source = r#"
        module.exports = function(input) {
            return {
                greeting:      'Hi ' + input.fetchUser.name,
                trigger_title: input.trigger.payload.title,
                prev_id:       input.$last.id,
            };
        };
    "#;
    let id = engine.load(source).unwrap();
    let result = engine.execute(&id, &input).unwrap();
    assert_eq!(
        result,
        json!({
            "greeting":      "Hi Alice",
            "trigger_title": "Hello",
            "prev_id":       42,
        })
    );
}

#[test]
fn merge_sets_step_key_and_last() {
    let chain = json!({
        "trigger":   { "event": "posts.update" },
        "fetchUser": { "name": "Alice" }
    });
    let result = json!({ "greeting": "Hi Alice" });
    let merged = merge(chain, "buildGreeting", result.clone());
    assert_eq!(merged["buildGreeting"], result);
    assert_eq!(merged["$last"], result);
    assert_eq!(merged["fetchUser"]["name"], json!("Alice"));
    assert_eq!(merged["trigger"]["event"], json!("posts.update"));
}

#[test]
fn script_exception_propagates_as_typed_error() {
    let engine = engine_or_skip!();
    let id = engine
        .load("module.exports = function(d) { throw new Error('boom'); };")
        .unwrap();
    let err = engine.execute(&id, &json!({})).unwrap_err();
    assert!(
        matches!(err, AfterburnerError::WasmTrap(_)),
        "expected WasmTrap on uncaught throw; got {err:?}"
    );
}

#[test]
fn no_global_mutation_across_runs() {
    let engine = engine_or_skip!();

    let poison = engine
        .load(
            r#"
            module.exports = function(d) {
                globalThis.__secret = 'leaked';
                return 'ok';
            };
            "#,
        )
        .unwrap();
    engine.execute(&poison, &json!({})).unwrap();

    let probe = engine
        .load(
            r#"
            module.exports = function(d) {
                return globalThis.__secret === undefined ? 'clean' : 'leaked';
            };
            "#,
        )
        .unwrap();
    let out = engine.execute(&probe, &json!({})).unwrap();
    assert_eq!(out, json!("clean"));
}

#[test]
fn caching_is_content_addressed() {
    let engine = engine_or_skip!();
    let src = "module.exports = (d) => d.n + 1";
    let id = engine.load(src).unwrap();
    engine.execute(&id, &json!({ "n": 1 })).unwrap();
    engine.execute(&id, &json!({ "n": 2 })).unwrap();
    engine.execute(&id, &json!({ "n": 3 })).unwrap();
    let (_, misses) = engine.cache_stats();
    assert_eq!(misses, 1);
}

#[test]
fn es2020_features_supported() {
    let engine = engine_or_skip!();
    let id = engine
        .load(
            r#"
            module.exports = function(input) {
                return {
                    missing: input?.nested?.missing ?? 'fallback',
                    present: input?.nested?.present ?? 'fallback',
                };
            };
            "#,
        )
        .unwrap();
    let out = engine
        .execute(&id, &json!({ "nested": { "present": "yes" } }))
        .unwrap();
    assert_eq!(out, json!({ "missing": "fallback", "present": "yes" }));
}
