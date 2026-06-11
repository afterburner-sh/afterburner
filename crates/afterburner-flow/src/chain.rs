// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Chain helpers — utilities for callers that thread a JSON object
//! between flow steps.
//!
//! A common pattern: each step receives the full chain as input and
//! returns a value that the orchestrator merges back under that step's
//! key (plus a `$last` slot pointing at the most recent return).
//! [`merge`] performs that merge so callers don't reinvent it.

use serde_json::{Map, Value};

/// Merge `result` into `chain` under `step_key`, also setting `$last`.
/// Returns the updated chain. If `chain` is not a JSON object, a fresh
/// object containing just the new keys is returned.
pub fn merge(mut chain: Value, step_key: &str, result: Value) -> Value {
    if let Value::Object(ref mut map) = chain {
        map.insert(step_key.to_string(), result.clone());
        map.insert("$last".to_string(), result);
        return chain;
    }
    let mut map = Map::new();
    map.insert(step_key.to_string(), result.clone());
    map.insert("$last".to_string(), result);
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_sets_step_key_and_last() {
        let chain = json!({ "trigger": {"payload": "x"} });
        let merged = merge(chain, "double", json!({"value": 42}));
        assert_eq!(merged["trigger"], json!({"payload": "x"}));
        assert_eq!(merged["double"], json!({"value": 42}));
        assert_eq!(merged["$last"], json!({"value": 42}));
    }

    #[test]
    fn merge_synthesizes_object_when_chain_is_null() {
        let merged = merge(Value::Null, "op", json!(1));
        assert_eq!(merged["op"], json!(1));
        assert_eq!(merged["$last"], json!(1));
    }
}
