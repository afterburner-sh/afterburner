// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `v8.serialize` / `v8.deserialize` host bridge.
//!
//! The JS adapter walks the value tree and produces a typed JSON
//! description (small enough to cross the host boundary as a string,
//! and binary chunks come through base64-encoded). This module parses
//! the JSON, converts it to a `V8Value`, and calls into `v8_serde`
//! for the actual wire-format encoding. The reverse path decodes the
//! V8 wire format and returns a typed JSON description that the JS
//! side reconstructs into JS values.

use afterburner_core::{AfterburnerError, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::v8_serde::{self, V8Value};

/// JS sends a JSON tree describing the value; we emit base64-encoded
/// V8 wire bytes (or `__HOST_ERR__:<msg>` on failure).
pub fn serialize_json(json: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| AfterburnerError::Host(format!("v8.serialize: bad json: {e}")))?;
    let value = json_to_v8(&v)?;
    let bytes = v8_serde::encode(&value)?;
    Ok(B64.encode(&bytes))
}

/// JS sends base64-encoded V8 wire bytes; we emit a JSON tree.
pub fn deserialize_to_json(b64_bytes: &str) -> Result<String> {
    let bytes = B64
        .decode(b64_bytes.trim())
        .map_err(|e| AfterburnerError::Host(format!("v8.deserialize: bad base64: {e}")))?;
    let value = v8_serde::decode(&bytes)?;
    Ok(v8_to_json(&value).to_string())
}

fn json_to_v8(j: &serde_json::Value) -> Result<V8Value> {
    use serde_json::Value as J;
    let obj = j
        .as_object()
        .ok_or_else(|| AfterburnerError::Host("v8.serialize: tree node must be object".into()))?;
    let t = obj
        .get("t")
        .and_then(|x| x.as_str())
        .ok_or_else(|| AfterburnerError::Host("v8.serialize: tree node missing 't'".into()))?;
    match t {
        "u" => Ok(V8Value::Undefined),
        "n" => Ok(V8Value::Null),
        "b" => Ok(V8Value::Bool(obj["v"].as_bool().unwrap_or(false))),
        "i" => {
            let n = obj["v"]
                .as_i64()
                .ok_or_else(|| AfterburnerError::Host("v8.serialize: i32 missing".into()))?;
            Ok(V8Value::Int32(n as i32))
        }
        "U" => {
            let n = obj["v"]
                .as_u64()
                .ok_or_else(|| AfterburnerError::Host("v8.serialize: u32 missing".into()))?;
            Ok(V8Value::Uint32(n as u32))
        }
        "d" => {
            // Doubles arrive as either a JSON number or a string for
            // NaN/Infinity (JSON has no native representation).
            let v = match &obj["v"] {
                J::Number(n) => n.as_f64().unwrap_or(0.0),
                J::String(s) => s.parse::<f64>().unwrap_or(match s.as_str() {
                    "Infinity" => f64::INFINITY,
                    "-Infinity" => f64::NEG_INFINITY,
                    "NaN" => f64::NAN,
                    _ => 0.0,
                }),
                _ => 0.0,
            };
            Ok(V8Value::Double(v))
        }
        "s" => Ok(V8Value::String(
            obj["v"].as_str().unwrap_or_default().to_string(),
        )),
        "D" => {
            let ms = obj["v"].as_f64().unwrap_or(0.0);
            Ok(V8Value::Date(ms))
        }
        "R" => Ok(V8Value::RegExp {
            pattern: obj["p"].as_str().unwrap_or_default().to_string(),
            flags: obj["f"].as_u64().unwrap_or(0) as u32,
        }),
        "o" => {
            let entries = obj["e"]
                .as_array()
                .ok_or_else(|| AfterburnerError::Host("v8.serialize: object 'e' missing".into()))?;
            let mut out = Vec::with_capacity(entries.len());
            for kv in entries {
                let pair = kv
                    .as_array()
                    .ok_or_else(|| AfterburnerError::Host("v8.serialize: kv pair".into()))?;
                let k = pair[0].as_str().unwrap_or_default().to_string();
                let v = json_to_v8(&pair[1])?;
                out.push((k, v));
            }
            Ok(V8Value::Object(out))
        }
        "a" => {
            let items = obj["v"]
                .as_array()
                .ok_or_else(|| AfterburnerError::Host("v8.serialize: array 'v' missing".into()))?;
            let out = items.iter().map(json_to_v8).collect::<Result<Vec<_>>>()?;
            Ok(V8Value::DenseArray(out))
        }
        "S" => {
            let length = obj["l"].as_u64().unwrap_or(0) as u32;
            let entries = obj["e"]
                .as_array()
                .ok_or_else(|| AfterburnerError::Host("v8.serialize: sparse 'e' missing".into()))?;
            let mut out = Vec::with_capacity(entries.len());
            for kv in entries {
                let pair = kv
                    .as_array()
                    .ok_or_else(|| AfterburnerError::Host("v8.serialize: sparse pair".into()))?;
                let idx = pair[0].as_u64().unwrap_or(0) as u32;
                let v = json_to_v8(&pair[1])?;
                out.push((idx, v));
            }
            Ok(V8Value::SparseArray {
                length,
                entries: out,
            })
        }
        "m" => {
            let entries = obj["e"]
                .as_array()
                .ok_or_else(|| AfterburnerError::Host("v8.serialize: map 'e' missing".into()))?;
            let mut out = Vec::with_capacity(entries.len());
            for kv in entries {
                let pair = kv
                    .as_array()
                    .ok_or_else(|| AfterburnerError::Host("v8.serialize: map pair".into()))?;
                let k = json_to_v8(&pair[0])?;
                let v = json_to_v8(&pair[1])?;
                out.push((k, v));
            }
            Ok(V8Value::Map(out))
        }
        "e" => {
            let items = obj["v"]
                .as_array()
                .ok_or_else(|| AfterburnerError::Host("v8.serialize: set 'v' missing".into()))?;
            Ok(V8Value::Set(
                items.iter().map(json_to_v8).collect::<Result<Vec<_>>>()?,
            ))
        }
        "B" => {
            let raw = obj["v"].as_str().unwrap_or_default();
            let bytes = B64
                .decode(raw)
                .map_err(|e| AfterburnerError::Host(format!("v8.serialize: AB b64: {e}")))?;
            Ok(V8Value::ArrayBuffer(bytes))
        }
        "V" => {
            let kind = obj["k"].as_u64().unwrap_or(0) as u8;
            let raw = obj["b"].as_str().unwrap_or_default();
            let buffer = B64
                .decode(raw)
                .map_err(|e| AfterburnerError::Host(format!("v8.serialize: ABV b64: {e}")))?;
            let byte_offset = obj["o"].as_u64().unwrap_or(0) as u32;
            let byte_length = obj["l"].as_u64().unwrap_or(buffer.len() as u64) as u32;
            Ok(V8Value::TypedArray {
                kind,
                buffer,
                byte_offset,
                byte_length,
            })
        }
        "E" => Ok(V8Value::Error {
            kind: obj["k"].as_u64().unwrap_or(b'E' as u64) as u8,
            message: obj.get("m").and_then(|m| m.as_str()).map(String::from),
            stack: obj.get("s").and_then(|s| s.as_str()).map(String::from),
        }),
        "Z" => {
            let negative = obj["n"].as_bool().unwrap_or(false);
            let hex_digits = obj["d"].as_str().unwrap_or_default();
            let digits = hex::decode(hex_digits)
                .map_err(|e| AfterburnerError::Host(format!("v8.serialize: bigint hex: {e}")))?;
            Ok(V8Value::BigInt { negative, digits })
        }
        other => Err(AfterburnerError::Host(format!(
            "v8.serialize: unknown tree tag '{other}'"
        ))),
    }
}

fn v8_to_json(v: &V8Value) -> serde_json::Value {
    use serde_json::json;
    match v {
        V8Value::Undefined => json!({"t":"u"}),
        V8Value::Null => json!({"t":"n"}),
        V8Value::Bool(b) => json!({"t":"b","v":b}),
        V8Value::Int32(n) => json!({"t":"i","v":n}),
        V8Value::Uint32(n) => json!({"t":"U","v":n}),
        V8Value::Double(d) => {
            if d.is_finite() {
                json!({"t":"d","v":d})
            } else if d.is_nan() {
                json!({"t":"d","v":"NaN"})
            } else if d.is_sign_positive() {
                json!({"t":"d","v":"Infinity"})
            } else {
                json!({"t":"d","v":"-Infinity"})
            }
        }
        V8Value::String(s) => json!({"t":"s","v":s}),
        V8Value::Date(ms) => {
            if ms.is_finite() {
                json!({"t":"D","v":ms})
            } else {
                json!({"t":"D","v":"NaN"})
            }
        }
        V8Value::RegExp { pattern, flags } => json!({"t":"R","p":pattern,"f":flags}),
        V8Value::Object(entries) => {
            let e: Vec<_> = entries
                .iter()
                .map(|(k, v)| json!([k, v8_to_json(v)]))
                .collect();
            json!({"t":"o","e":e})
        }
        V8Value::DenseArray(items) => {
            let v: Vec<_> = items.iter().map(v8_to_json).collect();
            json!({"t":"a","v":v})
        }
        V8Value::SparseArray { length, entries } => {
            let e: Vec<_> = entries
                .iter()
                .map(|(i, v)| json!([i, v8_to_json(v)]))
                .collect();
            json!({"t":"S","l":length,"e":e})
        }
        V8Value::Map(entries) => {
            let e: Vec<_> = entries
                .iter()
                .map(|(k, v)| json!([v8_to_json(k), v8_to_json(v)]))
                .collect();
            json!({"t":"m","e":e})
        }
        V8Value::Set(items) => {
            let v: Vec<_> = items.iter().map(v8_to_json).collect();
            json!({"t":"e","v":v})
        }
        V8Value::ArrayBuffer(bytes) => json!({"t":"B","v":B64.encode(bytes)}),
        V8Value::TypedArray {
            kind,
            buffer,
            byte_offset,
            byte_length,
        } => {
            json!({"t":"V","k":kind,"b":B64.encode(buffer),"o":byte_offset,"l":byte_length})
        }
        V8Value::Error {
            kind,
            message,
            stack,
        } => {
            let mut obj = serde_json::Map::new();
            obj.insert("t".into(), json!("E"));
            obj.insert("k".into(), json!(kind));
            if let Some(m) = message {
                obj.insert("m".into(), json!(m));
            }
            if let Some(s) = stack {
                obj.insert("s".into(), json!(s));
            }
            serde_json::Value::Object(obj)
        }
        V8Value::BigInt { negative, digits } => {
            json!({"t":"Z","n":negative,"d":hex::encode(digits)})
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jround(json: &str) -> String {
        let bytes = serialize_json(json).unwrap();
        deserialize_to_json(&bytes).unwrap()
    }

    #[test]
    fn primitives_round_trip_through_json_bridge() {
        assert_eq!(jround(r#"{"t":"u"}"#), r#"{"t":"u"}"#);
        assert_eq!(jround(r#"{"t":"n"}"#), r#"{"t":"n"}"#);
        assert_eq!(jround(r#"{"t":"b","v":true}"#), r#"{"t":"b","v":true}"#);
        assert_eq!(jround(r#"{"t":"i","v":-7}"#), r#"{"t":"i","v":-7}"#);
        assert_eq!(jround(r#"{"t":"s","v":"abc"}"#), r#"{"t":"s","v":"abc"}"#);
    }

    #[test]
    fn double_infinity_round_trips_via_string_marker() {
        assert_eq!(
            jround(r#"{"t":"d","v":"Infinity"}"#),
            r#"{"t":"d","v":"Infinity"}"#
        );
    }

    #[test]
    fn nested_object_round_trips() {
        let r = jround(r#"{"t":"o","e":[["k",{"t":"i","v":1}]]}"#);
        assert!(r.contains(r#""t":"o""#));
        assert!(r.contains(r#""k""#));
        assert!(r.contains(r#""v":1"#));
    }

    #[test]
    fn malformed_json_input_errors() {
        assert!(serialize_json("{not-json").is_err());
    }

    #[test]
    fn unknown_tree_tag_errors() {
        assert!(serialize_json(r#"{"t":"BOGUS"}"#).is_err());
    }
}
