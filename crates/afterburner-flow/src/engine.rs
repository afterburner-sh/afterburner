// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `FlowEngine` — initialize once, then `load` / `execute` / `unload`
//! user-authored JS modules against a chain input.
//!
//! The user writes the familiar `module.exports = function(input) { ... }`
//! shape; the WASM sandbox wraps it in a Javy I/O envelope so input arrives
//! on stdin as JSON and the return value goes out on stdout as JSON.

use afterburner_core::{BurnCache, FuelGauge, Result, ScriptId};
use afterburner_wasi::{WasmCombustor, WasmConfig};
use serde_json::Value;

/// Build a single source string from an entry script and a list of
/// named helper modules. Each module is wrapped in a
/// `__register_module('name', function(module, exports, require) { ... })`
/// call so the existing plenum resolver picks it up. `require('./foo')`
/// inside the entry then resolves to the registered factory.
fn compose_bundle(entry: &str, modules: &[(String, String)]) -> String {
    let mut out = String::with_capacity(
        entry.len() + modules.iter().map(|(_, s)| s.len()).sum::<usize>() + 256,
    );
    for (name, body) in modules {
        out.push_str("__register_module(");
        out.push_str(&js_string_literal(name));
        out.push_str(", function(module, exports, require) {\n");
        out.push_str(body);
        out.push_str("\n});\n");
    }
    out.push_str(entry);
    out
}

fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Conservative defaults for an interactive flow step: 1 B fuel
/// (≈10 s of compute on typical scripts), 64 MiB max memory, 30 s wall.
pub fn default_fuel_gauge() -> FuelGauge {
    FuelGauge {
        fuel: Some(1_000_000_000),
        memory_bytes: Some(64 * 1024 * 1024),
        timeout_ms: Some(30_000),
        ..FuelGauge::default()
    }
}

/// One engine per process is the intended pattern. Modules are content-
/// addressed — calling `load` twice with the same source returns the same
/// `ScriptId` and compiles only once.
pub struct FlowEngine {
    cache: BurnCache,
    fuel: FuelGauge,
}

impl FlowEngine {
    /// Build the engine with default fuel/memory/timeout settings.
    pub fn new() -> Result<Self> {
        Self::with_config(WasmConfig::default(), default_fuel_gauge())
    }

    /// Build the engine with custom limits applied to every `execute` call.
    pub fn with_fuel(fuel: FuelGauge) -> Result<Self> {
        Self::with_config(WasmConfig::default(), fuel)
    }

    fn with_config(cfg: WasmConfig, fuel: FuelGauge) -> Result<Self> {
        let backend = WasmCombustor::new(cfg)?;
        Ok(Self {
            cache: BurnCache::new(Box::new(backend)),
            fuel,
        })
    }

    /// Compile and cache a module. Idempotent — the second call with the
    /// same source returns the same `ScriptId` and skips compilation.
    #[fastrace::trace(name = "FlowEngine::load")]
    pub fn load(&self, source: &str) -> Result<ScriptId> {
        self.cache.register(source)
    }

    /// Compile a bundle: an `entry` script plus a set of named helper
    /// modules that the entry can `require()`. Names are matched
    /// verbatim — `require('./foo')` resolves to the entry with key
    /// `"./foo"`. The whole bundle is hashed as one unit, so the same
    /// (entry, modules) inputs produce the same `ScriptId`.
    ///
    /// ```ignore
    /// engine.load_bundle(
    ///     "module.exports = (input) => require('./util').double(input.n);",
    ///     &[("./util".into(), "module.exports = { double: (n) => n * 2 };".into())],
    /// )?;
    /// ```
    #[fastrace::trace(name = "FlowEngine::load_bundle")]
    pub fn load_bundle(&self, entry: &str, modules: &[(String, String)]) -> Result<ScriptId> {
        self.cache.register(&compose_bundle(entry, modules))
    }

    /// Run a previously loaded module against a JSON input. Each call gets
    /// a fresh sandbox context — globals do not leak between runs.
    #[fastrace::trace(name = "FlowEngine::execute")]
    pub fn execute(&self, id: &ScriptId, input: &Value) -> Result<Value> {
        self.cache.execute(id, input, &self.fuel)
    }

    /// Drop a module from the cache and release backend resources.
    #[fastrace::trace(name = "FlowEngine::unload")]
    pub fn unload(&self, id: &ScriptId) {
        self.cache.forget(id);
    }

    /// `(hits, misses)` against the module cache.
    pub fn cache_stats(&self) -> (u64, u64) {
        let s = self.cache.stats();
        (s.hits(), s.misses())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::AfterburnerError;
    use serde_json::json;

    fn make_engine() -> Option<FlowEngine> {
        Some(FlowEngine::new().unwrap())
    }

    #[test]
    fn load_execute_chain_input() {
        let Some(engine) = make_engine() else { return };
        let input = json!({
            "trigger": { "payload": { "title": "Hello" } },
            "previousOp": { "value": 5 }
        });
        let source = r#"
            module.exports = function(input) {
                return { timesTwo: input.previousOp.value * 2 };
            };
        "#;
        let id = engine.load(source).unwrap();
        let result = engine.execute(&id, &input).unwrap();
        assert_eq!(result, json!({ "timesTwo": 10 }));
    }

    #[test]
    fn execute_scalar_return() {
        let Some(engine) = make_engine() else { return };
        let id = engine.load("module.exports = (d) => d.n + 1;").unwrap();
        assert_eq!(engine.execute(&id, &json!({ "n": 3 })).unwrap(), json!(4));
    }

    #[test]
    fn fs_method_call_without_manifold_throws() {
        // `require('fs')` returns a stub module even under
        // `Manifold::sealed` — the polyfill always loads — but invoking
        // a method throws `Permission denied` because the host globals
        // aren't wired.
        let Some(engine) = make_engine() else { return };
        let id = engine
            .load(
                r#"
                module.exports = () => {
                    try { require('fs').readFileSync('/tmp/x'); return 'unexpected'; }
                    catch (e) { return e.message; }
                };
                "#,
            )
            .unwrap();
        let out = engine.execute(&id, &json!({})).unwrap();
        let msg = out.as_str().unwrap().to_lowercase();
        assert!(
            msg.contains("permission denied") || msg.contains("not available"),
            "expected fs denial; got {msg}"
        );
    }

    #[test]
    fn load_is_idempotent_and_cache_hits_count() {
        let Some(engine) = make_engine() else { return };
        let src = "module.exports = (d) => d.n * 2;";
        let id1 = engine.load(src).unwrap();
        let id2 = engine.load(src).unwrap();
        assert_eq!(id1.hash, id2.hash);
        engine.execute(&id1, &json!({ "n": 1 })).unwrap();
        engine.execute(&id1, &json!({ "n": 2 })).unwrap();
        let (hits, misses) = engine.cache_stats();
        assert_eq!(misses, 1);
        assert_eq!(hits, 1);
    }

    #[test]
    fn unload_removes_module() {
        let Some(engine) = make_engine() else { return };
        let id = engine.load("module.exports = () => 1;").unwrap();
        engine.unload(&id);
        let err = engine.execute(&id, &json!(null)).unwrap_err();
        assert!(matches!(err, AfterburnerError::ScriptNotFound));
    }
}
