// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Deterministic record/replay of an async script by shimming the
//! nondeterministic globals from pure JS, with the engine sealed.
//!
//! This is a capability spike for embedders that want to re-run a
//! recorded async workload and get the exact same result, with no real
//! I/O on the second run. It exercises four properties of the embedding
//! API that such a use case depends on:
//!
//!   1. An `async` module entry that `await`s `fetch` and a
//!      `setTimeout`-based delay runs to completion in the one-shot
//!      `run_out` path (the event loop drains; the returned promise is
//!      awaited).
//!   2. A capture-safe prelude can replace `globalThis.fetch`,
//!      `Math.random`, `Date.now`, and `setTimeout` before the workload
//!      module body runs, so even a workload that captures those at
//!      load time gets the shimmed versions.
//!   3. Record then replay yields a byte-identical result, driven by a
//!      seed + a virtual clock + an in-memory response map - so the
//!      recording stays tiny (a seed and an origin, not every draw) and
//!      replay does no real I/O.
//!   4. A replay miss (a response not in the recording) fails loud, and
//!      `Manifold::sealed()` denies real filesystem access, so an
//!      un-shimmed surface cannot diverge silently.
//!
//! Run: `cargo run -p afterburner --example record_replay_spike`
//!
//! Design note surfaced by this spike: an interceptor must not perturb
//! the very sequences it intercepts. The record-mode `fetch` here draws
//! its body from a private counter, NOT from the (shimmed) `Math.random`
//! (otherwise record would consume PRNG draws that replay, serving the
//! body from the map, would not, and the workload's later `Math.random`
//! would desynchronise). The same rule applies to the virtual clock.

use afterburner::{Afterburner, Manifold, Mode, OutputValue};
use serde_json::{Value, json};

// The capture-safe prelude. Installs wrappers over the nondeterministic
// globals at module-load time; each wrapper consults state populated
// per-invocation by `__installState`, so the recording can arrive as
// input while the globals are still replaced before the workload loads.
const PRELUDE: &str = r#"
(function () {
  var __mode = null, __rec = null, __rng = null, __clock = 0, __fc = 0;
  globalThis.__installState = function (env) {
    __mode = env.mode;
    __rec = (env.mode === 'record')
      ? { seed: env.recording.seed, clockOrigin: env.recording.clockOrigin, http: {} }
      : env.recording;
    var s = __rec.seed >>> 0;                       // mulberry32 seeded PRNG
    __rng = function () {
      s |= 0; s = (s + 0x6D2B79F5) | 0;
      var t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    __clock = __rec.clockOrigin >>> 0;
    __fc = 0;
  };
  globalThis.__recOut = function () { return __rec; };
  Math.random = function () { return __rng(); };
  Date.now = function () { var v = __clock; __clock = (__clock + 1) >>> 0; return v; };
  globalThis.fetch = async function (url) {
    var key = String(url);
    if (__mode === 'replay') {
      if (!Object.prototype.hasOwnProperty.call(__rec.http, key)) {
        throw new Error('DIVERGENCE: no recorded response for ' + key);
      }
      var rbody = __rec.http[key];
      return { status: 200, json: async function () { return rbody; } };
    }
    var body = { echo: key, n: __fc++ };            // record: independent of PRNG/clock
    __rec.http[key] = body;
    return { status: 200, json: async function () { return body; } };
  };
  globalThis.setTimeout = function (fn, ms) {        // shim-owned: virtual clock + microtask
    __clock = (__clock + ((ms | 0))) >>> 0;
    Promise.resolve().then(fn);
    return 0;
  };
  globalThis.clearTimeout = function () {};
})();
"#;

// A representative async workload: two awaited fetches, a timer delay, a
// clock read, and a random draw. Captures `fetch` into a local at load
// time to prove the prelude shimmed it first.
const AGENT: &str = r#"
var __captured_fetch = fetch;
module.exports = async function (d) {
  var a = await __captured_fetch('https://api.example/1');
  var ja = await a.json();
  await new Promise(function (res) { setTimeout(res, 50); });
  var b = await __captured_fetch('https://api.example/2');
  var jb = await b.json();
  var t = Date.now();
  var rnd = Math.random();
  return { task: d.task, ja: ja, jb: jb, t: t, rnd: rnd };
};
"#;

// The wrapper installs per-invocation state, runs the workload, and
// frames the output as raw bytes (Uint8Array -> OutputValue::Bytes).
// Record mode also returns the captured recording alongside the result.
const WRAPPER: &str = r#"
(function () {
  var __agent = module.exports;
  module.exports = async function (env) {
    globalThis.__installState(env);
    var r = await __agent(env.agentInput);
    var enc = new TextEncoder();
    if (env.mode === 'record') {
      return enc.encode(JSON.stringify({ result: r, recording: globalThis.__recOut() }));
    }
    return enc.encode(JSON.stringify(r));
  };
})();
"#;

fn compose() -> String {
    format!("{PRELUDE}\n{AGENT}\n{WRAPPER}")
}

fn out_bytes(o: OutputValue) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match o {
        OutputValue::Bytes(b) => Ok(b),
        OutputValue::Json(v) => Ok(serde_json::to_vec(&v)?),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ab = Afterburner::builder()
        .mode(Mode::Wasm)
        .manifold(Manifold::sealed())
        .build()?;

    // One source, compiled once; the recording arrives as input.
    let id = ab.register(&compose())?;

    // 1) RECORD.
    let rec_input = json!({
        "mode": "record",
        "recording": { "seed": 305419896u64, "clockOrigin": 1_000_000u64 },
        "agentInput": { "task": "demo" }
    });
    let rec_bytes = out_bytes(ab.run_out(&id, &rec_input)?)?;
    let rec_doc: Value = serde_json::from_slice(&rec_bytes)?;
    let recording = rec_doc
        .get("recording")
        .cloned()
        .ok_or("no recording in record output")?;
    let rec_result = rec_doc
        .get("result")
        .cloned()
        .ok_or("no result in record output")?;
    println!(
        "1) record      -> result {}",
        serde_json::to_string(&rec_result)?
    );
    println!(
        "                  recording {}",
        serde_json::to_string(&recording)?
    );

    // 2) REPLAY twice. Two replays must be byte-identical to each other
    //    (pure determinism), and must reproduce the recorded result at
    //    the value level. The recorded result here was round-tripped
    //    through a second JSON serializer (serde re-sorts keys and can
    //    reformat a float's last digit), so the record-vs-replay check
    //    is value-level, not byte-level. Lesson for production: the
    //    trace must be canonicalized by one serializer, never compared
    //    across QuickJS-stringify and Rust-serde.
    let replay_input =
        json!({ "mode": "replay", "recording": recording, "agentInput": { "task": "demo" } });
    let b1 = out_bytes(ab.run_out(&id, &replay_input)?)?;
    let b2 = out_bytes(ab.run_out(&id, &replay_input)?)?;
    assert_eq!(
        b1, b2,
        "two replays of the same recording must be byte-identical"
    );
    let v1: Value = serde_json::from_slice(&b1)?;
    assert_eq!(v1, rec_result, "replay must reproduce the recorded result");
    println!("2) replay x2   -> byte-identical across runs + reproduces record: PASS");

    // 3) Perturbed recording (different seed) must change the result -
    //    proves the result genuinely depends on the shimmed surfaces.
    let mut perturbed = recording.clone();
    perturbed["seed"] = json!(987654321u64);
    let perturbed_input =
        json!({ "mode": "replay", "recording": perturbed, "agentInput": { "task": "demo" } });
    let vp: Value = serde_json::from_slice(&out_bytes(ab.run_out(&id, &perturbed_input)?)?)?;
    assert_ne!(
        vp, rec_result,
        "a different seed must produce a different result (else vacuous)"
    );
    println!("3) perturb seed -> result differs (non-vacuous): PASS");

    // 4) Divergence: drop a recorded response -> replay fails loud.
    let mut holed = recording.clone();
    holed["http"]
        .as_object_mut()
        .ok_or("http not an object")?
        .remove("https://api.example/2");
    let holed_input =
        json!({ "mode": "replay", "recording": holed, "agentInput": { "task": "demo" } });
    match ab.run_out(&id, &holed_input) {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("DIVERGENCE"),
                "expected a DIVERGENCE error, got: {msg}"
            );
            println!("4) replay miss  -> fails loud with DIVERGENCE: PASS");
        }
        Ok(_) => return Err("replay miss should have diverged, but it succeeded".into()),
    }

    // 5) Sealing backstop: a real filesystem read must be denied.
    let fs_agent = r#"module.exports = async function () {
        var fs = require('node:fs');
        return fs.readFileSync('/etc/hostname', 'utf8');
    };"#;
    let fs_id = ab.register(fs_agent)?;
    match ab.run(&fs_id, &json!(null)) {
        Err(e) => println!(
            "5) sealed fs     -> denied ({}): PASS",
            short(&format!("{e}"))
        ),
        Ok(v) => return Err(format!("sealed engine read the filesystem: {v}").into()),
    }

    println!("\nALL SPIKE CHECKS PASSED");
    Ok(())
}

fn short(s: &str) -> String {
    let one = s.lines().next().unwrap_or(s);
    if one.len() > 80 {
        format!("{}...", &one[..80])
    } else {
        one.to_string()
    }
}
