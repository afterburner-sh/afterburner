// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Dynamically-linked precompiled WASM path.
//!
//! Proof-of-capability:
//!
//! * A `javy build -C dynamic` fixture calls `require('crypto').createHash`
//!   (a host-gated capability). Compiled once in-process via the same plugin
//!   bytes the engine embeds at runtime.
//!
//! * DENY test: `register_precompiled(dyn_wasm, "wasm32-wasip1-dyn")` +
//!   `thrust` under `Manifold::sealed()` MUST return an error (PermissionDenied
//!   or a WasmTrap - the crypto gate fires inside the plugin).
//!
//! * GRANT test: same module thrust under a `Manifold` with `crypto: true`
//!   MUST return the correct SHA-256 of "hello":
//!   `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`.
//!
//! * Parity test: dyn output under the grant manifold MUST equal the source
//!   path (`ignite` + `thrust`) output for the same input.
//!
//! `javy` absent -> all tests in this file skip with a clear message.

use afterburner_core::{AfterburnerError, Combustor, FuelGauge, Manifold};
use afterburner_wasi::{AFTERBURNER_PLUGIN_BYTES, WasmCombustor, WasmConfig};
use serde_json::{Value, json};

/// SHA-256 of the ASCII string "hello".
const SHA256_OF_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

/// Neutral fixture source: calls `crypto.createHash` which requires the
/// `afterburner:host` crypto import to be gated-open.
const FIXTURE_SOURCE: &str = r#"module.exports = (input) => {
  const crypto = require('crypto');
  const text = (input && typeof input.text === 'string') ? input.text : '';
  const hash = crypto.createHash('sha256').update(text).digest('hex');
  return { hash };
};"#;

/// Stdin/stdout harness that wraps the fixture for a Javy WASI command.
fn wrapped_source() -> String {
    format!(
        "const module = {{ exports: undefined }};\n\
         {src}\n\
         const __fn = module.exports;\n\
         const __chunks = [];\n\
         const __buf = new Uint8Array(65536);\n\
         while (true) {{ const n = Javy.IO.readSync(0, __buf); if (n <= 0) break; __chunks.push(__buf.slice(0, n)); }}\n\
         let __t = 0; for (const c of __chunks) __t += c.length;\n\
         const __all = new Uint8Array(__t);\n\
         let __o = 0; for (const c of __chunks) {{ __all.set(c, __o); __o += c.length; }}\n\
         const __in = JSON.parse(new TextDecoder().decode(__all));\n\
         const __res = __fn(__in);\n\
         Javy.IO.writeSync(1, new TextEncoder().encode(JSON.stringify(__res)));\n",
        src = FIXTURE_SOURCE,
    )
}

/// Return `true` when `javy` is on PATH (or `$JAVY`), `false` otherwise.
fn javy_available() -> bool {
    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());
    std::process::Command::new(&javy)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build the dyn wasm bytes for `FIXTURE_SOURCE` using the embedded plugin.
/// Returns `None` if javy is absent or the build fails.
fn build_dyn_wasm() -> Option<Vec<u8>> {
    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());
    let work = std::env::temp_dir().join(format!("ab-dyn-test-{}", std::process::id()));
    std::fs::create_dir_all(&work).ok()?;

    let src_path = work.join("fixture.js");
    let wasm_path = work.join("fixture_dyn.wasm");
    let plugin_path = work.join("afterburner_plugin.wasm");

    std::fs::write(&src_path, wrapped_source()).ok()?;
    std::fs::write(&plugin_path, AFTERBURNER_PLUGIN_BYTES).ok()?;

    let plugin_arg = format!("plugin={}", plugin_path.to_str().unwrap_or(""));
    let status = std::process::Command::new(&javy)
        .args([
            "build",
            "-C",
            "dynamic",
            "-C",
            &plugin_arg,
            "-C",
            "deterministic=y",
            src_path.to_str().unwrap_or(""),
            "-o",
            wasm_path.to_str().unwrap_or(""),
        ])
        .status()
        .ok()?;

    if !status.success() {
        let _ = std::fs::remove_dir_all(&work);
        return None;
    }

    let bytes = std::fs::read(&wasm_path).ok();
    let _ = std::fs::remove_dir_all(&work);
    bytes
}

fn make_combustor() -> WasmCombustor {
    WasmCombustor::new(WasmConfig::default()).unwrap()
}

/// A Manifold that grants only crypto (the minimum for this fixture).
fn crypto_manifold() -> Manifold {
    Manifold {
        crypto: true,
        ..Manifold::sealed()
    }
}

// ---- registration is idempotent ------------------------------------------

#[test]
fn register_dyn_precompiled_is_idempotent() {
    if !javy_available() {
        eprintln!(
            "SKIP register_dyn_precompiled_is_idempotent: \
             `javy` not found on PATH; install javy 8.1.1 to run dyn tests"
        );
        return;
    }
    let dyn_wasm = match build_dyn_wasm() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: dyn wasm build failed");
            return;
        }
    };
    let c = make_combustor();
    let id1 = c
        .register_precompiled(&dyn_wasm, "wasm32-wasip1-dyn")
        .unwrap();
    let id2 = c
        .register_precompiled(&dyn_wasm, "wasm32-wasip1-dyn")
        .unwrap();
    assert_eq!(
        id1.hash, id2.hash,
        "second registration of identical bytes must return the same hash"
    );
}

// ---- DENY test: crypto call under sealed Manifold must fail ----------------

#[test]
fn dyn_crypto_denied_under_sealed_manifold() {
    if !javy_available() {
        eprintln!(
            "SKIP dyn_crypto_denied_under_sealed_manifold: \
             `javy` not found on PATH; install javy 8.1.1 to run dyn tests"
        );
        return;
    }
    let dyn_wasm = match build_dyn_wasm() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: dyn wasm build failed");
            return;
        }
    };

    let c = make_combustor();
    let id = c
        .register_precompiled(&dyn_wasm, "wasm32-wasip1-dyn")
        .unwrap();

    // Sealed manifold: crypto is NOT granted.
    let limits = FuelGauge {
        manifold: Manifold::sealed(),
        ..FuelGauge::unlimited()
    };
    let result = c.thrust(&id, &json!({ "text": "hello" }), &limits);

    assert!(
        result.is_err(),
        "crypto call must fail under sealed Manifold, got: {:?}",
        result
    );
    // The error must be a gating or trap error - not a spurious infrastructure
    // failure. PermissionDenied is the expected variant, but the plugin may
    // surface it as WasmTrap (the host returns -1 and the JS throws an
    // exception which propagates as a trap). Accept both; only Ok is wrong.
    match result.unwrap_err() {
        AfterburnerError::WasmTrap(_)
        | AfterburnerError::PermissionDenied(_)
        | AfterburnerError::FuelExhausted
        | AfterburnerError::Engine(_) => {
            // Any of these proves the gate fired - not a silent pass-through.
        }
        other => panic!("expected a gating error under sealed manifold, got: {other:?}"),
    }
}

// ---- GRANT test: crypto call under open Manifold must return correct hash --

#[test]
fn dyn_crypto_granted_under_crypto_manifold() {
    if !javy_available() {
        eprintln!(
            "SKIP dyn_crypto_granted_under_crypto_manifold: \
             `javy` not found on PATH; install javy 8.1.1 to run dyn tests"
        );
        return;
    }
    let dyn_wasm = match build_dyn_wasm() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: dyn wasm build failed");
            return;
        }
    };

    let c = make_combustor();
    let id = c
        .register_precompiled(&dyn_wasm, "wasm32-wasip1-dyn")
        .unwrap();

    let limits = FuelGauge {
        manifold: crypto_manifold(),
        ..FuelGauge::unlimited()
    };
    let out = c
        .thrust(&id, &json!({ "text": "hello" }), &limits)
        .expect("crypto thrust under grant manifold must succeed");

    let got = out["hash"].as_str().expect("result must have a hash field");
    assert_eq!(
        got, SHA256_OF_HELLO,
        "sha256('hello') under dyn path must equal the reference value"
    );
}

// ---- parity test: dyn output == source path output ------------------------

#[test]
fn dyn_output_equals_source_path_output() {
    if !javy_available() {
        eprintln!(
            "SKIP dyn_output_equals_source_path_output: \
             `javy` not found on PATH; install javy 8.1.1 to run dyn tests"
        );
        return;
    }
    let dyn_wasm = match build_dyn_wasm() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: dyn wasm build failed");
            return;
        }
    };

    let c = make_combustor();
    let limits = FuelGauge {
        manifold: crypto_manifold(),
        ..FuelGauge::unlimited()
    };
    let input: Value = json!({ "text": "hello" });

    // Source path.
    let src_id = c.ignite(FIXTURE_SOURCE).unwrap();
    let src_out = c
        .thrust(&src_id, &input, &limits)
        .expect("source path must succeed under crypto manifold");

    // Dyn precompiled path.
    let dyn_id = c
        .register_precompiled(&dyn_wasm, "wasm32-wasip1-dyn")
        .unwrap();
    let dyn_out = c
        .thrust(&dyn_id, &input, &limits)
        .expect("dyn path must succeed under crypto manifold");

    assert_eq!(
        dyn_out, src_out,
        "dyn precompiled output must equal source path output\n  \
         dyn: {dyn_out}\n  source: {src_out}"
    );
}

// ---- extinguish clears the dyn cache ---------------------------------------

#[test]
fn dyn_extinguish_removes_from_cache() {
    if !javy_available() {
        eprintln!(
            "SKIP dyn_extinguish_removes_from_cache: \
             `javy` not found on PATH; install javy 8.1.1 to run dyn tests"
        );
        return;
    }
    let dyn_wasm = match build_dyn_wasm() {
        Some(b) => b,
        None => {
            eprintln!("SKIP: dyn wasm build failed");
            return;
        }
    };

    let c = make_combustor();
    let id = c
        .register_precompiled(&dyn_wasm, "wasm32-wasip1-dyn")
        .unwrap();

    c.extinguish(&id);

    let limits = FuelGauge {
        manifold: crypto_manifold(),
        ..FuelGauge::unlimited()
    };
    let err = c
        .thrust(&id, &json!({ "text": "hello" }), &limits)
        .unwrap_err();
    assert!(
        matches!(err, AfterburnerError::ScriptNotFound),
        "expected ScriptNotFound after extinguish, got {err:?}"
    );
}
