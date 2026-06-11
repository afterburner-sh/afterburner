// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! child_process under the WASM sandbox via host proxy.
//!
//! Drives the public Afterburner facade in `wasm` mode (the default
//! engine selects adaptive on the second call; pin `EngineMode::Wasm`
//! up front to keep the test deterministic). The host fn is gated by
//! `Manifold::child_process` — sealed-default scripts get EACCES; an
//! enabled manifold lets the script reach `/usr/bin/env` and friends.
//!
//! Coverage:
//!  * `wasm_exec_sync_runs_real_command` — `/bin/echo hi` round-trips.
//!  * `wasm_exec_sync_captures_stderr` — stderr makes it back.
//!  * `wasm_exec_sync_propagates_nonzero_status` — `false` returns 1.
//!  * `wasm_exec_sync_blocked_when_manifold_seals` — sealed manifold
//!    surfaces a permission-denied error.
//!  * `wasm_spawn_sync_round_trip` — args array threading.
//!  * `wasm_spawn_sync_with_no_args` — empty argv works.

use afterburner::{Afterburner, EngineMode, FsAccess, Manifold, Mode};
use serde_json::json;

fn wasm_ab(child_process: bool) -> Afterburner {
    let mut m = Manifold::sealed();
    m.child_process = child_process;
    // Some shells/binaries probe /tmp etc. — give them at least a
    // permissive read for the duration of the test. The host fn
    // itself doesn't touch fs, but the spawned binary may.
    m.fs = FsAccess::ReadOnly(vec!["/".into()]);
    Afterburner::builder()
        .mode(Mode::Wasm)
        .manifold(m)
        .build()
        .expect("Afterburner wasm")
}

fn assert_wasm_id(id: &afterburner::core::ScriptId) {
    assert_eq!(id.mode, EngineMode::Wasm, "test must pin wasm mode");
}

#[test]
fn wasm_exec_sync_runs_real_command() {
    let ab = wasm_ab(true);
    let id = ab
        .register(
            "module.exports = () => {\n\
                const cp = require('child_process');\n\
                return cp.execSync('/bin/echo hello-wasm-cp').toString().trim();\n\
            }",
        )
        .expect("register");
    assert_wasm_id(&id);
    let out = ab.run(&id, &json!({})).expect("run echo");
    assert_eq!(out, json!("hello-wasm-cp"));
}

#[test]
fn wasm_exec_sync_captures_stderr() {
    let ab = wasm_ab(true);
    let id = ab
        .register(
            "module.exports = () => {\n\
                const cp = require('child_process');\n\
                // /bin/sh writes to stderr deterministically and exits 0.\n\
                const r = cp.spawnSync('/bin/sh', ['-c', 'echo to-stderr 1>&2; echo to-stdout']);\n\
                return { status: r.status, stdout: (r.stdout||'').trim(), stderr: (r.stderr||'').trim() };\n\
            }",
        )
        .expect("register");
    assert_wasm_id(&id);
    let out = ab.run(&id, &json!({})).expect("run sh");
    assert_eq!(out["status"], json!(0));
    assert_eq!(out["stdout"], json!("to-stdout"));
    assert_eq!(out["stderr"], json!("to-stderr"));
}

#[test]
fn wasm_exec_sync_propagates_nonzero_status() {
    let ab = wasm_ab(true);
    // /usr/bin/false exits 1; spawnSync surfaces it without throwing.
    let id = ab
        .register(
            "module.exports = () => {\n\
                const cp = require('child_process');\n\
                const r = cp.spawnSync('/usr/bin/false', []);\n\
                return r.status;\n\
            }",
        )
        .expect("register");
    let out = ab.run(&id, &json!({})).expect("run false");
    assert_eq!(out, json!(1));
}

#[test]
fn wasm_exec_sync_blocked_when_manifold_seals() {
    // child_process disabled. The polyfill calls __host_child_process_exec_sync
    // which goes through the manifold gate inside the host fn — the host
    // returns a PermissionDenied error which becomes EACCES on the JS side.
    let ab = wasm_ab(false);
    let id = ab
        .register(
            "module.exports = () => {\n\
                const cp = require('child_process');\n\
                try { cp.execSync('/bin/echo ok'); return 'NO_THROW'; }\n\
                catch (e) { return e.code || 'EOTHER'; }\n\
            }",
        )
        .expect("register");
    let out = ab.run(&id, &json!({})).expect("run");
    // The host fn returns PermissionDenied → polyfill reads
    // __HOST_ERR__:permission denied → maps to EACCES. The wasm path's
    // generic error envelope also lands as EACCES via the polyfill's
    // permission-denied substring check.
    assert_eq!(out, json!("EACCES"), "expected EACCES, got {out:?}");
}

#[test]
fn wasm_spawn_sync_round_trip() {
    // Verifies argv encoding survives the JSON round-trip across the
    // host import boundary. Use a multi-arg invocation that's only
    // well-defined when argv is preserved exactly.
    let ab = wasm_ab(true);
    let id = ab
        .register(
            "module.exports = () => {\n\
                const cp = require('child_process');\n\
                const r = cp.spawnSync('/bin/sh', ['-c', 'printf %s.%s.%s a b c']);\n\
                return r.stdout.toString();\n\
            }",
        )
        .expect("register");
    let out = ab.run(&id, &json!({})).expect("run");
    assert_eq!(out, json!("a.b.c"));
}

#[test]
fn wasm_spawn_sync_with_no_args() {
    // Empty argv array — should work fine.
    let ab = wasm_ab(true);
    let id = ab
        .register(
            "module.exports = () => {\n\
                const cp = require('child_process');\n\
                const r = cp.spawnSync('/bin/true', []);\n\
                return r.status;\n\
            }",
        )
        .expect("register");
    let out = ab.run(&id, &json!({})).expect("run");
    assert_eq!(out, json!(0));
}
