// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! L3 shadow tests - bcrypt.
//!
//! `require('bcrypt')` should work inside the WASM sandbox even
//! though upstream's native addon can't load. The shadow is backed
//! by the Rust `bcrypt` crate; this suite validates the surface
//! that the npm package documents: `hash{,Sync}`, `compare{,Sync}`,
//! `genSalt{,Sync}`, `getRounds`, `truncates`, and the callback /
//! Promise dual shape of the async API.

#![cfg(all(feature = "bin", feature = "shadow-bcrypt"))]

mod common;

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_burn_eval(src: &str) -> std::process::Output {
    common::run_burn_capped(
        &["-e", src],
        &[("BURN_QUIET", "1"), ("BURN_SHARDS", "2")],
        std::time::Duration::from_secs(60),
    )
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} FAILED\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn require_bcrypt_returns_a_module() {
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         console.log(typeof bcrypt.hashSync);\n\
         console.log(typeof bcrypt.compareSync);\n\
         console.log(typeof bcrypt.genSaltSync);\n\
         console.log(typeof bcrypt.hash);\n\
         console.log(typeof bcrypt.compare);\n\
         console.log(typeof bcrypt.genSalt);",
    );
    assert_ok(&out, "require('bcrypt')");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Six 'function' lines.
    let count = stdout.matches("function").count();
    assert!(count >= 6, "expected 6+ function exports, got: {stdout}");
}

#[test]
fn hashsync_produces_bcrypt_shaped_hash() {
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         // Cost 4 is the minimum bcrypt accepts - keeps the test fast.\n\
         const h = bcrypt.hashSync('hunter2', 4);\n\
         // bcrypt hashes start with $2 variants and carry the cost.\n\
         console.log(h.slice(0, 7));\n\
         console.log(h.length);",
    );
    assert_ok(&out, "hashSync");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("$2b$04$") || stdout.contains("$2a$04$") || stdout.contains("$2y$04$"),
        "hash prefix wrong: {stdout}"
    );
    // bcrypt hashes are exactly 60 chars.
    assert!(stdout.contains("60"), "hash length wrong: {stdout}");
}

#[test]
fn compare_sync_roundtrips() {
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         const h = bcrypt.hashSync('correct-password', 4);\n\
         console.log(bcrypt.compareSync('correct-password', h));\n\
         console.log(bcrypt.compareSync('wrong-password', h));",
    );
    assert_ok(&out, "compareSync round-trip");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["true", "false"], "round-trip shape: {stdout}");
}

#[test]
fn async_hash_returns_promise_and_resolves() {
    let out = run_burn_eval(
        "(async () => {\n\
             const bcrypt = require('bcrypt');\n\
             const h = await bcrypt.hash('pw', 4);\n\
             console.log(h.slice(0, 7));\n\
             const ok = await bcrypt.compare('pw', h);\n\
             console.log(ok);\n\
         })();",
    );
    assert_ok(&out, "async hash+compare");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("$2"), "hash prefix: {stdout}");
    assert!(stdout.contains("true"), "compare result: {stdout}");
}

#[test]
fn callback_api_for_async_hash() {
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         bcrypt.hash('pw', 4, function(err, h) {\n\
             if (err) { console.error('err:', err); process.exit(1); }\n\
             console.log('cb got 60-char hash:', h && h.length === 60);\n\
         });",
    );
    assert_ok(&out, "callback hash");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cb got 60-char hash: true"),
        "callback: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn gen_salt_sync_produces_bcrypt_salt() {
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         const salt = bcrypt.genSaltSync(4);\n\
         console.log(salt.length);\n\
         console.log(salt.slice(0, 7));",
    );
    assert_ok(&out, "genSaltSync");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // bcrypt salt strings are 29 chars: `$2b$CC$` + 22 bytes base64.
    assert!(stdout.contains("29"), "salt length wrong: {stdout}");
    assert!(
        stdout.contains("$2b$04$") || stdout.contains("$2a$04$") || stdout.contains("$2y$04$"),
        "salt prefix wrong: {stdout}"
    );
}

#[test]
fn get_rounds_parses_cost_from_hash() {
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         const h = bcrypt.hashSync('pw', 6);\n\
         console.log(bcrypt.getRounds(h));",
    );
    assert_ok(&out, "getRounds");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "6");
}

#[test]
fn truncates_detects_long_passwords() {
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         console.log(bcrypt.truncates('short'));\n\
         console.log(bcrypt.truncates('x'.repeat(72)));\n\
         console.log(bcrypt.truncates('x'.repeat(73)));",
    );
    assert_ok(&out, "truncates");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["false", "false", "true"], "truncates: {stdout}");
}

#[test]
fn unknown_hash_raises_error() {
    // Passing a malformed hash should raise a typed bcrypt error -
    // not return false, because that would mask bad inputs.
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         try {\n\
             bcrypt.compareSync('pw', 'not-a-real-bcrypt-hash');\n\
             console.log('BAD: did not throw');\n\
         } catch (e) {\n\
             console.log('code=' + e.code);\n\
         }",
    );
    assert_ok(&out, "malformed hash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("code=ERR_SHADOW_BCRYPT"),
        "expected ERR_SHADOW_BCRYPT code: {stdout}"
    );
}

#[test]
fn shadow_wins_over_node_modules_bcrypt() {
    // If a user's node_modules carries a real bcrypt package, the
    // shadow must still win - the real one has a .node addon that
    // can't load in the WASM sandbox. Simulate by materializing a
    // fake node_modules/bcrypt/ tree and confirming require returns
    // the shadow, not the fake.
    let dir = std::env::temp_dir().join(format!("burn_bcrypt_precedence_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("node_modules/bcrypt")).unwrap();
    std::fs::write(
        dir.join("node_modules/bcrypt/package.json"),
        r#"{"name":"bcrypt","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/bcrypt/index.js"),
        "module.exports = { shadowed: 'FAKE-USER-BCRYPT' };",
    )
    .unwrap();

    // vertexia: run_burn_capped does not accept current_dir; use Command directly.
    // Upgrade path: extend run_burn_capped with an optional cwd parameter.
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(&dir)
        .arg("-e")
        .arg(
            "const bcrypt = require('bcrypt');\n\
             // Shadow exposes hashSync; the fake package above doesn't.\n\
             console.log(typeof bcrypt.hashSync);\n\
             console.log(!!bcrypt.shadowed);",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let _ = std::fs::remove_dir_all(&dir);

    assert_ok(&out, "shadow precedence");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("function"), "shadow not resolved: {stdout}");
    assert!(
        stdout.contains("false"),
        "fake user bcrypt leaked through: {stdout}"
    );
}

#[test]
fn hash_of_same_password_produces_different_bcrypt_hashes() {
    // bcrypt's salt is random; two hashes of the same password
    // must differ. Confirms we're generating per-call salts, not
    // a fixed one.
    let out = run_burn_eval(
        "const bcrypt = require('bcrypt');\n\
         const a = bcrypt.hashSync('same-pw', 4);\n\
         const b = bcrypt.hashSync('same-pw', 4);\n\
         console.log(a === b);\n\
         // But both should still verify.\n\
         console.log(bcrypt.compareSync('same-pw', a));\n\
         console.log(bcrypt.compareSync('same-pw', b));",
    );
    assert_ok(&out, "random salt per call");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["false", "true", "true"], "lines: {stdout}");
}
