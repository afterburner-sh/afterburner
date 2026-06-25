// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! L3 shadow tests - argon2.
//!
//! Mirrors the bcrypt suite's structure: `require('argon2')` resolves
//! to the pure-Rust shadow backed by the `argon2` crate. All three
//! methods (`hash` / `verify` / `needsRehash`) are async per upstream.

#![cfg(all(feature = "bin", feature = "shadow-argon2"))]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_burn_eval(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_ok(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} FAILED\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---- module surface -----------------------------------------------------

#[test]
fn require_argon2_returns_a_module() {
    let out = run_burn_eval(
        "const argon2 = require('argon2');\n\
         console.log(typeof argon2.hash);\n\
         console.log(typeof argon2.verify);\n\
         console.log(typeof argon2.needsRehash);\n\
         console.log(argon2.argon2d);\n\
         console.log(argon2.argon2i);\n\
         console.log(argon2.argon2id);",
    );
    assert_ok(&out, "require('argon2')");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines,
        vec!["function", "function", "function", "0", "1", "2"],
        "module surface: {stdout}"
    );
}

// ---- hash + verify round-trip ------------------------------------------

#[test]
fn hash_produces_phc_format_default_argon2id() {
    // Use light params so the test runs fast. Default memoryCost
    // is 64 MiB, which is legit expensive for CI - override down.
    let out = run_burn_eval(
        "(async () => {\n\
             const argon2 = require('argon2');\n\
             const h = await argon2.hash('hunter2', {\n\
                 timeCost: 2, memoryCost: 2048, parallelism: 1\n\
             });\n\
             // Default is argon2id; expect `$argon2id$…` prefix.\n\
             console.log(h.slice(0, 10));\n\
             console.log(h.split('$').length);\n\
         })();",
    );
    assert_ok(&out, "hash → PHC");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("$argon2id$"),
        "expected argon2id prefix: {stdout}"
    );
    // Correctly-formed PHC strings have 6 dollar-separated sections
    // when split: leading empty + algo + params + salt + hash + …
    assert!(stdout.contains("6"), "PHC section count: {stdout}");
}

#[test]
fn verify_roundtrips() {
    let out = run_burn_eval(
        "(async () => {\n\
             const argon2 = require('argon2');\n\
             const h = await argon2.hash('secret', {\n\
                 timeCost: 2, memoryCost: 2048, parallelism: 1\n\
             });\n\
             console.log(await argon2.verify(h, 'secret'));\n\
             console.log(await argon2.verify(h, 'wrong'));\n\
         })();",
    );
    assert_ok(&out, "verify round-trip");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["true", "false"], "verify: {stdout}");
}

// ---- explicit type selection -------------------------------------------

#[test]
fn argon2i_variant_selected_via_type_option() {
    let out = run_burn_eval(
        "(async () => {\n\
             const argon2 = require('argon2');\n\
             const h = await argon2.hash('pw', {\n\
                 type: argon2.argon2i, timeCost: 2, memoryCost: 2048, parallelism: 1\n\
             });\n\
             console.log(h.slice(0, 9));\n\
             console.log(await argon2.verify(h, 'pw'));\n\
         })();",
    );
    assert_ok(&out, "argon2i hash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("$argon2i$"), "expected argon2i: {stdout}");
    assert!(stdout.contains("true"), "verify: {stdout}");
}

#[test]
fn argon2d_variant_selected_via_type_option() {
    let out = run_burn_eval(
        "(async () => {\n\
             const argon2 = require('argon2');\n\
             const h = await argon2.hash('pw', {\n\
                 type: argon2.argon2d, timeCost: 2, memoryCost: 2048, parallelism: 1\n\
             });\n\
             console.log(h.slice(0, 9));\n\
             console.log(await argon2.verify(h, 'pw'));\n\
         })();",
    );
    assert_ok(&out, "argon2d hash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("$argon2d$"), "expected argon2d: {stdout}");
    assert!(stdout.contains("true"), "verify: {stdout}");
}

// ---- needsRehash -------------------------------------------------------

#[test]
fn needs_rehash_detects_weaker_params() {
    // Hash with weak params, then ask needsRehash with stronger
    // defaults - should say yes.
    let out = run_burn_eval(
        "(async () => {\n\
             const argon2 = require('argon2');\n\
             const weak = await argon2.hash('pw', {\n\
                 timeCost: 2, memoryCost: 2048, parallelism: 1\n\
             });\n\
             console.log(await argon2.needsRehash(weak, {\n\
                 timeCost: 3, memoryCost: 65536, parallelism: 4\n\
             }));\n\
             console.log(await argon2.needsRehash(weak, {\n\
                 timeCost: 2, memoryCost: 2048, parallelism: 1\n\
             }));\n\
         })();",
    );
    assert_ok(&out, "needsRehash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["true", "false"], "needsRehash: {stdout}");
}

// ---- error shapes ------------------------------------------------------

#[test]
fn verify_rejects_malformed_hash() {
    let out = run_burn_eval(
        "(async () => {\n\
             const argon2 = require('argon2');\n\
             try {\n\
                 await argon2.verify('not-a-real-phc-hash', 'pw');\n\
                 console.log('BAD');\n\
             } catch (e) {\n\
                 console.log('code=' + e.code);\n\
             }\n\
         })();",
    );
    assert_ok(&out, "malformed hash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("code=ERR_SHADOW_ARGON2"),
        "expected ERR_SHADOW_ARGON2: {stdout}"
    );
}

// ---- shadow precedence --------------------------------------------------

#[test]
fn shadow_wins_over_node_modules_argon2() {
    let dir = std::env::temp_dir().join(format!("burn_argon2_precedence_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("node_modules/argon2")).unwrap();
    std::fs::write(
        dir.join("node_modules/argon2/package.json"),
        r#"{"name":"argon2","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/argon2/index.js"),
        "module.exports = { shadowed: 'FAKE-USER-ARGON2' };",
    )
    .unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(&dir)
        .arg("-e")
        .arg(
            "const argon2 = require('argon2');\n\
             console.log(typeof argon2.hash);\n\
             console.log(!!argon2.shadowed);",
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
        "fake user argon2 leaked through: {stdout}"
    );
}

// ---- random salt per call ----------------------------------------------

#[test]
fn hash_of_same_password_produces_different_phc_hashes() {
    let out = run_burn_eval(
        "(async () => {\n\
             const argon2 = require('argon2');\n\
             const opts = { timeCost: 2, memoryCost: 2048, parallelism: 1 };\n\
             const a = await argon2.hash('same-pw', opts);\n\
             const b = await argon2.hash('same-pw', opts);\n\
             console.log(a === b);\n\
             console.log(await argon2.verify(a, 'same-pw'));\n\
             console.log(await argon2.verify(b, 'same-pw'));\n\
         })();",
    );
    assert_ok(&out, "random salt per call");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["false", "true", "true"], "lines: {stdout}");
}
