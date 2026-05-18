// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! L3 shadow tests — jsonwebtoken.
//!
//! Richer surface than bcrypt/argon2: sign / verify / decode with
//! multiple algorithms (HS256/384/512, RS256), rich options
//! (expiresIn, issuer, audience, subject), and the npm package's
//! dual sync / callback contract.

#![cfg(all(feature = "bin", feature = "shadow-jsonwebtoken"))]

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
fn require_jwt_returns_a_module() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         console.log(typeof jwt.sign);\n\
         console.log(typeof jwt.verify);\n\
         console.log(typeof jwt.decode);\n\
         console.log(typeof jwt.JsonWebTokenError);\n\
         console.log(typeof jwt.TokenExpiredError);",
    );
    assert_ok(&out, "require('jsonwebtoken')");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let count = stdout.matches("function").count();
    assert!(count >= 5, "expected 5+ functions, got: {stdout}");
}

// ---- HS256 round-trip --------------------------------------------------

#[test]
fn hs256_sign_and_verify() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const token = jwt.sign({ user: 'alice', role: 'admin' }, 'shh');\n\
         // Token has three base64url-encoded segments.\n\
         console.log(token.split('.').length);\n\
         const decoded = jwt.verify(token, 'shh');\n\
         console.log(decoded.user);\n\
         console.log(decoded.role);",
    );
    assert_ok(&out, "HS256 round-trip");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["3", "alice", "admin"], "round-trip: {stdout}");
}

#[test]
fn wrong_secret_fails_verify() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const token = jwt.sign({ a: 1 }, 'right');\n\
         try {\n\
             jwt.verify(token, 'wrong');\n\
             console.log('BAD');\n\
         } catch (e) {\n\
             console.log('name=' + e.name);\n\
             console.log('code=' + e.code);\n\
         }",
    );
    assert_ok(&out, "wrong secret");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("name=JsonWebTokenError"),
        "expected JsonWebTokenError name: {stdout}"
    );
}

// ---- algorithm selection -----------------------------------------------

#[test]
fn hs384_and_hs512_work() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         for (const alg of ['HS384', 'HS512']) {\n\
             const t = jwt.sign({ alg }, 'secret', { algorithm: alg });\n\
             const d = jwt.verify(t, 'secret', { algorithm: alg });\n\
             console.log(alg + ':' + d.alg);\n\
         }",
    );
    assert_ok(&out, "HS384/HS512");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("HS384:HS384"), "HS384: {stdout}");
    assert!(stdout.contains("HS512:HS512"), "HS512: {stdout}");
}

// ---- iat / exp / issuer / audience / subject claims --------------------

#[test]
fn expires_in_sets_exp_claim() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const t = jwt.sign({ x: 1 }, 'k', { expiresIn: 3600 });\n\
         const d = jwt.decode(t);\n\
         // exp should be about an hour past iat.\n\
         console.log((d.exp - d.iat) === 3600);",
    );
    assert_ok(&out, "expiresIn");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "true");
}

#[test]
fn expires_in_string_accepts_duration_suffix() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const t = jwt.sign({ x: 1 }, 'k', { expiresIn: '1h' });\n\
         const d = jwt.decode(t);\n\
         console.log((d.exp - d.iat) === 3600);\n\
         const t2 = jwt.sign({ x: 1 }, 'k', { expiresIn: '7d' });\n\
         const d2 = jwt.decode(t2);\n\
         console.log((d2.exp - d2.iat) === 7 * 86400);",
    );
    assert_ok(&out, "expiresIn duration string");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["true", "true"], "duration: {stdout}");
}

#[test]
fn expired_token_verify_throws_token_expired_error() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         // Negative expiresIn → exp is in the past immediately.\n\
         // Well past the jsonwebtoken crate's 60s default leeway.
         const t = jwt.sign({ x: 1 }, 'k', { expiresIn: -300 });\n\
         try {\n\
             jwt.verify(t, 'k');\n\
             console.log('BAD');\n\
         } catch (e) {\n\
             console.log('name=' + e.name);\n\
         }",
    );
    assert_ok(&out, "expired token");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("name=TokenExpiredError"),
        "expected TokenExpiredError: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn ignore_expiration_bypasses_exp_check() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         // Well past the jsonwebtoken crate's 60s default leeway.
         const t = jwt.sign({ x: 1 }, 'k', { expiresIn: -300 });\n\
         const d = jwt.verify(t, 'k', { ignoreExpiration: true });\n\
         console.log(d.x);",
    );
    assert_ok(&out, "ignoreExpiration");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
}

#[test]
fn issuer_audience_subject_round_trip() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const t = jwt.sign({ hello: 'world' }, 'k', {\n\
             issuer: 'afterburner-auth',\n\
             audience: 'apiserver',\n\
             subject: 'user:42',\n\
         });\n\
         const d = jwt.verify(t, 'k', {\n\
             issuer: 'afterburner-auth',\n\
             audience: 'apiserver',\n\
             subject: 'user:42',\n\
         });\n\
         console.log(d.iss);\n\
         console.log(d.aud);\n\
         console.log(d.sub);",
    );
    assert_ok(&out, "iss/aud/sub");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines,
        vec!["afterburner-auth", "apiserver", "user:42"],
        "claims: {stdout}"
    );
}

#[test]
fn wrong_issuer_fails_verify() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const t = jwt.sign({ hello: 'world' }, 'k', { issuer: 'right' });\n\
         try {\n\
             jwt.verify(t, 'k', { issuer: 'wrong' });\n\
             console.log('BAD');\n\
         } catch (e) {\n\
             console.log('err');\n\
         }",
    );
    assert_ok(&out, "wrong issuer");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "err");
}

// ---- decode ------------------------------------------------------------

#[test]
fn decode_does_not_verify_signature() {
    // Even with a clearly-forged signature, decode must return the
    // payload — matches upstream (decode == parse, no verification).
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const real = jwt.sign({ forged: false }, 'right');\n\
         // Replace signature segment with garbage.\n\
         const parts = real.split('.');\n\
         const fake = parts[0] + '.' + parts[1] + '.CLEARLY_FAKE_SIG';\n\
         const d = jwt.decode(fake);\n\
         console.log(d.forged);",
    );
    assert_ok(&out, "decode no-verify");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "false");
}

#[test]
fn decode_complete_returns_header_and_payload() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         const t = jwt.sign({ hello: 'world' }, 'k', { algorithm: 'HS256' });\n\
         const full = jwt.decode(t, { complete: true });\n\
         console.log(full.header.alg);\n\
         console.log(full.header.typ);\n\
         console.log(full.payload.hello);\n\
         console.log(typeof full.signature);",
    );
    assert_ok(&out, "decode complete");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("HS256"), "alg: {stdout}");
    assert!(stdout.contains("JWT"), "typ: {stdout}");
    assert!(stdout.contains("world"), "payload: {stdout}");
    assert!(stdout.contains("string"), "signature type: {stdout}");
}

#[test]
fn decode_malformed_returns_null() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         console.log(jwt.decode('not-a-jwt') === null);\n\
         console.log(jwt.decode('') === null);",
    );
    assert_ok(&out, "decode malformed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines, vec!["true", "true"], "null-on-malformed: {stdout}");
}

// ---- callback shape ----------------------------------------------------

#[test]
fn callback_shape_for_sign_and_verify() {
    let out = run_burn_eval(
        "const jwt = require('jsonwebtoken');\n\
         jwt.sign({ x: 7 }, 'k', function(err, tok) {\n\
             if (err) { process.exit(1); }\n\
             jwt.verify(tok, 'k', function(verr, dec) {\n\
                 if (verr) { process.exit(1); }\n\
                 console.log('x=' + dec.x);\n\
             });\n\
         });",
    );
    assert_ok(&out, "callback shape");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "x=7");
}

// ---- shadow precedence --------------------------------------------------

#[test]
fn shadow_wins_over_node_modules_jsonwebtoken() {
    let dir = std::env::temp_dir().join(format!("burn_jwt_precedence_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("node_modules/jsonwebtoken")).unwrap();
    std::fs::write(
        dir.join("node_modules/jsonwebtoken/package.json"),
        r#"{"name":"jsonwebtoken","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/jsonwebtoken/index.js"),
        "module.exports = { shadowed: 'FAKE-USER-JWT' };",
    )
    .unwrap();

    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .current_dir(&dir)
        .arg("-e")
        .arg(
            "const jwt = require('jsonwebtoken');\n\
             console.log(typeof jwt.sign);\n\
             console.log(!!jwt.shadowed);",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let _ = std::fs::remove_dir_all(&dir);

    assert_ok(&out, "jwt shadow precedence");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("function"), "shadow not resolved: {stdout}");
    assert!(
        stdout.contains("false"),
        "fake user jwt leaked through: {stdout}"
    );
}
