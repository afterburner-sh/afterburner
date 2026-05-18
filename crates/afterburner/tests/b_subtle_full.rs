// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! End-to-end coverage of the round-out SubtleCrypto algorithm set:
//! AES-CTR, AES-KW, RSA-OAEP / RSA-PSS / RSASSA-PKCS1-v1_5,
//! ECDSA / ECDH (P-256/384/521), Ed25519, X25519.
//!
//! Each test exercises the JS-side `crypto.subtle` surface end-to-end
//! through the burn binary so the host bridge, plugin globals, and
//! polyfill dispatcher are all wired correctly.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run(src: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(src)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn")
}

fn assert_marker(out: &std::process::Output, marker: &str) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "burn failed.\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

// ---- AES-CTR --------------------------------------------------------

#[test]
fn aes_ctr_encrypt_decrypt_round_trips_128_bit_key() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'AES-CTR', length: 128 }, true, ['encrypt','decrypt']);
            const counter = new Uint8Array(16);
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-CTR', counter, length: 64 }, k,
                new TextEncoder().encode('the quick brown fox'));
            const pt = await crypto.subtle.decrypt(
                { name: 'AES-CTR', counter, length: 64 }, k, ct);
            if (new TextDecoder().decode(pt) === 'the quick brown fox') console.log('AES-CTR-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "AES-CTR-OK");
}

#[test]
fn aes_ctr_encrypt_decrypt_round_trips_256_bit_key() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'AES-CTR', length: 256 }, true, ['encrypt','decrypt']);
            const counter = new Uint8Array(16);
            const ct = await crypto.subtle.encrypt(
                { name: 'AES-CTR', counter, length: 64 }, k,
                new Uint8Array([1,2,3,4,5,6,7,8,9,10]));
            const pt = await crypto.subtle.decrypt(
                { name: 'AES-CTR', counter, length: 64 }, k, ct);
            const u = new Uint8Array(pt);
            if (u.length === 10 && u[0] === 1 && u[9] === 10) console.log('AES-CTR-256-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "AES-CTR-256-OK");
}

// ---- AES-KW ---------------------------------------------------------

#[test]
fn aes_kw_wrap_unwrap_round_trips_aes_gcm_key() {
    let out = run(r#"
        async function main() {
            const wk = await crypto.subtle.generateKey(
                { name: 'AES-KW', length: 128 }, true, ['wrapKey','unwrapKey']);
            const tk = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 128 }, true, ['encrypt','decrypt']);
            const wrapped = await crypto.subtle.wrapKey('raw', tk, wk, 'AES-KW');
            const unwrapped = await crypto.subtle.unwrapKey(
                'raw', wrapped, wk, 'AES-KW',
                { name: 'AES-GCM', length: 128 }, true, ['encrypt']);
            if (unwrapped.algorithm.name === 'AES-GCM') console.log('AES-KW-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "AES-KW-OK");
}

#[test]
fn aes_kw_unwrap_rejects_tampered_blob() {
    let out = run(r#"
        async function main() {
            const wk = await crypto.subtle.generateKey(
                { name: 'AES-KW', length: 128 }, true, ['wrapKey','unwrapKey']);
            const tk = await crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 128 }, true, ['encrypt']);
            const wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', tk, wk, 'AES-KW'));
            wrapped[0] ^= 0xFF;
            try {
                await crypto.subtle.unwrapKey('raw', wrapped, wk, 'AES-KW',
                    { name: 'AES-GCM', length: 128 }, true, ['encrypt']);
                console.log('FAIL no-error');
            } catch (e) {
                console.log('AES-KW-TAMPER-OK');
            }
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "AES-KW-TAMPER-OK");
}

// ---- RSA-OAEP -------------------------------------------------------

#[test]
fn rsa_oaep_encrypt_decrypt_round_trips_with_sha256() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'RSA-OAEP', modulusLength: 2048,
                  publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
                true, ['encrypt','decrypt']);
            const ct = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' }, k.publicKey,
                new TextEncoder().encode('secret'));
            const pt = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' }, k.privateKey, ct);
            if (new TextDecoder().decode(pt) === 'secret') console.log('RSA-OAEP-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "RSA-OAEP-OK");
}

// ---- RSA-PSS --------------------------------------------------------

#[test]
fn rsa_pss_sign_verify_round_trips() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'RSA-PSS', modulusLength: 2048,
                  publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
                true, ['sign','verify']);
            const data = new TextEncoder().encode('rsa-pss');
            const sig = await crypto.subtle.sign(
                { name: 'RSA-PSS', saltLength: 32 }, k.privateKey, data);
            const ok = await crypto.subtle.verify(
                { name: 'RSA-PSS', saltLength: 32 }, k.publicKey, sig, data);
            if (ok === true) console.log('RSA-PSS-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "RSA-PSS-OK");
}

#[test]
fn rsa_pss_tampered_signature_rejects() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'RSA-PSS', modulusLength: 2048,
                  publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
                true, ['sign','verify']);
            const data = new TextEncoder().encode('rsa-pss');
            const sig = new Uint8Array(await crypto.subtle.sign(
                { name: 'RSA-PSS', saltLength: 32 }, k.privateKey, data));
            sig[0] ^= 0xFF;
            const ok = await crypto.subtle.verify(
                { name: 'RSA-PSS', saltLength: 32 }, k.publicKey, sig, data);
            if (ok === false) console.log('RSA-PSS-TAMPER-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "RSA-PSS-TAMPER-OK");
}

// ---- RSASSA-PKCS1-v1_5 ----------------------------------------------

#[test]
fn rsa_pkcs1_v15_sign_verify_round_trips() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
                  publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
                true, ['sign','verify']);
            const data = new TextEncoder().encode('rsa-pkcs1');
            const sig = await crypto.subtle.sign(
                { name: 'RSASSA-PKCS1-v1_5' }, k.privateKey, data);
            const ok = await crypto.subtle.verify(
                { name: 'RSASSA-PKCS1-v1_5' }, k.publicKey, sig, data);
            if (ok === true) console.log('RSA-PKCS1-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "RSA-PKCS1-OK");
}

// ---- ECDSA ----------------------------------------------------------

#[test]
fn ecdsa_p256_sign_verify_round_trips() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
            const data = new TextEncoder().encode('ecdsa');
            const sig = await crypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-256' }, k.privateKey, data);
            const ok = await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' }, k.publicKey, sig, data);
            if (ok === true) console.log('ECDSA-P256-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ECDSA-P256-OK");
}

#[test]
fn ecdsa_p384_sign_verify_round_trips() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign','verify']);
            const data = new TextEncoder().encode('ecdsa');
            const sig = await crypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-384' }, k.privateKey, data);
            const ok = await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-384' }, k.publicKey, sig, data);
            if (ok === true) console.log('ECDSA-P384-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ECDSA-P384-OK");
}

#[test]
fn ecdsa_p521_sign_verify_round_trips() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-521' }, true, ['sign','verify']);
            const data = new TextEncoder().encode('ecdsa');
            const sig = await crypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-512' }, k.privateKey, data);
            const ok = await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-512' }, k.publicKey, sig, data);
            if (ok === true) console.log('ECDSA-P521-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ECDSA-P521-OK");
}

#[test]
fn ecdsa_tampered_signature_rejects() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
            const data = new TextEncoder().encode('x');
            const sig = new Uint8Array(await crypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-256' }, k.privateKey, data));
            sig[0] ^= 0xFF;
            const ok = await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' }, k.publicKey, sig, data);
            if (ok === false) console.log('ECDSA-TAMPER-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ECDSA-TAMPER-OK");
}

// ---- ECDH -----------------------------------------------------------

#[test]
fn ecdh_p256_derive_bits_agrees_both_directions() {
    let out = run(r#"
        async function main() {
            const a = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            const b = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            const s1 = new Uint8Array(await crypto.subtle.deriveBits(
                { name: 'ECDH', public: b.publicKey }, a.privateKey, 256));
            const s2 = new Uint8Array(await crypto.subtle.deriveBits(
                { name: 'ECDH', public: a.publicKey }, b.privateKey, 256));
            if (s1.length === 32 && s1.every((v,i) => v === s2[i])) console.log('ECDH-P256-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ECDH-P256-OK");
}

#[test]
fn ecdh_p384_derive_bits_agrees_both_directions() {
    let out = run(r#"
        async function main() {
            const a = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
            const b = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
            const s1 = new Uint8Array(await crypto.subtle.deriveBits(
                { name: 'ECDH', public: b.publicKey }, a.privateKey, 384));
            const s2 = new Uint8Array(await crypto.subtle.deriveBits(
                { name: 'ECDH', public: a.publicKey }, b.privateKey, 384));
            if (s1.length === 48 && s1.every((v,i) => v === s2[i])) console.log('ECDH-P384-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ECDH-P384-OK");
}

// ---- Ed25519 --------------------------------------------------------

#[test]
fn ed25519_sign_verify_round_trips() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign','verify']);
            const data = new TextEncoder().encode('ed25519');
            const sig = await crypto.subtle.sign({ name: 'Ed25519' }, k.privateKey, data);
            const ok = await crypto.subtle.verify({ name: 'Ed25519' }, k.publicKey, sig, data);
            if (ok === true) console.log('ED25519-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ED25519-OK");
}

#[test]
fn ed25519_signature_is_64_bytes() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign','verify']);
            const sig = new Uint8Array(await crypto.subtle.sign(
                { name: 'Ed25519' }, k.privateKey, new TextEncoder().encode('x')));
            if (sig.length === 64) console.log('ED25519-SIGLEN-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ED25519-SIGLEN-OK");
}

#[test]
fn ed25519_tampered_signature_rejects() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign','verify']);
            const data = new TextEncoder().encode('ed');
            const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, k.privateKey, data));
            sig[0] ^= 0xFF;
            const ok = await crypto.subtle.verify({ name: 'Ed25519' }, k.publicKey, sig, data);
            if (ok === false) console.log('ED25519-TAMPER-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "ED25519-TAMPER-OK");
}

// ---- X25519 ---------------------------------------------------------

#[test]
fn x25519_derive_bits_agrees_both_ways() {
    let out = run(r#"
        async function main() {
            const a = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            const b = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
            const s1 = new Uint8Array(await crypto.subtle.deriveBits(
                { name: 'X25519', public: b.publicKey }, a.privateKey, 256));
            const s2 = new Uint8Array(await crypto.subtle.deriveBits(
                { name: 'X25519', public: a.publicKey }, b.privateKey, 256));
            if (s1.length === 32 && s1.every((v,i) => v === s2[i])) console.log('X25519-OK');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "X25519-OK");
}

// ---- JWK export -----------------------------------------------------

#[test]
fn rsa_oaep_export_jwk_emits_expected_field_set() {
    let out = run(r#"
        async function main() {
            const k = await crypto.subtle.generateKey(
                { name: 'RSA-OAEP', modulusLength: 2048,
                  publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
                true, ['encrypt','decrypt']);
            const priv_jwk = await crypto.subtle.exportKey('jwk', k.privateKey);
            const pub_jwk  = await crypto.subtle.exportKey('jwk', k.publicKey);
            const need = ['kty','n','e','d','p','q','dp','dq','qi'];
            if (need.every(f => typeof priv_jwk[f] === 'string')
                && typeof pub_jwk.n === 'string' && typeof pub_jwk.d === 'undefined')
                console.log('JWK-OK');
            else console.log('JWK-FAIL');
        }
        main().catch(e => { console.log('FAIL', e.message); process.exit(1); });
    "#);
    assert_marker(&out, "JWK-OK");
}
