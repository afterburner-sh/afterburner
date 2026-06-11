// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `crypto.subtle` Web Crypto subset. Backed by node:crypto host
//! fns (AES-GCM/CBC, HMAC, PBKDF2, SHA digest). Tests cover every
//! algorithm pair the polyfill ships, plus the import/export round-
//! trip path that real-world libraries (jose, signed-cookies, etc.)
//! exercise to fingerprint key material.

#![cfg(feature = "bin")]

use std::process::{Command, Stdio};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

fn run_inline(source: &str) -> std::process::Output {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(source)
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
        "burn failed. stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(marker),
        "missing marker `{marker}`. stdout={stdout}\nstderr={stderr}"
    );
}

// ---- digest ---------------------------------------------------------

#[test]
fn subtle_digest_sha256_matches_known_vector() {
    let out = run_inline(
        r#"
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        async function main() {
            const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('abc'));
            const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
            if (hex === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
                console.log('DIGEST-OK');
            } else {
                console.log('FAIL', hex);
            }
        }
        main().catch(e => { console.log('ERR', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "DIGEST-OK");
}

#[test]
fn subtle_digest_sha512_returns_64_bytes() {
    let out = run_inline(
        r#"
        async function main() {
            const buf = await crypto.subtle.digest('SHA-512', new Uint8Array([1,2,3]));
            if (new Uint8Array(buf).length === 64) console.log('SHA512-LEN-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "SHA512-LEN-OK");
}

// ---- AES-GCM --------------------------------------------------------

#[test]
fn subtle_aes_gcm_encrypt_decrypt_round_trips() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true,
                ['encrypt', 'decrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const pt = new TextEncoder().encode('hello world');
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
            const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
            if (new TextDecoder().decode(dec) === 'hello world') console.log('GCM-OK');
        }
        main().catch(e => { console.log('ERR', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "GCM-OK");
}

#[test]
fn subtle_aes_gcm_with_aad_round_trips() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true,
                ['encrypt', 'decrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const aad = new TextEncoder().encode('header');
            const pt = new TextEncoder().encode('secret payload');
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pt);
            const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct);
            if (new TextDecoder().decode(dec) === 'secret payload') console.log('GCM-AAD-OK');
        }
        main().catch(e => { console.log('ERR', e.message); process.exit(1); });
        "#,
    );
    assert_marker(&out, "GCM-AAD-OK");
}

#[test]
fn subtle_aes_gcm_tampered_ciphertext_rejects() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true,
                ['encrypt', 'decrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const pt = new TextEncoder().encode('don\'t change me');
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
            const tampered = new Uint8Array(ct);
            tampered[0] ^= 1; // flip first byte
            try {
                await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, tampered);
                console.log('FAIL no-throw');
            } catch (_) { console.log('TAMPER-OK'); }
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "TAMPER-OK");
}

// ---- AES-CBC --------------------------------------------------------

#[test]
fn subtle_aes_cbc_round_trips_block_aligned_input() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true,
                ['encrypt', 'decrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(16));
            const pt = new TextEncoder().encode('the quick brown fox jumped');
            const ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, pt);
            const dec = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ct);
            if (new TextDecoder().decode(dec) === 'the quick brown fox jumped') console.log('CBC-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "CBC-OK");
}

// ---- HMAC -----------------------------------------------------------

#[test]
fn subtle_hmac_sign_verify_round_trips() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true,
                ['sign', 'verify']);
            const msg = new TextEncoder().encode('verify me');
            const sig = await crypto.subtle.sign('HMAC', key, msg);
            const ok = await crypto.subtle.verify('HMAC', key, sig, msg);
            if (ok) console.log('HMAC-VERIFY-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "HMAC-VERIFY-OK");
}

#[test]
fn subtle_hmac_verify_rejects_tampered_signature() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, true,
                ['sign', 'verify']);
            const msg = new TextEncoder().encode('protected');
            const sig = await crypto.subtle.sign('HMAC', key, msg);
            const tampered = new Uint8Array(sig);
            tampered[0] ^= 1;
            const ok = await crypto.subtle.verify('HMAC', key, tampered, msg);
            if (!ok) console.log('HMAC-NEG-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "HMAC-NEG-OK");
}

#[test]
fn subtle_hmac_supports_sha384_and_sha512() {
    let out = run_inline(
        r#"
        async function main() {
            for (const hash of ['SHA-384', 'SHA-512']) {
                const key = await crypto.subtle.generateKey({ name: 'HMAC', hash }, true, ['sign', 'verify']);
                const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('x'));
                if (!(sig.byteLength > 0)) { console.log('FAIL', hash); return; }
            }
            console.log('HMAC-MULTI-HASH-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "HMAC-MULTI-HASH-OK");
}

// ---- PBKDF2 / HKDF deriveBits + deriveKey ---------------------------

#[test]
fn subtle_pbkdf2_derive_bits_returns_requested_length() {
    let out = run_inline(
        r#"
        async function main() {
            const password = new TextEncoder().encode('correct horse battery staple');
            const salt = new TextEncoder().encode('saltsalt');
            const baseKey = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' },
                false, ['deriveBits']);
            const bits = await crypto.subtle.deriveBits({
                name: 'PBKDF2', salt, iterations: 100, hash: 'SHA-256',
            }, baseKey, 256);
            if (new Uint8Array(bits).length === 32) console.log('PBKDF2-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "PBKDF2-OK");
}

#[test]
fn subtle_hkdf_derive_bits_round_trip_against_rfc5869_test_vector() {
    let out = run_inline(
        r#"
        async function main() {
            // RFC 5869 Test Case 1: SHA-256, IKM = 22*0x0b, salt=0x000102…0c,
            // info=0xf0…f9, L=42 → OKM = 3cb25f25...8a04ae837e
            const ikm = new Uint8Array(22).fill(0x0b);
            const salt = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12]);
            const info = new Uint8Array([0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9]);
            const baseKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' },
                false, ['deriveBits']);
            const okm = await crypto.subtle.deriveBits({
                name: 'HKDF', hash: 'SHA-256', salt, info,
            }, baseKey, 42 * 8);
            const hex = Array.from(new Uint8Array(okm)).map(b => b.toString(16).padStart(2,'0')).join('');
            const expected = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';
            if (hex === expected) console.log('HKDF-OK');
            else console.log('HKDF-FAIL', hex);
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "HKDF-OK");
}

#[test]
fn subtle_derive_key_imports_into_target_algorithm() {
    let out = run_inline(
        r#"
        async function main() {
            const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode('p'),
                { name: 'PBKDF2' }, false, ['deriveKey']);
            const aesKey = await crypto.subtle.deriveKey(
                { name: 'PBKDF2', salt: new TextEncoder().encode('s'), iterations: 100, hash: 'SHA-256' },
                baseKey,
                { name: 'AES-GCM', length: 256 },
                true, ['encrypt', 'decrypt']);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new Uint8Array([1,2,3]));
            const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
            const arr = new Uint8Array(pt);
            if (arr[0] === 1 && arr[1] === 2 && arr[2] === 3) console.log('DERIVE-KEY-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "DERIVE-KEY-OK");
}

// ---- import / export round-trip --------------------------------------

#[test]
fn subtle_export_raw_round_trips_through_import() {
    let out = run_inline(
        r#"
        async function main() {
            const key1 = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true,
                ['encrypt', 'decrypt']);
            const raw = await crypto.subtle.exportKey('raw', key1);
            const key2 = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true,
                ['encrypt', 'decrypt']);
            // Verify same key by encrypting with key1, decrypting with key2.
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const pt = new TextEncoder().encode('round-trip');
            const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, pt);
            const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ct);
            if (new TextDecoder().decode(dec) === 'round-trip') console.log('EXPORT-RAW-OK');
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "EXPORT-RAW-OK");
}

#[test]
fn subtle_export_jwk_emits_oct_kty_with_base64url_k() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true,
                ['encrypt', 'decrypt']);
            const jwk = await crypto.subtle.exportKey('jwk', key);
            if (jwk.kty === 'oct' && typeof jwk.k === 'string' &&
                /^[A-Za-z0-9_-]+$/.test(jwk.k)) console.log('JWK-OK');
            else console.log('JWK-FAIL', JSON.stringify(jwk));
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "JWK-OK");
}

#[test]
fn subtle_non_extractable_key_export_rejects() {
    let out = run_inline(
        r#"
        async function main() {
            const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false,
                ['encrypt']);
            try {
                await crypto.subtle.exportKey('raw', key);
                console.log('FAIL no-throw');
            } catch (_) { console.log('NON-EXTRACTABLE-OK'); }
        }
        main().catch(e => { process.exit(1); });
        "#,
    );
    assert_marker(&out, "NON-EXTRACTABLE-OK");
}
