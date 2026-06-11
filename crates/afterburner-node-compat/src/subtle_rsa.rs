// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Subtle Crypto RSA — OAEP, PSS, PKCS1-v1.5 (encrypt/decrypt + sign/verify),
//! plus key generation / import / export across PKCS#8, SPKI, and JWK.

use afterburner_core::{AfterburnerError, Result};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

/// Generate an RSA key pair. Returns (pkcs8 private DER, spki public DER).
pub fn rsa_keygen(modulus_bits: usize, public_exponent: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    if !(2048..=8192).contains(&modulus_bits) || !modulus_bits.is_multiple_of(8) {
        return Err(AfterburnerError::Host(format!(
            "RSA keygen: modulusLength must be 2048..8192 and multiple of 8, got {modulus_bits}"
        )));
    }
    let mut rng = rsa::rand_core::OsRng;
    let exp = rsa::BigUint::from(public_exponent);
    let priv_key = RsaPrivateKey::new_with_exp(&mut rng, modulus_bits, &exp)
        .map_err(|e| AfterburnerError::Host(format!("RSA keygen: {e}")))?;
    let priv_der = priv_key
        .to_pkcs8_der()
        .map_err(|e| AfterburnerError::Host(format!("RSA priv encode: {e}")))?
        .as_bytes()
        .to_vec();
    let pub_der = rsa::pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&priv_key.to_public_key())
        .map_err(|e| AfterburnerError::Host(format!("RSA pub encode: {e}")))?
        .as_bytes()
        .to_vec();
    // We return SPKI for the pub side (Web Crypto exportKey('spki')).
    use rsa::pkcs8::EncodePublicKey;
    let pub_spki = priv_key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| AfterburnerError::Host(format!("RSA spki encode: {e}")))?
        .as_bytes()
        .to_vec();
    let _ = pub_der; // silence unused — we now return SPKI by default
    Ok((priv_der, pub_spki))
}

fn parse_priv(pkcs8_der: &[u8]) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| AfterburnerError::Host(format!("RSA priv parse: {e}")))
}

fn parse_pub(spki_der: &[u8]) -> Result<RsaPublicKey> {
    use rsa::pkcs8::DecodePublicKey;
    RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| AfterburnerError::Host(format!("RSA pub parse: {e}")))
}

/// RSA-OAEP encrypt with the given hash. `label` is optional (Web
/// Crypto's `label` parameter). Returns ciphertext.
pub fn rsa_oaep_encrypt(spki_der: &[u8], hash: &str, label: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key = parse_pub(spki_der)?;
    let mut rng = rsa::rand_core::OsRng;
    let label_opt = if label.is_empty() {
        None
    } else {
        Some(String::from_utf8(label.to_vec()).unwrap_or_default())
    };
    let padding = match hash {
        "SHA-1" | "sha1" => rsa::Oaep::new_with_label::<Sha1, _>(label_opt.unwrap_or_default()),
        "SHA-256" | "sha256" => {
            rsa::Oaep::new_with_label::<Sha256, _>(label_opt.unwrap_or_default())
        }
        "SHA-384" | "sha384" => {
            rsa::Oaep::new_with_label::<Sha384, _>(label_opt.unwrap_or_default())
        }
        "SHA-512" | "sha512" => {
            rsa::Oaep::new_with_label::<Sha512, _>(label_opt.unwrap_or_default())
        }
        other => {
            return Err(AfterburnerError::Host(format!(
                "RSA-OAEP: unsupported hash '{other}'"
            )));
        }
    };
    key.encrypt(&mut rng, padding, data)
        .map_err(|e| AfterburnerError::Host(format!("RSA-OAEP encrypt: {e}")))
}

pub fn rsa_oaep_decrypt(pkcs8_der: &[u8], hash: &str, label: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let key = parse_priv(pkcs8_der)?;
    let label_opt = if label.is_empty() {
        None
    } else {
        Some(String::from_utf8(label.to_vec()).unwrap_or_default())
    };
    let padding = match hash {
        "SHA-1" | "sha1" => rsa::Oaep::new_with_label::<Sha1, _>(label_opt.unwrap_or_default()),
        "SHA-256" | "sha256" => {
            rsa::Oaep::new_with_label::<Sha256, _>(label_opt.unwrap_or_default())
        }
        "SHA-384" | "sha384" => {
            rsa::Oaep::new_with_label::<Sha384, _>(label_opt.unwrap_or_default())
        }
        "SHA-512" | "sha512" => {
            rsa::Oaep::new_with_label::<Sha512, _>(label_opt.unwrap_or_default())
        }
        other => {
            return Err(AfterburnerError::Host(format!(
                "RSA-OAEP: unsupported hash '{other}'"
            )));
        }
    };
    key.decrypt(padding, ct)
        .map_err(|e| AfterburnerError::Host(format!("RSA-OAEP decrypt: {e}")))
}

/// RSA-PSS sign. `salt_len` matches Web Crypto's `saltLength` param.
pub fn rsa_pss_sign(pkcs8_der: &[u8], hash: &str, salt_len: usize, data: &[u8]) -> Result<Vec<u8>> {
    use rsa::pss::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let key = parse_priv(pkcs8_der)?;
    let mut rng = rsa::rand_core::OsRng;
    let sig = match hash {
        "SHA-256" | "sha256" => {
            SigningKey::<Sha256>::new_with_salt_len(key, salt_len).sign_with_rng(&mut rng, data)
        }
        "SHA-384" | "sha384" => {
            SigningKey::<Sha384>::new_with_salt_len(key, salt_len).sign_with_rng(&mut rng, data)
        }
        "SHA-512" | "sha512" => {
            SigningKey::<Sha512>::new_with_salt_len(key, salt_len).sign_with_rng(&mut rng, data)
        }
        other => {
            return Err(AfterburnerError::Host(format!(
                "RSA-PSS: unsupported hash '{other}'"
            )));
        }
    };
    Ok(sig.to_bytes().to_vec())
}

pub fn rsa_pss_verify(
    spki_der: &[u8],
    hash: &str,
    salt_len: usize,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let key = parse_pub(spki_der)?;
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| AfterburnerError::Host(format!("RSA-PSS sig: {e}")))?;
    let ok = match hash {
        "SHA-256" | "sha256" => VerifyingKey::<Sha256>::new_with_salt_len(key, salt_len)
            .verify(data, &sig)
            .is_ok(),
        "SHA-384" | "sha384" => VerifyingKey::<Sha384>::new_with_salt_len(key, salt_len)
            .verify(data, &sig)
            .is_ok(),
        "SHA-512" | "sha512" => VerifyingKey::<Sha512>::new_with_salt_len(key, salt_len)
            .verify(data, &sig)
            .is_ok(),
        other => {
            return Err(AfterburnerError::Host(format!(
                "RSA-PSS: unsupported hash '{other}'"
            )));
        }
    };
    Ok(ok)
}

/// RSASSA-PKCS1-v1_5 sign over a raw message. Hash is applied internally
/// (matches WebCrypto's `RsaHashedKeyAlgorithm` shape).
pub fn rsa_pkcs1_sign(pkcs8_der: &[u8], hash: &str, data: &[u8]) -> Result<Vec<u8>> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let key = parse_priv(pkcs8_der)?;
    let mut rng = rsa::rand_core::OsRng;
    let sig = match hash {
        "SHA-256" | "sha256" => SigningKey::<Sha256>::new(key).sign_with_rng(&mut rng, data),
        "SHA-384" | "sha384" => SigningKey::<Sha384>::new(key).sign_with_rng(&mut rng, data),
        "SHA-512" | "sha512" => SigningKey::<Sha512>::new(key).sign_with_rng(&mut rng, data),
        "SHA-1" | "sha1" => SigningKey::<Sha1>::new(key).sign_with_rng(&mut rng, data),
        other => {
            return Err(AfterburnerError::Host(format!(
                "RSASSA-PKCS1: unsupported hash '{other}'"
            )));
        }
    };
    Ok(sig.to_bytes().to_vec())
}

pub fn rsa_pkcs1_verify(
    spki_der: &[u8],
    hash: &str,
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let key = parse_pub(spki_der)?;
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| AfterburnerError::Host(format!("RSASSA-PKCS1 sig: {e}")))?;
    let ok = match hash {
        "SHA-256" | "sha256" => VerifyingKey::<Sha256>::new(key).verify(data, &sig).is_ok(),
        "SHA-384" | "sha384" => VerifyingKey::<Sha384>::new(key).verify(data, &sig).is_ok(),
        "SHA-512" | "sha512" => VerifyingKey::<Sha512>::new(key).verify(data, &sig).is_ok(),
        "SHA-1" | "sha1" => VerifyingKey::<Sha1>::new(key).verify(data, &sig).is_ok(),
        other => {
            return Err(AfterburnerError::Host(format!(
                "RSASSA-PKCS1: unsupported hash '{other}'"
            )));
        }
    };
    Ok(ok)
}

/// Export RSA private key to JWK as a JSON object string.
pub fn rsa_export_jwk_priv(pkcs8_der: &[u8]) -> Result<String> {
    let key = parse_priv(pkcs8_der)?;
    let n = b64url(&key.n().to_bytes_be());
    let e = b64url(&key.e().to_bytes_be());
    let d = b64url(&key.d().to_bytes_be());
    let primes = key.primes();
    if primes.len() < 2 {
        return Err(AfterburnerError::Host("RSA priv: missing primes".into()));
    }
    let p = b64url(&primes[0].to_bytes_be());
    let q = b64url(&primes[1].to_bytes_be());
    // dp = d mod (p-1), dq = d mod (q-1), qi = q^-1 mod p — reconstruct
    // from d, p, q so the JWK matches what `node:crypto` emits.
    use num_bigint_dig::ModInverse;
    use num_traits::One;
    let p_big = primes[0].clone();
    let q_big = primes[1].clone();
    let d_big = key.d().clone();
    let one = num_bigint_dig::BigUint::one();
    let dp = (&d_big) % (&p_big - &one);
    let dq = (&d_big) % (&q_big - &one);
    let qi = q_big
        .clone()
        .mod_inverse(&p_big)
        .ok_or_else(|| AfterburnerError::Host("RSA priv: q has no inverse mod p".into()))?
        .to_biguint()
        .ok_or_else(|| AfterburnerError::Host("RSA priv: qi conversion failed".into()))?;
    Ok(format!(
        r#"{{"kty":"RSA","n":"{n}","e":"{e}","d":"{d}","p":"{p}","q":"{q}","dp":"{}","dq":"{}","qi":"{}"}}"#,
        b64url(&dp.to_bytes_be()),
        b64url(&dq.to_bytes_be()),
        b64url(&qi.to_bytes_be()),
    ))
}

pub fn rsa_export_jwk_pub(spki_der: &[u8]) -> Result<String> {
    let key = parse_pub(spki_der)?;
    let n = b64url(&key.n().to_bytes_be());
    let e = b64url(&key.e().to_bytes_be());
    Ok(format!(r#"{{"kty":"RSA","n":"{n}","e":"{e}"}}"#))
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_keypair() -> (Vec<u8>, Vec<u8>) {
        // 2048 is the minimum we accept; tests need a real key but keep
        // it small to stay quick.
        rsa_keygen(2048, 65537).unwrap()
    }

    #[test]
    fn rsa_oaep_round_trips_each_hash() {
        let (priv_der, pub_der) = small_keypair();
        for h in ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] {
            let pt = b"hello, world";
            let ct = rsa_oaep_encrypt(&pub_der, h, b"", pt).unwrap();
            let rt = rsa_oaep_decrypt(&priv_der, h, b"", &ct).unwrap();
            assert_eq!(rt, pt, "round-trip broken at hash {h}");
        }
    }

    #[test]
    fn rsa_oaep_with_label_round_trips() {
        let (priv_der, pub_der) = small_keypair();
        let ct = rsa_oaep_encrypt(&pub_der, "SHA-256", b"context", b"x").unwrap();
        let rt = rsa_oaep_decrypt(&priv_der, "SHA-256", b"context", &ct).unwrap();
        assert_eq!(rt, b"x");
    }

    #[test]
    fn rsa_oaep_wrong_hash_rejects() {
        let (priv_der, pub_der) = small_keypair();
        let ct = rsa_oaep_encrypt(&pub_der, "SHA-256", b"", b"x").unwrap();
        let r = rsa_oaep_decrypt(&priv_der, "SHA-512", b"", &ct);
        assert!(r.is_err());
    }

    #[test]
    fn rsa_pss_sign_verify_round_trips() {
        let (priv_der, pub_der) = small_keypair();
        let data = b"signed message";
        for h in ["SHA-256", "SHA-384", "SHA-512"] {
            let sig = rsa_pss_sign(&priv_der, h, 32, data).unwrap();
            let ok = rsa_pss_verify(&pub_der, h, 32, data, &sig).unwrap();
            assert!(ok, "PSS verify failed at hash {h}");
        }
    }

    #[test]
    fn rsa_pss_tampered_sig_rejects() {
        let (priv_der, pub_der) = small_keypair();
        let mut sig = rsa_pss_sign(&priv_der, "SHA-256", 32, b"x").unwrap();
        sig[0] ^= 0xFF;
        assert!(!rsa_pss_verify(&pub_der, "SHA-256", 32, b"x", &sig).unwrap());
    }

    #[test]
    fn rsa_pkcs1_sign_verify_round_trips() {
        let (priv_der, pub_der) = small_keypair();
        for h in ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] {
            let sig = rsa_pkcs1_sign(&priv_der, h, b"data").unwrap();
            assert!(rsa_pkcs1_verify(&pub_der, h, b"data", &sig).unwrap());
        }
    }

    #[test]
    fn rsa_export_jwk_priv_emits_full_field_set() {
        let (priv_der, _) = small_keypair();
        let jwk = rsa_export_jwk_priv(&priv_der).unwrap();
        for f in ["kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            assert!(jwk.contains(f), "missing JWK field {f}");
        }
    }

    #[test]
    fn rsa_export_jwk_pub_minimal() {
        let (_, pub_der) = small_keypair();
        let jwk = rsa_export_jwk_pub(&pub_der).unwrap();
        assert!(jwk.contains("\"kty\":\"RSA\""));
        assert!(jwk.contains("\"n\":"));
        assert!(jwk.contains("\"e\":"));
        assert!(!jwk.contains("\"d\":"));
    }

    #[test]
    fn rsa_keygen_rejects_undersized_modulus() {
        assert!(rsa_keygen(1024, 65537).is_err());
        assert!(rsa_keygen(2049, 65537).is_err()); // not multiple of 8
    }
}
