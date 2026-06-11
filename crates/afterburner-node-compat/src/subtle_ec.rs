// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Subtle Crypto elliptic-curve algorithms - ECDSA / ECDH on
//! P-256 / P-384 / P-521, plus Ed25519 and X25519.

use afterburner_core::{AfterburnerError, Result};

/// Allowed Web-Crypto curve names.
pub fn parse_curve(name: &str) -> Result<&'static str> {
    match name {
        "P-256" | "p-256" | "P256" | "p256" => Ok("P-256"),
        "P-384" | "p-384" | "P384" | "p384" => Ok("P-384"),
        "P-521" | "p-521" | "P521" | "p521" => Ok("P-521"),
        other => Err(AfterburnerError::Host(format!(
            "EC: unsupported curve '{other}'"
        ))),
    }
}

/// Generate an ECDSA / ECDH key pair on the named curve.
/// Returns (pkcs8 private DER, spki public DER).
pub fn ec_keygen(curve: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let c = parse_curve(curve)?;
    let mut rng = rsa::rand_core::OsRng;
    match c {
        "P-256" => {
            use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
            let sk = p256::SecretKey::random(&mut rng);
            let pk = sk.public_key();
            Ok((
                sk.to_pkcs8_der()
                    .map_err(|e| AfterburnerError::Host(format!("P-256 priv encode: {e}")))?
                    .as_bytes()
                    .to_vec(),
                pk.to_public_key_der()
                    .map_err(|e| AfterburnerError::Host(format!("P-256 pub encode: {e}")))?
                    .as_bytes()
                    .to_vec(),
            ))
        }
        "P-384" => {
            use p384::pkcs8::{EncodePrivateKey, EncodePublicKey};
            let sk = p384::SecretKey::random(&mut rng);
            let pk = sk.public_key();
            Ok((
                sk.to_pkcs8_der()
                    .map_err(|e| AfterburnerError::Host(format!("P-384 priv encode: {e}")))?
                    .as_bytes()
                    .to_vec(),
                pk.to_public_key_der()
                    .map_err(|e| AfterburnerError::Host(format!("P-384 pub encode: {e}")))?
                    .as_bytes()
                    .to_vec(),
            ))
        }
        "P-521" => {
            use p521::pkcs8::{EncodePrivateKey, EncodePublicKey};
            let sk = p521::SecretKey::random(&mut rng);
            let pk = sk.public_key();
            Ok((
                sk.to_pkcs8_der()
                    .map_err(|e| AfterburnerError::Host(format!("P-521 priv encode: {e}")))?
                    .as_bytes()
                    .to_vec(),
                pk.to_public_key_der()
                    .map_err(|e| AfterburnerError::Host(format!("P-521 pub encode: {e}")))?
                    .as_bytes()
                    .to_vec(),
            ))
        }
        _ => unreachable!(),
    }
}

/// ECDSA sign over a raw message with the named hash. Output is the
/// IEEE P-1363 fixed-size raw signature (r||s), as Web Crypto returns.
pub fn ecdsa_sign(curve: &str, hash: &str, pkcs8_der: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let c = parse_curve(curve)?;
    match (c, hash) {
        ("P-256", "SHA-256") | ("P-256", "sha256") => {
            use p256::ecdsa::SigningKey;
            use p256::pkcs8::DecodePrivateKey;
            use rsa::signature::RandomizedSigner;
            let key = SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| AfterburnerError::Host(format!("P-256 priv: {e}")))?;
            let mut rng = rsa::rand_core::OsRng;
            let sig: p256::ecdsa::Signature = key.sign_with_rng(&mut rng, data);
            Ok(sig.to_bytes().to_vec())
        }
        ("P-384", "SHA-384") | ("P-384", "sha384") => {
            use p384::ecdsa::SigningKey;
            use p384::pkcs8::DecodePrivateKey;
            use rsa::signature::RandomizedSigner;
            let key = SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| AfterburnerError::Host(format!("P-384 priv: {e}")))?;
            let mut rng = rsa::rand_core::OsRng;
            let sig: p384::ecdsa::Signature = key.sign_with_rng(&mut rng, data);
            Ok(sig.to_bytes().to_vec())
        }
        ("P-521", "SHA-512") | ("P-521", "sha512") => {
            use p521::pkcs8::DecodePrivateKey;
            use rsa::signature::RandomizedSigner;
            // P-521 ecdsa::SigningKey lacks DecodePrivateKey; load the
            // SecretKey and re-encode via raw scalar bytes (66 bytes).
            let sk = p521::SecretKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| AfterburnerError::Host(format!("P-521 priv: {e}")))?;
            let signing_key = p521::ecdsa::SigningKey::from_bytes(&sk.to_bytes())
                .map_err(|e| AfterburnerError::Host(format!("P-521 sk bytes: {e}")))?;
            let mut rng = rsa::rand_core::OsRng;
            let sig: p521::ecdsa::Signature = signing_key.sign_with_rng(&mut rng, data);
            Ok(sig.to_bytes().to_vec())
        }
        (c, h) => Err(AfterburnerError::Host(format!(
            "ECDSA: curve/hash mismatch {c}/{h}"
        ))),
    }
}

pub fn ecdsa_verify(
    curve: &str,
    hash: &str,
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    let c = parse_curve(curve)?;
    match (c, hash) {
        ("P-256", "SHA-256") | ("P-256", "sha256") => {
            use p256::ecdsa::{Signature, VerifyingKey};
            use p256::pkcs8::DecodePublicKey;
            use rsa::signature::Verifier;
            let key = VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| AfterburnerError::Host(format!("P-256 pub: {e}")))?;
            let sig = Signature::from_slice(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("P-256 sig: {e}")))?;
            Ok(key.verify(data, &sig).is_ok())
        }
        ("P-384", "SHA-384") | ("P-384", "sha384") => {
            use p384::ecdsa::{Signature, VerifyingKey};
            use p384::pkcs8::DecodePublicKey;
            use rsa::signature::Verifier;
            let key = VerifyingKey::from_public_key_der(spki_der)
                .map_err(|e| AfterburnerError::Host(format!("P-384 pub: {e}")))?;
            let sig = Signature::from_slice(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("P-384 sig: {e}")))?;
            Ok(key.verify(data, &sig).is_ok())
        }
        ("P-521", "SHA-512") | ("P-521", "sha512") => {
            use p521::pkcs8::DecodePublicKey;
            use rsa::signature::Verifier;
            // VerifyingKey lacks DecodePublicKey + From<PublicKey> at
            // this rev. Round through SEC1 encoded point form - both
            // sides accept it.
            let pk = p521::PublicKey::from_public_key_der(spki_der)
                .map_err(|e| AfterburnerError::Host(format!("P-521 pub: {e}")))?;
            let encoded_point = pk.to_sec1_bytes();
            let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&encoded_point)
                .map_err(|e| AfterburnerError::Host(format!("P-521 vk bytes: {e}")))?;
            let sig = p521::ecdsa::Signature::from_slice(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("P-521 sig: {e}")))?;
            Ok(verifying_key.verify(data, &sig).is_ok())
        }
        (c, h) => Err(AfterburnerError::Host(format!(
            "ECDSA: curve/hash mismatch {c}/{h}"
        ))),
    }
}

/// ECDH derive shared secret. Output is the raw X coordinate.
pub fn ecdh_derive(curve: &str, priv_pkcs8_der: &[u8], pub_spki_der: &[u8]) -> Result<Vec<u8>> {
    let c = parse_curve(curve)?;
    match c {
        "P-256" => {
            use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
            let sk = p256::SecretKey::from_pkcs8_der(priv_pkcs8_der)
                .map_err(|e| AfterburnerError::Host(format!("P-256 priv: {e}")))?;
            let pk = p256::PublicKey::from_public_key_der(pub_spki_der)
                .map_err(|e| AfterburnerError::Host(format!("P-256 pub: {e}")))?;
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        "P-384" => {
            use p384::pkcs8::{DecodePrivateKey, DecodePublicKey};
            let sk = p384::SecretKey::from_pkcs8_der(priv_pkcs8_der)
                .map_err(|e| AfterburnerError::Host(format!("P-384 priv: {e}")))?;
            let pk = p384::PublicKey::from_public_key_der(pub_spki_der)
                .map_err(|e| AfterburnerError::Host(format!("P-384 pub: {e}")))?;
            let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        "P-521" => {
            use p521::pkcs8::{DecodePrivateKey, DecodePublicKey};
            let sk = p521::SecretKey::from_pkcs8_der(priv_pkcs8_der)
                .map_err(|e| AfterburnerError::Host(format!("P-521 priv: {e}")))?;
            let pk = p521::PublicKey::from_public_key_der(pub_spki_der)
                .map_err(|e| AfterburnerError::Host(format!("P-521 pub: {e}")))?;
            let shared = p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        _ => unreachable!(),
    }
}

/// Ed25519 keygen. Returns (32-byte priv seed, 32-byte pub key).
pub fn ed25519_keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    use ed25519_dalek::SigningKey;
    use rsa::rand_core::RngCore;
    let mut seed = [0u8; 32];
    rsa::rand_core::OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    Ok((seed.to_vec(), pk.to_bytes().to_vec()))
}

pub fn ed25519_sign(seed: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};
    if seed.len() != 32 {
        return Err(AfterburnerError::Host(format!(
            "Ed25519: priv must be 32 bytes, got {}",
            seed.len()
        )));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(seed);
    let sk = SigningKey::from_bytes(&buf);
    Ok(sk.sign(data).to_bytes().to_vec())
}

pub fn ed25519_verify(pub_bytes: &[u8], data: &[u8], sig_bytes: &[u8]) -> Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if pub_bytes.len() != 32 {
        return Err(AfterburnerError::Host(format!(
            "Ed25519: pub must be 32 bytes, got {}",
            pub_bytes.len()
        )));
    }
    if sig_bytes.len() != 64 {
        return Err(AfterburnerError::Host(format!(
            "Ed25519: sig must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut pb = [0u8; 32];
    pb.copy_from_slice(pub_bytes);
    let mut sb = [0u8; 64];
    sb.copy_from_slice(sig_bytes);
    let pk = VerifyingKey::from_bytes(&pb)
        .map_err(|e| AfterburnerError::Host(format!("Ed25519 pub: {e}")))?;
    let sig = Signature::from_bytes(&sb);
    Ok(pk.verify(data, &sig).is_ok())
}

/// X25519 keygen. Returns (32-byte priv, 32-byte pub).
pub fn x25519_keygen() -> Result<(Vec<u8>, Vec<u8>)> {
    use rsa::rand_core::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};
    let mut seed = [0u8; 32];
    rsa::rand_core::OsRng.fill_bytes(&mut seed);
    let sk = StaticSecret::from(seed);
    let pk = PublicKey::from(&sk);
    Ok((sk.to_bytes().to_vec(), pk.to_bytes().to_vec()))
}

pub fn x25519_derive(priv_bytes: &[u8], pub_bytes: &[u8]) -> Result<Vec<u8>> {
    use x25519_dalek::{PublicKey, StaticSecret};
    if priv_bytes.len() != 32 || pub_bytes.len() != 32 {
        return Err(AfterburnerError::Host(format!(
            "X25519: priv/pub must be 32 bytes (got {}/{})",
            priv_bytes.len(),
            pub_bytes.len()
        )));
    }
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(priv_bytes);
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(pub_bytes);
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(pk_bytes);
    Ok(sk.diffie_hellman(&pk).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_keygen_round_trips_each_curve() {
        for c in ["P-256", "P-384", "P-521"] {
            let (sk, pk) = ec_keygen(c).unwrap();
            assert!(!sk.is_empty(), "{c}: priv empty");
            assert!(!pk.is_empty(), "{c}: pub empty");
        }
    }

    #[test]
    fn ecdsa_sign_verify_round_trips_p256_p384_p521() {
        for (curve, hash) in [
            ("P-256", "SHA-256"),
            ("P-384", "SHA-384"),
            ("P-521", "SHA-512"),
        ] {
            let (sk, pk) = ec_keygen(curve).unwrap();
            let sig = ecdsa_sign(curve, hash, &sk, b"data").unwrap();
            assert!(
                ecdsa_verify(curve, hash, &pk, b"data", &sig).unwrap(),
                "verify failed at {curve}/{hash}"
            );
        }
    }

    #[test]
    fn ecdsa_tampered_signature_rejects() {
        let (sk, pk) = ec_keygen("P-256").unwrap();
        let mut sig = ecdsa_sign("P-256", "SHA-256", &sk, b"data").unwrap();
        sig[0] ^= 0xFF;
        assert!(!ecdsa_verify("P-256", "SHA-256", &pk, b"data", &sig).unwrap());
    }

    #[test]
    fn ecdsa_curve_hash_mismatch_errors() {
        let (sk, _) = ec_keygen("P-256").unwrap();
        assert!(ecdsa_sign("P-256", "SHA-512", &sk, b"x").is_err());
    }

    #[test]
    fn ecdh_derive_matches_both_directions_p256() {
        let (a_sk, a_pk) = ec_keygen("P-256").unwrap();
        let (b_sk, b_pk) = ec_keygen("P-256").unwrap();
        let s1 = ecdh_derive("P-256", &a_sk, &b_pk).unwrap();
        let s2 = ecdh_derive("P-256", &b_sk, &a_pk).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32, "P-256 shared secret must be 32 bytes");
    }

    #[test]
    fn ecdh_derive_each_curve() {
        for (c, want_len) in [("P-256", 32), ("P-384", 48), ("P-521", 66)] {
            let (a_sk, a_pk) = ec_keygen(c).unwrap();
            let (b_sk, b_pk) = ec_keygen(c).unwrap();
            let s1 = ecdh_derive(c, &a_sk, &b_pk).unwrap();
            let s2 = ecdh_derive(c, &b_sk, &a_pk).unwrap();
            assert_eq!(s1, s2, "{c}: ECDH disagreement");
            assert_eq!(s1.len(), want_len, "{c}: shared secret length");
        }
    }

    #[test]
    fn ed25519_sign_verify_round_trips() {
        let (sk, pk) = ed25519_keygen().unwrap();
        let sig = ed25519_sign(&sk, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
        assert!(ed25519_verify(&pk, b"hello", &sig).unwrap());
    }

    #[test]
    fn ed25519_tampered_signature_rejects() {
        let (sk, pk) = ed25519_keygen().unwrap();
        let mut sig = ed25519_sign(&sk, b"hello").unwrap();
        sig[0] ^= 0xFF;
        assert!(!ed25519_verify(&pk, b"hello", &sig).unwrap());
    }

    #[test]
    fn x25519_derive_agrees_both_ways() {
        let (a_sk, a_pk) = x25519_keygen().unwrap();
        let (b_sk, b_pk) = x25519_keygen().unwrap();
        let s1 = x25519_derive(&a_sk, &b_pk).unwrap();
        let s2 = x25519_derive(&b_sk, &a_pk).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn ec_keygen_unknown_curve_errors() {
        assert!(ec_keygen("Curve25519").is_err());
        assert!(parse_curve("nope").is_err());
    }
}
