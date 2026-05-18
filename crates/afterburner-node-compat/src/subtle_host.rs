// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Subtle Crypto host dispatcher — single host import, JSON-encoded args.
//!
//! Wire format:
//! - input: `op_name`, `args_b64_json` (JSON array of base64url-encoded
//!   byte buffers; scalars are encoded as base64url-of-utf8-string for
//!   uniformity).
//! - output: base64url-encoded result, or `[<b64>,<b64>,...]` JSON
//!   array for ops that return multiple buffers (keygen).
//!
//! A single import keeps the plugin host-API extern-decl table compact
//! while allowing arbitrary algorithm coverage.

use afterburner_core::{AfterburnerError, Manifold, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

use crate::{subtle_aes, subtle_ec, subtle_rsa};

/// Decode a JSON array of base64url-encoded byte strings.
fn decode_args(args_json: &str) -> Result<Vec<Vec<u8>>> {
    let v: serde_json::Value = serde_json::from_str(args_json)
        .map_err(|e| AfterburnerError::Host(format!("subtle: args json: {e}")))?;
    let arr = v
        .as_array()
        .ok_or_else(|| AfterburnerError::Host("subtle: args must be JSON array".into()))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| AfterburnerError::Host(format!("subtle: args[{i}] must be string")))?;
        out.push(
            B64.decode(s)
                .map_err(|e| AfterburnerError::Host(format!("subtle: args[{i}] base64: {e}")))?,
        );
    }
    Ok(out)
}

fn encode_one(out: &[u8]) -> String {
    B64.encode(out)
}

fn encode_pair(a: &[u8], b: &[u8]) -> String {
    format!("[\"{}\",\"{}\"]", B64.encode(a), B64.encode(b))
}

fn arg_str(arg: &[u8]) -> Result<&str> {
    std::str::from_utf8(arg).map_err(|e| AfterburnerError::Host(format!("subtle: arg utf8: {e}")))
}

fn arg_usize(arg: &[u8]) -> Result<usize> {
    arg_str(arg)?
        .parse::<usize>()
        .map_err(|e| AfterburnerError::Host(format!("subtle: arg usize: {e}")))
}

fn arg_u64(arg: &[u8]) -> Result<u64> {
    arg_str(arg)?
        .parse::<u64>()
        .map_err(|e| AfterburnerError::Host(format!("subtle: arg u64: {e}")))
}

/// The single dispatcher. Op names are colon-separated:
/// `<algo>:<verb>[:<curve_or_hash>]`.
pub fn subtle_op(op: &str, args_json: &str, m: &Manifold) -> Result<String> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.subtle.{op}"
        )));
    }
    let args = decode_args(args_json)?;
    match op {
        // ---- AES-CTR ------------------------------------------------
        "aes-ctr:apply" => {
            // [key, counter, data]
            need(&args, 3, op)?;
            Ok(encode_one(&subtle_aes::aes_ctr_apply(
                &args[0], &args[1], &args[2],
            )?))
        }

        // ---- AES-KW -------------------------------------------------
        "aes-kw:wrap" => {
            need(&args, 2, op)?;
            Ok(encode_one(&subtle_aes::aes_kw_wrap(&args[0], &args[1])?))
        }
        "aes-kw:unwrap" => {
            need(&args, 2, op)?;
            Ok(encode_one(&subtle_aes::aes_kw_unwrap(&args[0], &args[1])?))
        }

        // ---- RSA: keygen returns pair -----------------------------
        "rsa:keygen" => {
            // [modulus_bits_str, public_exp_str]
            need(&args, 2, op)?;
            let bits = arg_usize(&args[0])?;
            let exp = arg_u64(&args[1])?;
            let (priv_, pub_) = subtle_rsa::rsa_keygen(bits, exp)?;
            Ok(encode_pair(&priv_, &pub_))
        }

        // ---- RSA-OAEP ----------------------------------------------
        "rsa-oaep:encrypt" => {
            need(&args, 4, op)?;
            let hash = arg_str(&args[0])?;
            Ok(encode_one(&subtle_rsa::rsa_oaep_encrypt(
                &args[1], hash, &args[2], &args[3],
            )?))
        }
        "rsa-oaep:decrypt" => {
            need(&args, 4, op)?;
            let hash = arg_str(&args[0])?;
            Ok(encode_one(&subtle_rsa::rsa_oaep_decrypt(
                &args[1], hash, &args[2], &args[3],
            )?))
        }

        // ---- RSA-PSS -----------------------------------------------
        "rsa-pss:sign" => {
            need(&args, 4, op)?;
            let hash = arg_str(&args[0])?;
            let salt_len = arg_usize(&args[1])?;
            Ok(encode_one(&subtle_rsa::rsa_pss_sign(
                &args[2], hash, salt_len, &args[3],
            )?))
        }
        "rsa-pss:verify" => {
            need(&args, 5, op)?;
            let hash = arg_str(&args[0])?;
            let salt_len = arg_usize(&args[1])?;
            Ok(
                if subtle_rsa::rsa_pss_verify(&args[2], hash, salt_len, &args[3], &args[4])? {
                    "1".into()
                } else {
                    "0".into()
                },
            )
        }

        // ---- RSASSA-PKCS1-v1_5 -------------------------------------
        "rsa-pkcs1:sign" => {
            need(&args, 3, op)?;
            let hash = arg_str(&args[0])?;
            Ok(encode_one(&subtle_rsa::rsa_pkcs1_sign(
                &args[1], hash, &args[2],
            )?))
        }
        "rsa-pkcs1:verify" => {
            need(&args, 4, op)?;
            let hash = arg_str(&args[0])?;
            Ok(
                if subtle_rsa::rsa_pkcs1_verify(&args[1], hash, &args[2], &args[3])? {
                    "1".into()
                } else {
                    "0".into()
                },
            )
        }

        // ---- RSA JWK export ----------------------------------------
        "rsa:export-jwk-priv" => {
            need(&args, 1, op)?;
            // JWK is JSON; encode as base64url so the wire stays uniform.
            let jwk = subtle_rsa::rsa_export_jwk_priv(&args[0])?;
            Ok(encode_one(jwk.as_bytes()))
        }
        "rsa:export-jwk-pub" => {
            need(&args, 1, op)?;
            let jwk = subtle_rsa::rsa_export_jwk_pub(&args[0])?;
            Ok(encode_one(jwk.as_bytes()))
        }

        // ---- EC: keygen returns pair --------------------------------
        "ec:keygen" => {
            need(&args, 1, op)?;
            let curve = arg_str(&args[0])?;
            let (priv_, pub_) = subtle_ec::ec_keygen(curve)?;
            Ok(encode_pair(&priv_, &pub_))
        }

        // ---- ECDSA --------------------------------------------------
        "ecdsa:sign" => {
            need(&args, 4, op)?;
            let curve = arg_str(&args[0])?;
            let hash = arg_str(&args[1])?;
            Ok(encode_one(&subtle_ec::ecdsa_sign(
                curve, hash, &args[2], &args[3],
            )?))
        }
        "ecdsa:verify" => {
            need(&args, 5, op)?;
            let curve = arg_str(&args[0])?;
            let hash = arg_str(&args[1])?;
            Ok(
                if subtle_ec::ecdsa_verify(curve, hash, &args[2], &args[3], &args[4])? {
                    "1".into()
                } else {
                    "0".into()
                },
            )
        }

        // ---- ECDH ---------------------------------------------------
        "ecdh:derive" => {
            need(&args, 3, op)?;
            let curve = arg_str(&args[0])?;
            Ok(encode_one(&subtle_ec::ecdh_derive(
                curve, &args[1], &args[2],
            )?))
        }

        // ---- Ed25519 ------------------------------------------------
        "ed25519:keygen" => {
            need(&args, 0, op)?;
            let (priv_, pub_) = subtle_ec::ed25519_keygen()?;
            Ok(encode_pair(&priv_, &pub_))
        }
        "ed25519:sign" => {
            need(&args, 2, op)?;
            Ok(encode_one(&subtle_ec::ed25519_sign(&args[0], &args[1])?))
        }
        "ed25519:verify" => {
            need(&args, 3, op)?;
            Ok(
                if subtle_ec::ed25519_verify(&args[0], &args[1], &args[2])? {
                    "1".into()
                } else {
                    "0".into()
                },
            )
        }

        // ---- X25519 -------------------------------------------------
        "x25519:keygen" => {
            need(&args, 0, op)?;
            let (priv_, pub_) = subtle_ec::x25519_keygen()?;
            Ok(encode_pair(&priv_, &pub_))
        }
        "x25519:derive" => {
            need(&args, 2, op)?;
            Ok(encode_one(&subtle_ec::x25519_derive(&args[0], &args[1])?))
        }

        other => Err(AfterburnerError::Host(format!(
            "crypto.subtle: unknown op '{other}'"
        ))),
    }
}

fn need(args: &[Vec<u8>], n: usize, op: &str) -> Result<()> {
    if args.len() != n {
        Err(AfterburnerError::Host(format!(
            "crypto.subtle.{op}: expected {n} args, got {}",
            args.len()
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::Manifold;

    fn open_manifold() -> Manifold {
        Manifold::open()
    }

    fn args(items: &[&[u8]]) -> String {
        let parts: Vec<String> = items
            .iter()
            .map(|b| format!("\"{}\"", B64.encode(b)))
            .collect();
        format!("[{}]", parts.join(","))
    }

    fn args_str(items: &[&str]) -> String {
        let parts: Vec<String> = items
            .iter()
            .map(|s| format!("\"{}\"", B64.encode(s.as_bytes())))
            .collect();
        format!("[{}]", parts.join(","))
    }

    #[test]
    fn unknown_op_errors() {
        let r = subtle_op("bogus:nope", "[]", &open_manifold());
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
    }

    #[test]
    fn aes_ctr_round_trip_via_dispatcher() {
        let key = vec![0x42u8; 16];
        let counter = vec![0u8; 16];
        let data = b"plaintext".to_vec();
        let ct_b64 = subtle_op(
            "aes-ctr:apply",
            &args(&[&key, &counter, &data]),
            &open_manifold(),
        )
        .unwrap();
        let ct = B64.decode(&ct_b64).unwrap();
        let pt_b64 = subtle_op(
            "aes-ctr:apply",
            &args(&[&key, &counter, &ct]),
            &open_manifold(),
        )
        .unwrap();
        assert_eq!(B64.decode(pt_b64).unwrap(), data);
    }

    #[test]
    fn aes_kw_round_trip_via_dispatcher() {
        let kek = vec![0x11u8; 16];
        let target = vec![0x42u8; 32];
        let wrapped = subtle_op("aes-kw:wrap", &args(&[&kek, &target]), &open_manifold()).unwrap();
        let wb = B64.decode(&wrapped).unwrap();
        let unwrapped = subtle_op("aes-kw:unwrap", &args(&[&kek, &wb]), &open_manifold()).unwrap();
        assert_eq!(B64.decode(unwrapped).unwrap(), target);
    }

    #[test]
    fn rsa_keygen_returns_pair() {
        let r = subtle_op(
            "rsa:keygen",
            &args_str(&["2048", "65537"]),
            &open_manifold(),
        )
        .unwrap();
        assert!(r.starts_with('['));
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr[0].as_str().unwrap().len() > 100);
        assert!(arr[1].as_str().unwrap().len() > 100);
    }

    #[test]
    fn ecdsa_sign_verify_via_dispatcher() {
        let kp = subtle_op("ec:keygen", &args_str(&["P-256"]), &open_manifold()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&kp).unwrap();
        let priv_b64 = v[0].as_str().unwrap();
        let pub_b64 = v[1].as_str().unwrap();
        let priv_ = B64.decode(priv_b64).unwrap();
        let pub_ = B64.decode(pub_b64).unwrap();
        let data = b"signed".to_vec();

        // build args manually because curve+hash are utf8 strings
        let mut argv = String::from("[");
        argv.push_str(&format!("\"{}\",", B64.encode(b"P-256")));
        argv.push_str(&format!("\"{}\",", B64.encode(b"SHA-256")));
        argv.push_str(&format!("\"{}\",", B64.encode(&priv_)));
        argv.push_str(&format!("\"{}\"]", B64.encode(&data)));
        let sig_b64 = subtle_op("ecdsa:sign", &argv, &open_manifold()).unwrap();
        let sig = B64.decode(&sig_b64).unwrap();

        let mut argv = String::from("[");
        argv.push_str(&format!("\"{}\",", B64.encode(b"P-256")));
        argv.push_str(&format!("\"{}\",", B64.encode(b"SHA-256")));
        argv.push_str(&format!("\"{}\",", B64.encode(&pub_)));
        argv.push_str(&format!("\"{}\",", B64.encode(&data)));
        argv.push_str(&format!("\"{}\"]", B64.encode(&sig)));
        let ok = subtle_op("ecdsa:verify", &argv, &open_manifold()).unwrap();
        assert_eq!(ok, "1");
    }

    #[test]
    fn ed25519_round_trip_via_dispatcher() {
        let kp = subtle_op("ed25519:keygen", "[]", &open_manifold()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&kp).unwrap();
        let priv_ = B64.decode(v[0].as_str().unwrap()).unwrap();
        let pub_ = B64.decode(v[1].as_str().unwrap()).unwrap();
        let data = b"hello".to_vec();
        let sig_b64 = subtle_op("ed25519:sign", &args(&[&priv_, &data]), &open_manifold()).unwrap();
        let sig = B64.decode(&sig_b64).unwrap();
        let ok = subtle_op(
            "ed25519:verify",
            &args(&[&pub_, &data, &sig]),
            &open_manifold(),
        )
        .unwrap();
        assert_eq!(ok, "1");
    }

    #[test]
    fn x25519_derive_via_dispatcher() {
        let a = subtle_op("x25519:keygen", "[]", &open_manifold()).unwrap();
        let av: serde_json::Value = serde_json::from_str(&a).unwrap();
        let a_priv = B64.decode(av[0].as_str().unwrap()).unwrap();
        let a_pub = B64.decode(av[1].as_str().unwrap()).unwrap();
        let b = subtle_op("x25519:keygen", "[]", &open_manifold()).unwrap();
        let bv: serde_json::Value = serde_json::from_str(&b).unwrap();
        let b_priv = B64.decode(bv[0].as_str().unwrap()).unwrap();
        let b_pub = B64.decode(bv[1].as_str().unwrap()).unwrap();
        let s1 = subtle_op("x25519:derive", &args(&[&a_priv, &b_pub]), &open_manifold()).unwrap();
        let s2 = subtle_op("x25519:derive", &args(&[&b_priv, &a_pub]), &open_manifold()).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn rsa_oaep_round_trip_via_dispatcher() {
        let kp = subtle_op(
            "rsa:keygen",
            &args_str(&["2048", "65537"]),
            &open_manifold(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&kp).unwrap();
        let priv_ = B64.decode(v[0].as_str().unwrap()).unwrap();
        let pub_ = B64.decode(v[1].as_str().unwrap()).unwrap();
        let label: Vec<u8> = vec![];
        let data = b"hi".to_vec();

        let mut argv = String::from("[");
        argv.push_str(&format!("\"{}\",", B64.encode(b"SHA-256")));
        argv.push_str(&format!("\"{}\",", B64.encode(&pub_)));
        argv.push_str(&format!("\"{}\",", B64.encode(&label)));
        argv.push_str(&format!("\"{}\"]", B64.encode(&data)));
        let ct = B64
            .decode(subtle_op("rsa-oaep:encrypt", &argv, &open_manifold()).unwrap())
            .unwrap();

        let mut argv = String::from("[");
        argv.push_str(&format!("\"{}\",", B64.encode(b"SHA-256")));
        argv.push_str(&format!("\"{}\",", B64.encode(&priv_)));
        argv.push_str(&format!("\"{}\",", B64.encode(&label)));
        argv.push_str(&format!("\"{}\"]", B64.encode(&ct)));
        let pt = B64
            .decode(subtle_op("rsa-oaep:decrypt", &argv, &open_manifold()).unwrap())
            .unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn permission_denied_when_manifold_crypto_off() {
        let mut m = Manifold::open();
        m.crypto = false;
        let r = subtle_op("ed25519:keygen", "[]", &m);
        assert!(matches!(r, Err(AfterburnerError::PermissionDenied(_))));
    }

    #[test]
    fn malformed_args_json_errors() {
        assert!(subtle_op("aes-kw:wrap", "{not array}", &open_manifold()).is_err());
        assert!(subtle_op("aes-kw:wrap", "[1,2]", &open_manifold()).is_err());
    }
}
