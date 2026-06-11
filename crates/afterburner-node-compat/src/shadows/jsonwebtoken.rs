// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! L3 shadow for the `jsonwebtoken` npm package.
//!
//! Upstream `jsonwebtoken` is pure JS but depends on Node's
//! `crypto` module with a surface that goes beyond what the Node-
//! compat layer covers today. Rather than chase every crypto edge
//! case, we intercept `require('jsonwebtoken')` and dispatch to the
//! Rust [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) crate.
//!
//! Algorithm coverage:
//!
//! * **HS256 / HS384 / HS512** - HMAC with a secret string.
//! * **RS256 / RS384 / RS512** - RSA with PEM-formatted keys.
//! * **ES256 / ES384** - ECDSA with PEM-formatted keys.
//!
//! The three public functions take an options JSON blob (instead of
//! ten-plus positional parameters) so the host ABI stays narrow and
//! new options can land without ABI breakage.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::Value;

/// `sign(payload, secret, options)` - returns the JWT compact
/// serialization. `options` is the JSON-encoded argument object
/// that the npm API accepts (algorithm, expiresIn, issuer, audience,
/// subject); we parse only the subset listed above.
pub fn sign(payload_json: &str, secret: &[u8], options_json: &str) -> Result<String, String> {
    let mut payload: Value =
        serde_json::from_str(payload_json).map_err(|e| format!("sign: parse payload: {e}"))?;
    let opts: Value = serde_json::from_str(options_json).unwrap_or(Value::Null);

    let algorithm = parse_algorithm(&opts).unwrap_or(Algorithm::HS256);
    let mut header = Header::new(algorithm);
    if let Some(kid) = opts.get("keyid").and_then(|v| v.as_str()) {
        header.kid = Some(kid.to_string());
    }

    // Attach standard claims if requested via options. Only done
    // when the caller didn't already provide them in the payload
    // itself; this matches the npm package's semantics.
    let now = now_secs();
    if let Some(obj) = payload.as_object_mut() {
        // iat defaults to current time unless `noTimestamp` is set
        // or the caller already populated iat.
        if !obj.contains_key("iat")
            && opts.get("noTimestamp").and_then(|v| v.as_bool()) != Some(true)
        {
            obj.insert("iat".into(), Value::from(now));
        }
        if !obj.contains_key("exp")
            && let Some(exp_in) = opts.get("expiresIn").and_then(|v| v.as_i64())
        {
            obj.insert("exp".into(), Value::from(now + exp_in));
        }
        if !obj.contains_key("nbf")
            && let Some(nbf_in) = opts.get("notBefore").and_then(|v| v.as_i64())
        {
            obj.insert("nbf".into(), Value::from(now + nbf_in));
        }
        for (field, opt_key) in [
            ("iss", "issuer"),
            ("sub", "subject"),
            ("aud", "audience"),
            ("jti", "jwtid"),
        ] {
            if !obj.contains_key(field)
                && let Some(v) = opts.get(opt_key)
            {
                obj.insert(field.into(), v.clone());
            }
        }
    }

    let key = encoding_key(algorithm, secret)?;
    encode(&header, &payload, &key).map_err(|e| format!("sign: {e}"))
}

/// `verify(token, secret, options)` - validates the JWT and returns
/// the decoded payload as JSON. Mismatched algorithm, expired token,
/// or bad signature surface as `Err` with a descriptive message.
pub fn verify(token: &str, secret: &[u8], options_json: &str) -> Result<String, String> {
    let opts: Value = serde_json::from_str(options_json).unwrap_or(Value::Null);
    let algorithm = parse_algorithm(&opts).unwrap_or(Algorithm::HS256);
    let mut validation = Validation::new(algorithm);
    // Match npm jsonwebtoken's semantics: no claims are required
    // by default. If exp IS present the jsonwebtoken crate still
    // validates it (unless `ignoreExpiration` is set); same for nbf.
    // jsonwebtoken v10 ships with `required_spec_claims = {"exp"}`
    // which would reject any token that didn't opt into expiresIn -
    // too strict for the npm package's surface.
    validation.required_spec_claims = std::collections::HashSet::new();
    // Default leeway is 60s in the jsonwebtoken crate; tests that
    // deliberately build already-expired tokens need tighter bounds.
    // Keep the 60s default for normal code paths (matches npm's own
    // generous clock-skew tolerance).
    if opts.get("ignoreExpiration").and_then(|v| v.as_bool()) == Some(true) {
        validation.validate_exp = false;
    }
    if opts.get("ignoreNotBefore").and_then(|v| v.as_bool()) == Some(true) {
        validation.validate_nbf = false;
    }
    if let Some(iss) = opts.get("issuer").and_then(|v| v.as_str()) {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = opts.get("audience") {
        if let Some(s) = aud.as_str() {
            validation.set_audience(&[s]);
        } else if let Some(arr) = aud.as_array() {
            let list: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            validation.set_audience(&list);
        }
    }
    if let Some(sub) = opts.get("subject").and_then(|v| v.as_str()) {
        validation.sub = Some(sub.to_string());
    }

    let key = decoding_key(algorithm, secret)?;
    let data = decode::<Value>(token, &key, &validation).map_err(|e| format!("verify: {e}"))?;
    serde_json::to_string(&data.claims).map_err(|e| format!("verify: serialize: {e}"))
}

/// `decode(token)` - parses the JWT without verifying the signature.
/// Returns `{ header, payload }` as JSON. Matches the npm package's
/// `jwt.decode(token, { complete: true })` output.
pub fn decode_unverified(token: &str) -> Result<String, String> {
    // Do a minimal split; avoid the jsonwebtoken crate's public
    // decode path since it requires a key. The JWT format is three
    // base64url-encoded segments joined by '.'.
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| "decode: missing header".to_string())?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| "decode: missing payload".to_string())?;
    if parts.next().is_none() {
        return Err("decode: missing signature segment".into());
    }
    let header_bytes = b64url_decode(header_b64).map_err(|e| format!("decode: header: {e}"))?;
    let payload_bytes = b64url_decode(payload_b64).map_err(|e| format!("decode: payload: {e}"))?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("decode: header json: {e}"))?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("decode: payload json: {e}"))?;
    serde_json::to_string(&serde_json::json!({
        "header": header,
        "payload": payload,
    }))
    .map_err(|e| format!("decode: serialize: {e}"))
}

// ---- helpers -----------------------------------------------------------

fn parse_algorithm(opts: &Value) -> Option<Algorithm> {
    let s = opts.get("algorithm").and_then(|v| v.as_str())?;
    match s {
        "HS256" => Some(Algorithm::HS256),
        "HS384" => Some(Algorithm::HS384),
        "HS512" => Some(Algorithm::HS512),
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "EdDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

fn encoding_key(alg: Algorithm, secret: &[u8]) -> Result<EncodingKey, String> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(EncodingKey::from_secret(secret))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            EncodingKey::from_rsa_pem(secret).map_err(|e| format!("rsa key: {e}"))
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            EncodingKey::from_ec_pem(secret).map_err(|e| format!("ec key: {e}"))
        }
        Algorithm::EdDSA => EncodingKey::from_ed_pem(secret).map_err(|e| format!("ed key: {e}")),
    }
}

fn decoding_key(alg: Algorithm, secret: &[u8]) -> Result<DecodingKey, String> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(secret))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            DecodingKey::from_rsa_pem(secret).map_err(|e| format!("rsa key: {e}"))
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(secret).map_err(|e| format!("ec key: {e}"))
        }
        Algorithm::EdDSA => DecodingKey::from_ed_pem(secret).map_err(|e| format!("ed key: {e}")),
    }
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url: {e}"))
}
