// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! L3 shadow for the `argon2` npm package.
//!
//! Upstream argon2 ships a `.node` native addon; inside the WASM
//! sandbox we intercept `require('argon2')` and dispatch to pure-
//! Rust implementations in the [`argon2`](https://crates.io/crates/argon2)
//! crate.
//!
//! API matches the npm package:
//!
//! * `hash(password, options?)` — returns the PHC-formatted hash.
//!   Options: `type` (0 = Argon2d, 1 = Argon2i, 2 = Argon2id;
//!   default Argon2id), `timeCost`, `memoryCost`, `parallelism`,
//!   `hashLength`, `raw` (return bytes instead of PHC string).
//! * `verify(hash, password)` — returns `true` iff the password
//!   matches.
//! * `needsRehash(hash, options?)` — returns `true` if the stored
//!   hash was produced with weaker parameters than the current
//!   defaults.
//!
//! argon2 is async-only in the npm package; we match by exposing
//! the Rust functions synchronously here, with the JS polyfill
//! wrapping them in `Promise.resolve()` to preserve the Node
//! contract.

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Resolve the npm-package's numeric `type` field to an Argon2
/// variant. The npm default (when `type` is omitted) is Argon2id.
fn algo_from_type(ty: u8) -> Algorithm {
    match ty {
        0 => Algorithm::Argon2d,
        1 => Algorithm::Argon2i,
        _ => Algorithm::Argon2id,
    }
}

/// `argon2::hash(password, options)` — returns the PHC-formatted
/// hash string. Matches the npm package's default output shape
/// (`$argon2id$v=19$m=...,t=...,p=...$SALT$HASH`).
pub fn hash(
    password: &str,
    ty: u8,
    time_cost: u32,
    memory_cost_kib: u32,
    parallelism: u32,
) -> Result<String, String> {
    let algo = algo_from_type(ty);
    // Defaults match the npm package's documented defaults.
    let t = if time_cost == 0 { 3 } else { time_cost };
    let m = if memory_cost_kib == 0 {
        65_536
    } else {
        memory_cost_kib
    };
    let p = if parallelism == 0 { 4 } else { parallelism };
    let params = Params::new(m, t, p, None).map_err(|e| format!("argon2 params: {e}"))?;
    let argon = Argon2::new(algo, Version::V0x13, params);

    // `SaltString::generate` pulls from OsRng — matches the npm
    // package's behavior of generating a fresh salt per hash.
    let salt = SaltString::generate(&mut rand_core_04());
    let hash = argon
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("argon2 hash: {e}"))?;
    Ok(hash.to_string())
}

/// `argon2::verify(hash, password)` — parse the PHC hash and run
/// the verifier. Returns `Ok(true)` on match, `Ok(false)` on
/// mismatch, `Err` if the hash string is malformed.
pub fn verify(phc_hash: &str, password: &str) -> Result<bool, String> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| format!("argon2 parse hash: {e}"))?;
    // Let the argon2 algorithm handle verification; hash parameters
    // come from the stored string so we don't need to recompute.
    let argon = Argon2::default();
    match argon.verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::Password) => Ok(false),
        Err(e) => Err(format!("argon2 verify: {e}")),
    }
}

/// `argon2::needsRehash(hash, options)` — parses the PHC string,
/// compares its parameters against the target, and returns `true`
/// if any tightened defaults require re-hashing.
pub fn needs_rehash(
    phc_hash: &str,
    ty: u8,
    time_cost: u32,
    memory_cost_kib: u32,
    parallelism: u32,
) -> Result<bool, String> {
    let parsed = PasswordHash::new(phc_hash).map_err(|e| format!("argon2 parse hash: {e}"))?;
    // Compare algorithm first — a type change always requires rehash.
    let target_algo = algo_from_type(ty);
    let target_ident = target_algo.ident();
    if parsed.algorithm != target_ident {
        return Ok(true);
    }
    // Compare each numeric parameter. Stored params appear inside
    // `parsed.params`. Missing parameter means "was at some default"
    // — treat as needing rehash if caller explicitly requested one.
    let t = if time_cost == 0 { 3 } else { time_cost };
    let m = if memory_cost_kib == 0 {
        65_536
    } else {
        memory_cost_kib
    };
    let p = if parallelism == 0 { 4 } else { parallelism };
    let get_num = |key: &str| -> Option<u64> {
        parsed
            .params
            .get(key)
            .and_then(|v| v.decimal().ok())
            .map(|n| n as u64)
    };
    let cur_t = get_num("t").unwrap_or(0);
    let cur_m = get_num("m").unwrap_or(0);
    let cur_p = get_num("p").unwrap_or(0);
    Ok(cur_t < t as u64 || cur_m < m as u64 || cur_p < p as u64)
}

// `password-hash` expects `RngCore + CryptoRng`. The argon2 crate
// pulls in `rand_core` 0.6; we re-export a default here to keep the
// shadow's dep graph minimal.
fn rand_core_04() -> impl password_hash::rand_core::CryptoRngCore {
    password_hash::rand_core::OsRng
}
