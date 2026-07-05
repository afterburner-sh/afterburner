// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! L3 shadow for the `bcrypt` npm package.
//!
//! Upstream bcrypt ships a `.node` native addon; inside the WASM
//! sandbox we intercept `require('bcrypt')` and dispatch to pure-
//! Rust implementations in the [`bcrypt`](https://crates.io/crates/bcrypt)
//! crate.
//!
//! API matches the npm package at the one level that matters for
//! real-world use:
//!
//! * `hash(data, saltOrRounds)` / `hashSync(data, saltOrRounds)`
//! * `compare(data, hash)` / `compareSync(data, hash)`
//! * `genSalt(rounds)` / `genSaltSync(rounds)`
//!
//! The async variants wrap the sync call in a `Promise.resolve()` -
//! no thread pool; bcrypt's cost parameter bounds CPU time anyway.

use bcrypt::DEFAULT_COST;

/// `bcrypt::hash(password, cost)` - returns the full PHC-formatted
/// hash string on success, or an error string on failure.
pub fn hash(password: &str, cost: u32) -> Result<String, String> {
    let cost = if cost == 0 { DEFAULT_COST } else { cost };
    bcrypt::hash(password, cost).map_err(|e| format!("bcrypt hash: {e}"))
}

/// `bcrypt::verify(password, hash)` - returns `true` iff the
/// password matches the hash. A parse error on the hash surfaces
/// as an `Err` so the JS side can distinguish "wrong password"
/// from "bad hash string".
pub fn verify(password: &str, hash: &str) -> Result<bool, String> {
    bcrypt::verify(password, hash).map_err(|e| format!("bcrypt verify: {e}"))
}

/// `bcrypt::gen_salt(cost)` - returns a salt string that the user
/// can pass to `hash(password, salt)` later. We just generate and
/// discard the password; the salt portion of the hash is what
/// callers actually want. Matches the npm package's `genSaltSync`
/// output shape ("$2b$12$…" - 29 characters).
pub fn gen_salt(rounds: u32) -> Result<String, String> {
    let rounds = if rounds == 0 { DEFAULT_COST } else { rounds };
    // Preserve the previous behavior: the old implementation hashed at
    // `rounds`, so it returned Err for a cost outside bcrypt's valid range
    // (MIN_COST=4 ..= MAX_COST=31). We now hash at a fixed minimum cost, so
    // re-validate the requested cost explicitly to keep the same reject
    // behavior and to stop the 2-digit "{:02}" cost field below from
    // overflowing the 29-char salt for a cost >= 100.
    if !(4..=31).contains(&rounds) {
        return Err(format!("bcrypt gen_salt: cost {rounds} out of range (4..=31)"));
    }
    // The 16-byte salt is random and independent of cost; only the
    // discarded KDF suffix scales with cost. Generate the salt at the
    // minimum cost (cheap), then splice in the requested cost, instead of
    // running a full 2^rounds KDF just to read the salt prefix.
    let h = bcrypt::hash("", 4).map_err(|e| format!("bcrypt gen_salt: {e}"))?;
    if h.len() < 29 {
        return Err(format!("bcrypt: unexpected hash length {}", h.len()));
    }
    // h = "$2b$04$<22-char-salt>...". Preserve the version prefix (h[..4]),
    // rewrite the 2-digit cost, keep the 22-char salt (h[7..29]).
    Ok(format!("{}{:02}${}", &h[..4], rounds, &h[7..29]))
}
