// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

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
    // Generate a hash of an empty password, extract the "$2b$CC$SALT"
    // prefix (the bcrypt crate doesn't expose a salt-only generator
    // today, but the prefix of a hash IS the salt in bcrypt's wire
    // format). Prefix is always 29 chars.
    let h = bcrypt::hash("", rounds).map_err(|e| format!("bcrypt gen_salt: {e}"))?;
    // Strip the password-hash suffix (everything after the 29-char
    // header) so callers passing this to hash() get bcrypt's
    // recompute-from-salt behavior.
    if h.len() < 29 {
        return Err(format!("bcrypt: unexpected hash length {}", h.len()));
    }
    Ok(h[..29].to_string())
}
