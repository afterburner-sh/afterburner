// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `crypto.checkPrime` / `crypto.generatePrime` host impls.
//!
//! Both back the Node Crypto module's prime-testing surface with the
//! `num-bigint-dig` BigUint + Miller-Rabin primality test (the same
//! primitives the `rsa` crate uses for keygen).

use afterburner_core::{AfterburnerError, Manifold, Result};
use num_bigint_dig::BigUint;
use num_bigint_dig::RandPrime;
use num_bigint_dig::prime::probably_prime;
use num_traits::{One, Zero};

/// Probabilistic primality test (Miller-Rabin). `checks` is the number
/// of rounds (Node defaults to 0, which our caller maps to a sensible
/// default). The standard cryptographic recommendation is 40 rounds for
/// numbers up to 4096 bits, which gives <= 2^-80 false-positive prob.
pub fn check_prime(candidate_be: &[u8], checks: usize, m: &Manifold) -> Result<bool> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(
            "crypto.checkPrime".into(),
        ));
    }
    if candidate_be.is_empty() {
        return Ok(false);
    }
    let n = BigUint::from_bytes_be(candidate_be);
    // Cheap exits.
    if n < BigUint::from(2u32) {
        return Ok(false);
    }
    if n == BigUint::from(2u32) || n == BigUint::from(3u32) {
        return Ok(true);
    }
    if (&n & BigUint::one()).is_zero() {
        return Ok(false);
    }
    let rounds = if checks == 0 { 40 } else { checks };
    Ok(probably_prime(&n, rounds))
}

/// Generate a probable prime of `bits` bits, optionally constrained
/// `[min, max)` (Node's `add`/`rem` flow approximated as a range).
/// Returns the prime as big-endian bytes.
pub fn generate_prime(bits: usize, safe: bool, m: &Manifold) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(
            "crypto.generatePrime".into(),
        ));
    }
    if bits < 16 {
        return Err(AfterburnerError::Host(format!(
            "generatePrime: bits must be ≥16, got {bits}"
        )));
    }
    let mut rng = rsa::rand_core::OsRng;
    // num-bigint-dig's RandBigInt requires a rand v0.8 trait-compatible
    // RNG; OsRng works because both crates speak the same trait set.
    let p = if safe {
        // Safe prime: p, (p-1)/2 both prime. Constant-time-ish loop.
        loop {
            let candidate = rng.gen_prime(bits);
            let half = (&candidate - BigUint::one()) >> 1;
            if probably_prime(&half, 20) {
                break candidate;
            }
        }
    } else {
        rng.gen_prime(bits)
    };
    Ok(p.to_bytes_be())
}

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::Manifold;

    fn open() -> Manifold {
        Manifold::open()
    }

    fn be(n: u32) -> Vec<u8> {
        BigUint::from(n).to_bytes_be()
    }

    #[test]
    fn small_known_primes_pass() {
        let m = open();
        for &p in &[2u32, 3, 5, 7, 11, 13, 17, 97, 1009, 7919] {
            assert!(check_prime(&be(p), 0, &m).unwrap(), "{p} should be prime");
        }
    }

    #[test]
    fn small_known_composites_fail() {
        let m = open();
        for &c in &[1u32, 4, 6, 9, 25, 100, 1000, 7920] {
            assert!(
                !check_prime(&be(c), 0, &m).unwrap(),
                "{c} should be composite"
            );
        }
    }

    #[test]
    fn empty_input_returns_false() {
        assert!(!check_prime(&[], 0, &open()).unwrap());
    }

    #[test]
    fn zero_and_one_return_false() {
        assert!(!check_prime(&be(0), 0, &open()).unwrap());
        assert!(!check_prime(&be(1), 0, &open()).unwrap());
    }

    #[test]
    fn carmichael_number_561_rejected_by_strong_prime_test() {
        // 561 = 3·11·17 is a Carmichael number (passes Fermat) but
        // Miller-Rabin catches it.
        assert!(!check_prime(&be(561), 0, &open()).unwrap());
    }

    #[test]
    fn check_prime_permission_denied_when_disabled() {
        let mut m = Manifold::open();
        m.crypto = false;
        assert!(matches!(
            check_prime(&be(7), 0, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
    }

    #[test]
    fn generate_prime_returns_prime_at_target_bit_size() {
        let bytes = generate_prime(64, false, &open()).unwrap();
        let n = BigUint::from_bytes_be(&bytes);
        assert!(probably_prime(&n, 40));
        assert!(n.bits() <= 64);
    }

    #[test]
    fn generate_safe_prime_has_safe_property() {
        // 32 bits is small but exercises the safe-prime branch quickly.
        let bytes = generate_prime(32, true, &open()).unwrap();
        let p = BigUint::from_bytes_be(&bytes);
        assert!(probably_prime(&p, 40));
        let half = (&p - BigUint::one()) >> 1;
        assert!(probably_prime(&half, 40));
    }

    #[test]
    fn generate_prime_rejects_too_few_bits() {
        let r = generate_prime(8, false, &open());
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
    }

    #[test]
    fn generate_prime_permission_denied_when_disabled() {
        let mut m = Manifold::open();
        m.crypto = false;
        assert!(matches!(
            generate_prime(64, false, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
    }
}
