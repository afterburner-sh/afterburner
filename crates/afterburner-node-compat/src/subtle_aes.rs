// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Subtle Crypto AES additions — AES-CTR and AES-KW (RFC 3394).
//!
//! AES-GCM and AES-CBC live in `crypto_host.rs` (Node-API surface);
//! this module ships the Web-Crypto-only modes.

use aes::cipher::{KeyIvInit, StreamCipher};
use afterburner_core::{AfterburnerError, Result};

type Aes128Ctr64 = ctr::Ctr64BE<aes::Aes128>;
type Aes192Ctr64 = ctr::Ctr64BE<aes::Aes192>;
type Aes256Ctr64 = ctr::Ctr64BE<aes::Aes256>;

/// AES-CTR encrypt/decrypt (the same operation either direction).
/// Counter must be 16 bytes. Per Web Crypto, `length` is the
/// counter-block bit width — only 64 (Ctr64BE) and 128 are spec'd;
/// we ship 64 (matches Node's WebCrypto + browsers' default).
pub fn aes_ctr_apply(key: &[u8], counter: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if counter.len() != 16 {
        return Err(AfterburnerError::Host(format!(
            "AES-CTR: counter must be 16 bytes, got {}",
            counter.len()
        )));
    }
    let mut buf = data.to_vec();
    match key.len() {
        16 => {
            let mut c = Aes128Ctr64::new(key.into(), counter.into());
            c.apply_keystream(&mut buf);
        }
        24 => {
            let mut c = Aes192Ctr64::new(key.into(), counter.into());
            c.apply_keystream(&mut buf);
        }
        32 => {
            let mut c = Aes256Ctr64::new(key.into(), counter.into());
            c.apply_keystream(&mut buf);
        }
        n => {
            return Err(AfterburnerError::Host(format!(
                "AES-CTR: key must be 128/192/256 bits, got {}",
                n * 8
            )));
        }
    }
    Ok(buf)
}

/// AES-KW (RFC 3394) — wraps a target key with a key-encryption key.
/// Plaintext (target key) length must be a multiple of 8 bytes and at
/// least 16 bytes per RFC. Output is plaintext_len + 8 bytes.
pub fn aes_kw_wrap(kek: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    if target.len() < 16 || !target.len().is_multiple_of(8) {
        return Err(AfterburnerError::Host(format!(
            "AES-KW: plaintext must be ≥16 bytes and a multiple of 8, got {}",
            target.len()
        )));
    }
    let mut out = vec![0u8; target.len() + 8];
    match kek.len() {
        16 => aes_kw::KekAes128::new(kek.into())
            .wrap(target, &mut out)
            .map_err(|e| AfterburnerError::Host(format!("AES-KW wrap (128): {e}")))?,
        24 => aes_kw::KekAes192::new(kek.into())
            .wrap(target, &mut out)
            .map_err(|e| AfterburnerError::Host(format!("AES-KW wrap (192): {e}")))?,
        32 => aes_kw::KekAes256::new(kek.into())
            .wrap(target, &mut out)
            .map_err(|e| AfterburnerError::Host(format!("AES-KW wrap (256): {e}")))?,
        n => {
            return Err(AfterburnerError::Host(format!(
                "AES-KW: KEK must be 128/192/256 bits, got {}",
                n * 8
            )));
        }
    }
    Ok(out)
}

/// AES-KW unwrap. Authenticates via the RFC 3394 IV constant; a tampered
/// blob fails with a clear error rather than silently returning garbage.
pub fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(AfterburnerError::Host(format!(
            "AES-KW: ciphertext must be ≥24 bytes and a multiple of 8, got {}",
            wrapped.len()
        )));
    }
    let mut out = vec![0u8; wrapped.len() - 8];
    match kek.len() {
        16 => aes_kw::KekAes128::new(kek.into())
            .unwrap(wrapped, &mut out)
            .map_err(|e| AfterburnerError::Host(format!("AES-KW unwrap (128): {e}")))?,
        24 => aes_kw::KekAes192::new(kek.into())
            .unwrap(wrapped, &mut out)
            .map_err(|e| AfterburnerError::Host(format!("AES-KW unwrap (192): {e}")))?,
        32 => aes_kw::KekAes256::new(kek.into())
            .unwrap(wrapped, &mut out)
            .map_err(|e| AfterburnerError::Host(format!("AES-KW unwrap (256): {e}")))?,
        n => {
            return Err(AfterburnerError::Host(format!(
                "AES-KW: KEK must be 128/192/256 bits, got {}",
                n * 8
            )));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ctr_round_trips_three_key_sizes() {
        let counter = [0u8; 16];
        let data = b"the quick brown fox jumps over the lazy dog";
        for &k in &[16, 24, 32] {
            let key = vec![0xAA; k];
            let ct = aes_ctr_apply(&key, &counter, data).unwrap();
            assert_ne!(ct, data, "ciphertext = plaintext at key {k}");
            let pt = aes_ctr_apply(&key, &counter, &ct).unwrap();
            assert_eq!(pt, data, "round-trip broken at key {k}");
        }
    }

    #[test]
    fn aes_ctr_rejects_bad_counter_length() {
        let r = aes_ctr_apply(&[0u8; 16], &[0u8; 8], b"x");
        assert!(matches!(r, Err(AfterburnerError::Host(s)) if s.contains("counter")));
    }

    #[test]
    fn aes_ctr_rejects_bad_key_length() {
        let r = aes_ctr_apply(&[0u8; 7], &[0u8; 16], b"x");
        assert!(matches!(r, Err(AfterburnerError::Host(s)) if s.contains("key")));
    }

    #[test]
    fn aes_kw_wrap_unwrap_round_trips_for_each_kek_size() {
        let target = [0x42u8; 32];
        for &k in &[16, 24, 32] {
            let kek = vec![0x11; k];
            let wrapped = aes_kw_wrap(&kek, &target).unwrap();
            assert_eq!(wrapped.len(), target.len() + 8);
            let unwrapped = aes_kw_unwrap(&kek, &wrapped).unwrap();
            assert_eq!(unwrapped, target);
        }
    }

    #[test]
    fn aes_kw_unwrap_rejects_tampered_blob() {
        let kek = [0x11u8; 16];
        let target = [0x42u8; 16];
        let mut wrapped = aes_kw_wrap(&kek, &target).unwrap();
        wrapped[0] ^= 0xFF;
        let r = aes_kw_unwrap(&kek, &wrapped);
        assert!(r.is_err(), "tampered AES-KW blob must fail authentication");
    }

    #[test]
    fn aes_kw_rejects_short_target() {
        let kek = [0x11u8; 16];
        let r = aes_kw_wrap(&kek, &[0u8; 8]);
        assert!(matches!(r, Err(AfterburnerError::Host(s)) if s.contains("plaintext")));
    }

    #[test]
    fn aes_kw_rfc_3394_section_4_1_test_vector() {
        // RFC 3394 §4.1: 128-bit KEK, 128-bit data.
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let expected = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();
        let wrapped = aes_kw_wrap(&kek, &pt).unwrap();
        assert_eq!(wrapped, expected);
        let unwrapped = aes_kw_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, pt);
    }
}
