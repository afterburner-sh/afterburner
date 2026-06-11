// SPDX-License-Identifier: Apache-2.0
//! Content addressing: SHA-256 of the whole compressed `.afb`.
//!
//! This is the package identity used everywhere - the runtime's
//! `ScriptId.hash`, the local cache filename, the registry primary key, the
//! GCS object path. Unlike `afterburner_core::hex32` (an 8-byte *log* prefix),
//! [`hex`] here is the full 64-char address; do not truncate it.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes`.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Full 64-char lowercase hex of a 32-byte digest. Stable across machines.
pub fn hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        // Hand-rolled to avoid a formatting-machinery dependency on the hot
        // path; equivalent to `{:02x}` per byte.
        const LUT: &[u8; 16] = b"0123456789abcdef";
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0f) as usize] as char);
    }
    s
}

/// Parse a 64-char hex string back into a digest. Errors on bad length or
/// non-hex characters (`None`).
pub fn from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        out[i] = (hi as u8) << 4 | lo as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_sha256_of_empty() {
        // Well-known SHA-256("") vector.
        assert_eq!(
            hex(&digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn digest_is_deterministic_and_input_sensitive() {
        assert_eq!(digest(b"afterburner"), digest(b"afterburner"));
        assert_ne!(digest(b"afterburner"), digest(b"afterburneR"));
    }

    #[test]
    fn hex_is_64_lowercase_and_roundtrips() {
        let d = digest(b"hello");
        let h = hex(&d);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(from_hex(&h), Some(d));
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert_eq!(from_hex("xyz"), None);
        assert_eq!(from_hex(&"g".repeat(64)), None);
        assert_eq!(from_hex(&"a".repeat(63)), None);
    }
}
