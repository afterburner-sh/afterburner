// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Crypto host functions — SHA-2 family hashes, MD5, HMAC, secure random.
//!
//! Gated behind `Manifold::crypto`; a disabled manifold returns
//! `PermissionDenied` for every operation.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use afterburner_core::{AfterburnerError, Manifold, Result};
use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Shake128, Shake256};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Incremental digest state for streaming sign / verify and hash.
/// `Clone` because the host exposes an `update` primitive that takes
/// the current state, feeds the new chunk, and stores the new state
/// back — cloning is how we avoid interior-mutability + sync primitives.
#[derive(Clone)]
pub enum DigestState {
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Md5(Md5),
    /// SHAKE is a XOF — variable-length output. We accumulate input
    /// state here; finalization picks the byte length at digest time
    /// (defaults match Node: shake128→16 bytes, shake256→32 bytes).
    Shake128(Shake128),
    Shake256(Shake256),
}

impl DigestState {
    /// Build a fresh digest state for `algorithm`. Accepts:
    /// - sign algorithm codes: `RS256` (sha-256), `ES256` (sha-256),
    ///   `RS384` (sha-384), `RS512` (sha-512).
    /// - hash names (lowercase): `sha1`, `sha224`, `sha256`, `sha384`,
    ///   `sha512`, `md5`. SHA-1 is included for parity with Node's
    ///   getHashes() — callers requesting cryptographic strength
    ///   should pick a SHA-2 variant.
    pub fn new(algorithm: &str) -> Result<Self> {
        match algorithm {
            "sha1" => Ok(DigestState::Sha1(Sha1::new())),
            "sha224" => Ok(DigestState::Sha224(Sha224::new())),
            "RS256" | "ES256" | "sha256" => Ok(DigestState::Sha256(Sha256::new())),
            "RS384" | "sha384" => Ok(DigestState::Sha384(Sha384::new())),
            "RS512" | "sha512" => Ok(DigestState::Sha512(Sha512::new())),
            "md5" => Ok(DigestState::Md5(Md5::new())),
            "shake128" => Ok(DigestState::Shake128(Shake128::default())),
            "shake256" => Ok(DigestState::Shake256(Shake256::default())),
            other => Err(AfterburnerError::Host(format!(
                "digest: unsupported algorithm '{other}'"
            ))),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            DigestState::Sha1(h) => h.update(data),
            DigestState::Sha224(h) => h.update(data),
            DigestState::Sha256(h) => h.update(data),
            DigestState::Sha384(h) => h.update(data),
            DigestState::Sha512(h) => h.update(data),
            DigestState::Md5(h) => h.update(data),
            DigestState::Shake128(h) => sha3::digest::Update::update(h, data),
            DigestState::Shake256(h) => sha3::digest::Update::update(h, data),
        }
    }

    /// Consume the state and return the raw digest bytes. SHAKE is a
    /// XOF; without a caller-supplied length we emit Node's default
    /// (shake128 → 16 bytes, shake256 → 32 bytes).
    pub fn finalize_bytes(self) -> Vec<u8> {
        self.finalize_bytes_n(0)
    }

    /// Same as `finalize_bytes` but allows variable-length output for
    /// XOF algorithms. `n_override == 0` selects the default length per
    /// algorithm. Non-XOF algorithms ignore `n_override`.
    pub fn finalize_bytes_n(self, n_override: usize) -> Vec<u8> {
        match self {
            DigestState::Sha1(h) => h.finalize().to_vec(),
            DigestState::Sha224(h) => h.finalize().to_vec(),
            DigestState::Sha256(h) => h.finalize().to_vec(),
            DigestState::Sha384(h) => h.finalize().to_vec(),
            DigestState::Sha512(h) => h.finalize().to_vec(),
            DigestState::Md5(h) => h.finalize().to_vec(),
            DigestState::Shake128(h) => {
                let n = if n_override == 0 { 16 } else { n_override };
                let mut out = vec![0u8; n];
                let mut reader = h.finalize_xof();
                reader.read(&mut out);
                out
            }
            DigestState::Shake256(h) => {
                let n = if n_override == 0 { 32 } else { n_override };
                let mut out = vec![0u8; n];
                let mut reader = h.finalize_xof();
                reader.read(&mut out);
                out
            }
        }
    }
}

/// Incremental HMAC state for streaming `createHmac`. Same
/// `Clone`-on-update pattern as [`DigestState`]. The key is embedded
/// at construction time — HMAC doesn't accept a key change mid-stream.
#[derive(Clone)]
pub enum HmacState {
    Sha1(Hmac<Sha1>),
    Sha224(Hmac<Sha224>),
    Sha256(Hmac<Sha256>),
    Sha384(Hmac<Sha384>),
    Sha512(Hmac<Sha512>),
    Md5(Hmac<Md5>),
}

impl HmacState {
    pub fn new(algorithm: &str, key: &[u8]) -> Result<Self> {
        // Helper macro keeps the per-algorithm arms small and the
        // error-conversion uniform. Every `Hmac<H>` impls
        // `Mac::new_from_slice` so this generalizes cleanly.
        macro_rules! make {
            ($variant:ident, $hash:ty) => {
                <Hmac<$hash> as Mac>::new_from_slice(key)
                    .map(HmacState::$variant)
                    .map_err(|e| AfterburnerError::Host(format!("hmac key: {e}")))
            };
        }
        match algorithm {
            "sha1" => make!(Sha1, Sha1),
            "sha224" => make!(Sha224, Sha224),
            "sha256" => make!(Sha256, Sha256),
            "sha384" => make!(Sha384, Sha384),
            "sha512" => make!(Sha512, Sha512),
            "md5" => make!(Md5, Md5),
            other => Err(AfterburnerError::Host(format!(
                "hmac: unsupported algorithm '{other}'"
            ))),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            HmacState::Sha1(m) => m.update(data),
            HmacState::Sha224(m) => m.update(data),
            HmacState::Sha256(m) => m.update(data),
            HmacState::Sha384(m) => m.update(data),
            HmacState::Sha512(m) => m.update(data),
            HmacState::Md5(m) => m.update(data),
        }
    }

    pub fn finalize_bytes(self) -> Vec<u8> {
        match self {
            HmacState::Sha1(m) => m.finalize().into_bytes().to_vec(),
            HmacState::Sha224(m) => m.finalize().into_bytes().to_vec(),
            HmacState::Sha256(m) => m.finalize().into_bytes().to_vec(),
            HmacState::Sha384(m) => m.finalize().into_bytes().to_vec(),
            HmacState::Sha512(m) => m.finalize().into_bytes().to_vec(),
            HmacState::Md5(m) => m.finalize().into_bytes().to_vec(),
        }
    }
}

/// Finalize an accumulated digest with an RSA/ECDSA private key and
/// produce a raw signature. The digest state is consumed.
pub fn sign_finalize(
    algorithm: &str,
    key_pem: &str,
    state: DigestState,
    m: &Manifold,
) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.sign({algorithm})"
        )));
    }
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{RandomizedDigestSigner, SignatureEncoding};
    let mut rng = rsa::rand_core::OsRng;
    match (algorithm, state) {
        ("RS256", DigestState::Sha256(hasher)) => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS256 key: {e}")))?;
            let signer: SigningKey<Sha256> = SigningKey::<Sha256>::new(key);
            Ok(signer
                .sign_digest_with_rng(&mut rng, hasher)
                .to_bytes()
                .to_vec())
        }
        ("RS384", DigestState::Sha384(hasher)) => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS384 key: {e}")))?;
            let signer: SigningKey<Sha384> = SigningKey::<Sha384>::new(key);
            Ok(signer
                .sign_digest_with_rng(&mut rng, hasher)
                .to_bytes()
                .to_vec())
        }
        ("RS512", DigestState::Sha512(hasher)) => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS512 key: {e}")))?;
            let signer: SigningKey<Sha512> = SigningKey::<Sha512>::new(key);
            Ok(signer
                .sign_digest_with_rng(&mut rng, hasher)
                .to_bytes()
                .to_vec())
        }
        ("ES256", DigestState::Sha256(hasher)) => {
            use p256::ecdsa::signature::DigestSigner;
            use p256::ecdsa::{Signature, SigningKey as EcdsaKey};
            use p256::pkcs8::DecodePrivateKey as _;
            let key = EcdsaKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("ES256 key: {e}")))?;
            let sig: Signature = key.sign_digest(hasher);
            Ok(sig.to_bytes().to_vec())
        }
        (other, _) => Err(AfterburnerError::Host(format!(
            "sign/verify: algorithm / digest mismatch for '{other}'"
        ))),
    }
}

/// Finalize an accumulated digest and verify against `sig_bytes`.
pub fn verify_finalize(
    algorithm: &str,
    key_pem: &str,
    state: DigestState,
    sig_bytes: &[u8],
    m: &Manifold,
) -> Result<bool> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.verify({algorithm})"
        )));
    }
    use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::DigestVerifier;
    match (algorithm, state) {
        ("RS256", DigestState::Sha256(hasher)) => {
            let key = rsa::RsaPublicKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS256 key: {e}")))?;
            let verifier: VerifyingKey<Sha256> = VerifyingKey::<Sha256>::new(key);
            let sig = RsaSig::try_from(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("RS256 sig: {e}")))?;
            Ok(verifier.verify_digest(hasher, &sig).is_ok())
        }
        ("RS384", DigestState::Sha384(hasher)) => {
            let key = rsa::RsaPublicKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS384 key: {e}")))?;
            let verifier: VerifyingKey<Sha384> = VerifyingKey::<Sha384>::new(key);
            let sig = RsaSig::try_from(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("RS384 sig: {e}")))?;
            Ok(verifier.verify_digest(hasher, &sig).is_ok())
        }
        ("RS512", DigestState::Sha512(hasher)) => {
            let key = rsa::RsaPublicKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS512 key: {e}")))?;
            let verifier: VerifyingKey<Sha512> = VerifyingKey::<Sha512>::new(key);
            let sig = RsaSig::try_from(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("RS512 sig: {e}")))?;
            Ok(verifier.verify_digest(hasher, &sig).is_ok())
        }
        ("ES256", DigestState::Sha256(hasher)) => {
            use p256::ecdsa::signature::DigestVerifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            use p256::pkcs8::DecodePublicKey as _;
            let key = VerifyingKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("ES256 key: {e}")))?;
            let sig = Signature::from_slice(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("ES256 sig: {e}")))?;
            Ok(key.verify_digest(hasher, &sig).is_ok())
        }
        (other, _) => Err(AfterburnerError::Host(format!(
            "sign/verify: algorithm / digest mismatch for '{other}'"
        ))),
    }
}

/// Hash `data` with the named algorithm. Supported: `md5`, `sha1` (no —
/// too weak, rejected), `sha256`, `sha384`, `sha512`.
pub fn hash(algorithm: &str, data: &[u8], m: &Manifold) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.createHash({algorithm})"
        )));
    }
    // Delegate to the streaming state type so one-shot and streaming
    // share a single algorithm whitelist + per-algo crate. This keeps
    // sha1/sha224/sha256/sha384/sha512/md5 coverage in lockstep.
    let mut s = DigestState::new(&algorithm.to_ascii_lowercase())
        .map_err(|e| AfterburnerError::Host(format!("crypto.hash: {e}")))?;
    s.update(data);
    Ok(s.finalize_bytes())
}

/// HMAC with the named algorithm.
pub fn hmac(algorithm: &str, key: &[u8], data: &[u8], m: &Manifold) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.createHmac({algorithm})"
        )));
    }
    let mut s = HmacState::new(&algorithm.to_ascii_lowercase(), key)
        .map_err(|e| AfterburnerError::Host(format!("crypto.hmac: {e}")))?;
    s.update(data);
    Ok(s.finalize_bytes())
}

/// Fill a buffer with cryptographically strong random bytes.
pub fn random_bytes(len: usize, m: &Manifold) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(
            "crypto.randomBytes".into(),
        ));
    }
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out)
        .map_err(|e| AfterburnerError::Host(format!("getrandom: {e}")))?;
    Ok(out)
}

/// Version-4 UUID (random).
pub fn random_uuid(m: &Manifold) -> Result<String> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(
            "crypto.randomUUID".into(),
        ));
    }
    Ok(uuid::Uuid::new_v4().to_string())
}

/// AES-GCM encrypt. `algo` is `aes-128-gcm` or `aes-256-gcm`. The nonce
/// must be 12 bytes. Returns `ciphertext || 16-byte-tag`.
pub fn aes_gcm_encrypt(
    algo: &str,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    aad: &[u8],
    m: &Manifold,
) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.{algo}.encrypt"
        )));
    }
    if nonce.len() != 12 {
        return Err(AfterburnerError::Host(format!(
            "{algo}: nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }
    let nonce = Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload { msg: data, aad };
    match algo {
        "aes-128-gcm" => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key: {e}")))?;
            cipher
                .encrypt(nonce, payload)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: encrypt: {e}")))
        }
        "aes-256-gcm" => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key: {e}")))?;
            cipher
                .encrypt(nonce, payload)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: encrypt: {e}")))
        }
        other => Err(AfterburnerError::Host(format!(
            "unsupported cipher '{other}'"
        ))),
    }
}

pub fn aes_gcm_decrypt(
    algo: &str,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    aad: &[u8],
    m: &Manifold,
) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.{algo}.decrypt"
        )));
    }
    if nonce.len() != 12 {
        return Err(AfterburnerError::Host(format!(
            "{algo}: nonce must be 12 bytes, got {}",
            nonce.len()
        )));
    }
    let nonce = Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload { msg: data, aad };
    match algo {
        "aes-128-gcm" => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key: {e}")))?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: decrypt: {e}")))
        }
        "aes-256-gcm" => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key: {e}")))?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: decrypt: {e}")))
        }
        other => Err(AfterburnerError::Host(format!(
            "unsupported cipher '{other}'"
        ))),
    }
}

/// AES-CBC with PKCS#7 padding. `algo` is `aes-128-cbc` or `aes-256-cbc`.
pub fn aes_cbc_encrypt(
    algo: &str,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    m: &Manifold,
) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.{algo}.encrypt"
        )));
    }
    use aes::cipher::block_padding::Pkcs7;
    if iv.len() != 16 {
        return Err(AfterburnerError::Host(format!(
            "{algo}: iv must be 16 bytes, got {}",
            iv.len()
        )));
    }
    match algo {
        "aes-128-cbc" => {
            let enc = Aes128CbcEnc::new_from_slices(key, iv)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key/iv: {e}")))?;
            Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(data))
        }
        "aes-256-cbc" => {
            let enc = Aes256CbcEnc::new_from_slices(key, iv)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key/iv: {e}")))?;
            Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(data))
        }
        other => Err(AfterburnerError::Host(format!(
            "unsupported cipher '{other}'"
        ))),
    }
}

pub fn aes_cbc_decrypt(
    algo: &str,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    m: &Manifold,
) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.{algo}.decrypt"
        )));
    }
    use aes::cipher::block_padding::Pkcs7;
    if iv.len() != 16 {
        return Err(AfterburnerError::Host(format!(
            "{algo}: iv must be 16 bytes, got {}",
            iv.len()
        )));
    }
    match algo {
        "aes-128-cbc" => {
            let dec = Aes128CbcDec::new_from_slices(key, iv)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key/iv: {e}")))?;
            dec.decrypt_padded_vec_mut::<Pkcs7>(data)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: decrypt: {e}")))
        }
        "aes-256-cbc" => {
            let dec = Aes256CbcDec::new_from_slices(key, iv)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: key/iv: {e}")))?;
            dec.decrypt_padded_vec_mut::<Pkcs7>(data)
                .map_err(|e| AfterburnerError::Host(format!("{algo}: decrypt: {e}")))
        }
        other => Err(AfterburnerError::Host(format!(
            "unsupported cipher '{other}'"
        ))),
    }
}

/// PBKDF2-HMAC-SHA variants.
pub fn pbkdf2_sync(
    digest: &str,
    password: &[u8],
    salt: &[u8],
    iters: u32,
    key_len: usize,
    m: &Manifold,
) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(
            "crypto.pbkdf2Sync".into(),
        ));
    }
    let mut out = vec![0u8; key_len];
    match digest.to_ascii_lowercase().as_str() {
        "sha256" => pbkdf2_hmac::<Sha256>(password, salt, iters, &mut out),
        "sha384" => pbkdf2_hmac::<Sha384>(password, salt, iters, &mut out),
        "sha512" => pbkdf2_hmac::<Sha512>(password, salt, iters, &mut out),
        other => {
            return Err(AfterburnerError::Host(format!(
                "pbkdf2: unsupported digest '{other}'"
            )));
        }
    }
    Ok(out)
}

/// `scrypt` KDF with RFC 7914 parameters.
pub fn scrypt_sync(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    key_len: usize,
    m: &Manifold,
) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(
            "crypto.scryptSync".into(),
        ));
    }
    // `scrypt::Params` takes log2(N) as a u8. Reject non-power-of-2 N so
    // we don't silently alter the user's requested work factor.
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(AfterburnerError::Host(format!(
            "scrypt: N must be a power of 2, got {n}"
        )));
    }
    let log_n = n.trailing_zeros() as u8;
    let params = scrypt::Params::new(log_n, r, p, key_len)
        .map_err(|e| AfterburnerError::Host(format!("scrypt params: {e}")))?;
    let mut out = vec![0u8; key_len];
    scrypt::scrypt(password, salt, &params, &mut out)
        .map_err(|e| AfterburnerError::Host(format!("scrypt: {e}")))?;
    Ok(out)
}

/// Sign `data` with the private key. `algorithm` selects the algorithm:
/// `RS256`/`RS384`/`RS512` (RSA-PKCS#1 v1.5 over SHA-2),
/// `ES256` (ECDSA P-256 with SHA-256). Returns the raw signature bytes.
pub fn sign(algorithm: &str, key_pem: &str, data: &[u8], m: &Manifold) -> Result<Vec<u8>> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.sign({algorithm})"
        )));
    }
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    let mut rng = rsa::rand_core::OsRng;
    match algorithm {
        "RS256" => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS256: parse pem: {e}")))?;
            let signer: SigningKey<Sha256> = SigningKey::<Sha256>::new(key);
            let sig = signer.sign_with_rng(&mut rng, data);
            Ok(sig.to_bytes().to_vec())
        }
        "RS384" => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS384: parse pem: {e}")))?;
            let signer: SigningKey<Sha384> = SigningKey::<Sha384>::new(key);
            let sig = signer.sign_with_rng(&mut rng, data);
            Ok(sig.to_bytes().to_vec())
        }
        "RS512" => {
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS512: parse pem: {e}")))?;
            let signer: SigningKey<Sha512> = SigningKey::<Sha512>::new(key);
            let sig = signer.sign_with_rng(&mut rng, data);
            Ok(sig.to_bytes().to_vec())
        }
        "ES256" => {
            use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey, signature::Signer};
            use p256::pkcs8::DecodePrivateKey as _;
            let key = EcdsaSigningKey::from_pkcs8_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("ES256: parse pem: {e}")))?;
            let sig: Signature = key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
        other => Err(AfterburnerError::Host(format!(
            "sign: unsupported algorithm '{other}'"
        ))),
    }
}

/// Verify a signature.
pub fn verify(
    algorithm: &str,
    key_pem: &str,
    data: &[u8],
    sig_bytes: &[u8],
    m: &Manifold,
) -> Result<bool> {
    if !m.crypto {
        return Err(AfterburnerError::PermissionDenied(format!(
            "crypto.verify({algorithm})"
        )));
    }
    use rsa::pkcs1v15::{Signature as RsaSig, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    match algorithm {
        "RS256" => {
            let key = rsa::RsaPublicKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS256: parse pem: {e}")))?;
            let verifier: VerifyingKey<Sha256> = VerifyingKey::<Sha256>::new(key);
            let sig = RsaSig::try_from(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("RS256: bad sig: {e}")))?;
            Ok(verifier.verify(data, &sig).is_ok())
        }
        "RS384" => {
            let key = rsa::RsaPublicKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS384: parse pem: {e}")))?;
            let verifier: VerifyingKey<Sha384> = VerifyingKey::<Sha384>::new(key);
            let sig = RsaSig::try_from(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("RS384: bad sig: {e}")))?;
            Ok(verifier.verify(data, &sig).is_ok())
        }
        "RS512" => {
            let key = rsa::RsaPublicKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("RS512: parse pem: {e}")))?;
            let verifier: VerifyingKey<Sha512> = VerifyingKey::<Sha512>::new(key);
            let sig = RsaSig::try_from(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("RS512: bad sig: {e}")))?;
            Ok(verifier.verify(data, &sig).is_ok())
        }
        "ES256" => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            use p256::pkcs8::DecodePublicKey as _;
            let key = VerifyingKey::from_public_key_pem(key_pem)
                .map_err(|e| AfterburnerError::Host(format!("ES256: parse pem: {e}")))?;
            let sig = Signature::from_slice(sig_bytes)
                .map_err(|e| AfterburnerError::Host(format!("ES256: bad sig: {e}")))?;
            Ok(key.verify(data, &sig).is_ok())
        }
        other => Err(AfterburnerError::Host(format!(
            "verify: unsupported algorithm '{other}'"
        ))),
    }
}

/// Constant-time byte comparison.
pub fn timing_safe_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}
