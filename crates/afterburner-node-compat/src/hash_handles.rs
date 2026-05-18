// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Per-runtime handle store for streaming `crypto.createHash` /
//! `createHmac`. Same `Clone`-on-update, lock-free-map pattern as
//! [`crate::sign_handles::SignHandleStore`], but with two handle kinds
//! (plain digest vs keyed HMAC) sharing one id space.
//!
//! Separate from `SignHandleStore` because the semantics differ —
//! `finalize_digest` doesn't take a key, while sign's finalize does —
//! and keeping them split makes each type's API obvious at the call
//! site without a chain of `match` arms.

use crate::crypto_host::{DigestState, HmacState};
use afterburner_core::{AfterburnerError, Result};
use kovan_map::HopscotchMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// One handle slot. A handle is either a plain digest (SHA-2 family,
/// MD5) or a keyed HMAC. `update` and `finalize` dispatch to whichever.
#[derive(Clone)]
pub enum HashHandleKind {
    Digest(DigestState),
    Hmac(HmacState),
}

#[derive(Default)]
pub struct HashHandleStore {
    states: HopscotchMap<u64, HashHandleKind>,
    next_id: AtomicU64,
}

impl HashHandleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a plain-digest handle. `algorithm` is a hash name
    /// (`sha256`, `sha384`, `sha512`, `md5`).
    pub fn open_digest(&self, algorithm: &str) -> Result<u64> {
        let state = DigestState::new(algorithm)?;
        let id = self.alloc_id();
        self.states.insert(id, HashHandleKind::Digest(state));
        Ok(id)
    }

    /// Open a keyed HMAC handle. `algorithm` is a hash name; `key` is
    /// the HMAC key bytes.
    pub fn open_hmac(&self, algorithm: &str, key: &[u8]) -> Result<u64> {
        let state = HmacState::new(algorithm, key)?;
        let id = self.alloc_id();
        self.states.insert(id, HashHandleKind::Hmac(state));
        Ok(id)
    }

    pub fn update(&self, handle: u64, data: &[u8]) -> Result<()> {
        let mut kind = self
            .states
            .get(&handle)
            .ok_or_else(|| AfterburnerError::Host(format!("hash handle {handle} not found")))?;
        match &mut kind {
            HashHandleKind::Digest(d) => d.update(data),
            HashHandleKind::Hmac(h) => h.update(data),
        }
        self.states.insert(handle, kind);
        Ok(())
    }

    /// Consume the handle and return the finalized digest bytes. Both
    /// digest and HMAC paths return the raw bytes — encoding (hex /
    /// base64) is the caller's job, same as the `hash()` one-shot.
    pub fn finalize(&self, handle: u64) -> Result<Vec<u8>> {
        let kind = self
            .states
            .remove(&handle)
            .ok_or_else(|| AfterburnerError::Host(format!("hash handle {handle} not found")))?;
        Ok(match kind {
            HashHandleKind::Digest(d) => d.finalize_bytes(),
            HashHandleKind::Hmac(h) => h.finalize_bytes(),
        })
    }

    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed) + 1
    }
}
