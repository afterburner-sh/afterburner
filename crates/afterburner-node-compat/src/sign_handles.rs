// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Per-runtime handle store for streaming `crypto.createSign` /
//! `createVerify`. The JS API expects to keep a cursor alive across
//! `.update(chunk)` calls; each cursor maps to a [`DigestState`] kept
//! in a lock-free `HopscotchMap` keyed by an `AtomicU64`-allocated id.
//!
//! Because scripts are synchronous within a thrust and `DigestState`
//! is `Clone`, the update path "clone out, feed the chunk, insert
//! back" is race-free inside one thrust. Two concurrent thrusts each
//! hold their own [`SignHandleStore`] - one per `HostState` in the
//! WASM path, one per thread-local on the native path.

use crate::crypto_host::DigestState;
use afterburner_core::{AfterburnerError, Result};
use kovan_map::HopscotchMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct SignHandleStore {
    states: HopscotchMap<u64, DigestState>,
    next_id: AtomicU64,
}

impl SignHandleStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&self, algorithm: &str) -> Result<u64> {
        let state = DigestState::new(algorithm)?;
        // Start ids at 1 so `0` is reserved as "invalid" - the JS glue
        // can check the return value cheaply.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.states.insert(id, state);
        Ok(id)
    }

    pub fn update(&self, handle: u64, data: &[u8]) -> Result<()> {
        let mut state = self
            .states
            .get(&handle)
            .ok_or_else(|| AfterburnerError::Host(format!("sign handle {handle} not found")))?;
        state.update(data);
        self.states.insert(handle, state);
        Ok(())
    }

    /// Remove the handle and return the owned `DigestState` for
    /// one-shot finalization. Subsequent calls on the same handle
    /// fail with a clear message.
    pub fn take(&self, handle: u64) -> Result<DigestState> {
        self.states
            .remove(&handle)
            .ok_or_else(|| AfterburnerError::Host(format!("sign handle {handle} not found")))
    }
}
