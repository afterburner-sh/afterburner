// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Per-thread active [`SharedStateStore`].
//!
//! Same activation pattern as `active_manifold`: the engine drops a
//! state-store handle into a thread-local slot before running user JS
//! and clears it after. Host globals read from the slot at call time.

use afterburner_core::{AfterburnerError, Result, SharedStateStore};
use std::cell::RefCell;

thread_local! {
    static ACTIVE: RefCell<Option<SharedStateStore>> = const { RefCell::new(None) };
}

pub fn activate(store: SharedStateStore) -> ActiveGuard {
    let prev = ACTIVE.with(|s| s.replace(Some(store)));
    ActiveGuard { prev }
}

pub fn with<R>(f: impl FnOnce(&SharedStateStore) -> Result<R>) -> Result<R> {
    ACTIVE.with(|slot| {
        let borrow = slot.borrow();
        match borrow.as_ref() {
            Some(s) => f(s),
            None => Err(AfterburnerError::Host(
                "no active state store: engine did not provide one".into(),
            )),
        }
    })
}

pub struct ActiveGuard {
    prev: Option<SharedStateStore>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        ACTIVE.with(|s| *s.borrow_mut() = prev);
    }
}
