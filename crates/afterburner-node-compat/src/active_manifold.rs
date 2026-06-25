// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Per-thread active [`Manifold`].
//!
//! Globals registered on a long-lived `rquickjs::Context` can't easily
//! close over per-thrust state, so the ignite engine drops the active
//! manifold into a thread-local slot before running the user script and
//! clears it after. Closures read the slot at call time.

use afterburner_core::{AfterburnerError, Manifold, Result};
use std::cell::RefCell;

thread_local! {
    static ACTIVE: RefCell<Option<Manifold>> = const { RefCell::new(None) };
}

/// Install `m` as the manifold for the current thread. Returns a guard
/// that restores the previous value when dropped - allowing nested
/// activations (rarely useful, but safer than a bare setter).
pub fn activate(m: Manifold) -> ActiveGuard {
    let prev = ACTIVE.with(|s| s.replace(Some(m)));
    ActiveGuard { prev }
}

/// Run `f` with a borrowed reference to the active manifold. Returns
/// `PermissionDenied` when no manifold is active - callers should always
/// install one via `activate` before running user JS.
pub fn with<R>(f: impl FnOnce(&Manifold) -> Result<R>) -> Result<R> {
    ACTIVE.with(|slot| {
        let borrow = slot.borrow();
        match borrow.as_ref() {
            Some(m) => f(m),
            None => Err(AfterburnerError::PermissionDenied(
                "no active manifold (internal): host function called outside a thrust".into(),
            )),
        }
    })
}

pub struct ActiveGuard {
    prev: Option<Manifold>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        ACTIVE.with(|s| *s.borrow_mut() = prev);
    }
}
