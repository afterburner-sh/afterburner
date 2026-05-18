// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Per-thread active [`HostContext`]. Same activation pattern as
//! `state_active` / `active_manifold`: the engine drops a context
//! handle into a thread-local slot before running user JS and clears
//! it after. `__host_read_column` / `__host_emit_row` globals consult
//! the slot.

use afterburner_core::HostContext;
use std::cell::RefCell;
use std::sync::Arc;

thread_local! {
    static ACTIVE: RefCell<Option<Arc<dyn HostContext>>> = const { RefCell::new(None) };
}

pub fn activate(ctx: Arc<dyn HostContext>) -> ActiveGuard {
    let prev = ACTIVE.with(|s| s.replace(Some(ctx)));
    ActiveGuard { prev }
}

/// Run `f` against the active context. If no embedder has set one,
/// the function is called with `None` — caller decides the default.
pub fn with<R>(f: impl FnOnce(Option<&Arc<dyn HostContext>>) -> R) -> R {
    ACTIVE.with(|slot| {
        let borrow = slot.borrow();
        f(borrow.as_ref())
    })
}

pub struct ActiveGuard {
    prev: Option<Arc<dyn HostContext>>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        ACTIVE.with(|s| *s.borrow_mut() = prev);
    }
}
