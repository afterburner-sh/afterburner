// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Governed spawn wrapper for node-compat's capability helper threads
//! (the DNS resolver's per-call timeout worker in [`crate::dns_host`],
//! the sqlite3 shadow's per-connection worker in
//! [`crate::shadows::sqlite3`]).
//!
//! These threads are spawned deep inside host-call paths reached from
//! many call sites - plumbing a `ThreadGovernance` value through every
//! one is not viable, unlike the thrust pool or the adaptive compile
//! worker, which each own a single config-carrying constructor. Instead
//! every site here calls [`spawn_governed`], which reads the
//! process-wide governance an embedder installs once via
//! [`afterburner_core::governance::set_helper_governance`] and applies
//! it exactly like every other governed spawn in the workspace. Unset
//! (the default) is [`ThreadGovernance::default()`] - a pure no-op,
//! today's ungoverned behavior, byte-identical.

use afterburner_core::Result;
use afterburner_core::governance::helper_governance;
use std::thread::JoinHandle;

/// Spawn `body` as a node-compat capability helper thread named `name`,
/// governed by whatever [`afterburner_core::governance::set_helper_governance`]
/// last installed for this process (or ungoverned, if it was never
/// called). See the module doc for why this reads a process-wide value
/// instead of taking a `ThreadGovernance` parameter.
pub fn spawn_governed<F>(name: impl Into<String>, body: F) -> Result<JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    afterburner_core::governance::spawn_governed(name, helper_governance(), body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn spawn_governed_runs_the_body_and_names_the_thread() {
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = ran.clone();
        let (tx, rx) = kovan_channel::bounded::<String>(1);
        let handle = spawn_governed("test-node-compat-helper", move || {
            ran2.store(true, Ordering::Release);
            tx.send(std::thread::current().name().unwrap_or("").to_string());
        })
        .unwrap();
        handle.join().unwrap();
        assert!(ran.load(Ordering::Acquire));
        assert_eq!(rx.recv(), Some("test-node-compat-helper".to_string()));
    }
}
