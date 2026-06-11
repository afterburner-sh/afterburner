// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Shared port-claim registry for multi-shard daemon coordinators.
//!
//! `DaemonNet` / `DaemonTls` / `DaemonDgram` each live per-shard in
//! `HostState`. When a daemon-init source calls
//! `net.createServer().listen(3000)`, every shard's coordinator
//! tries to bind port 3000 — without arbitration, only one shard
//! wins and the others fail with EADDRINUSE, killing daemon-init.
//!
//! `SharedPortClaims` is a process-shared, lock-free port arbiter
//! built on `kovan_map::HopscotchMap::get_or_insert` (CAS-based).
//! All shard-local coordinators consult it before binding:
//!
//! * The first shard to call `try_claim(port)` becomes the
//!   **owner** and proceeds with the real `bind(2)` + listener task.
//! * Subsequent shards become **followers** — they get the same
//!   id back and treat their `listen()` as a no-op (no bind, no
//!   listener task spawned). The user's JS sees a live listener,
//!   the kernel sees only one bound socket.
//!
//! ## Connection-load semantics
//!
//! Unlike HTTP (where the central event channel fans accepts out
//! to every shard via the pool's RR dispatcher), raw TCP / TLS /
//! UDP listeners feed connections only to the **owner** shard's
//! event queue. The follower shards' `server.on('connection')`
//! / `socket.on('message')` handlers never fire for that port.
//!
//! Concretely: a multi-shard daemon serving HTTP gets N-way
//! parallelism; the same daemon serving raw TCP gets 1-way
//! (only the binding shard's CPU is used for that listener).
//! For workloads that need N-way TCP throughput, front the
//! service with HTTP, or run with `BURN_SHARDS=1` for explicit
//! single-shard semantics.
//!
//! This trade-off is acceptable because the alternative —
//! cross-shard FD passing or SO_REUSEPORT — adds significant
//! complexity (the kernel hashes connections across listeners
//! by 4-tuple, which doesn't load-balance evenly under bursty
//! traffic; FD passing introduces ordering races between accept
//! and dispatch). Listener compatibility (no init crash) is the
//! security-relevant property; throughput parallelism for raw
//! sockets is a separate phase.

#![cfg(feature = "daemon")]

use kovan_map::HopscotchMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

pub type ServerId = i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimResult {
    /// We won the claim race. The caller is responsible for
    /// binding the real socket and spawning the listener task.
    Owner(ServerId),
    /// Another shard already claimed this port. The caller should
    /// register a follower listener — allocate a local server_id
    /// for JS bookkeeping, but do not bind. Connection events
    /// flow only through the owner shard.
    Follower(ServerId),
}

/// Process-shared port-claim arbiter. Lives in an `Arc` and is
/// shared across all per-shard coordinator instances.
pub struct SharedPortClaims {
    /// port → owning server_id. The first shard to insert wins.
    claims: HopscotchMap<u16, ServerId>,
    /// Monotonic id allocator. Each call to `try_claim` consumes
    /// one id regardless of outcome (the loser still emits an id
    /// to its caller; `get_or_insert` returns the winner's id but
    /// the loser's id is just discarded — no leak, no reuse).
    next_id: AtomicI32,
}

impl SharedPortClaims {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            claims: HopscotchMap::new(),
            next_id: AtomicI32::new(1),
        })
    }

    /// Lock-free try-claim. The kovan map's `get_or_insert` is a
    /// CAS — N shards racing on the same port converge atomically
    /// to a single winner. No mutex, no syscall on the uncontended
    /// path (the contended path's only real cost is the kernel's
    /// own bind arbitration, which the owner handles).
    pub fn try_claim(&self, port: u16) -> ClaimResult {
        let new_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let claimed = self.claims.get_or_insert(port, new_id);
        if claimed == new_id {
            ClaimResult::Owner(new_id)
        } else {
            ClaimResult::Follower(claimed)
        }
    }

    /// Release a claim. The owner shard calls this when its
    /// `server.close()` fires. Followers must NOT call this —
    /// they don't own the claim. Idempotent: removing a missing
    /// port is a no-op.
    ///
    /// Loops `remove` until it returns `None`. Reason: kovan-map's
    /// `HopscotchMap` allows transient duplicates of the same key
    /// when multiple threads concurrently `get_or_insert` the
    /// same key (per the inline comment in `get_or_insert` source:
    /// "the CAS-then-hop-bit window allows duplicates"). A single
    /// `remove` clears only the first matching entry it finds; if
    /// duplicates remain, the next `try_claim` (after release)
    /// would see one of the leftover entries and return
    /// `Follower(stale_id)` instead of `Owner(new_id)`. Looping
    /// drains all duplicates so the port is genuinely free.
    pub fn release(&self, port: u16) {
        while self.claims.remove(&port).is_some() {}
    }

    /// Look up the current owner id for a port, if any. Used by
    /// tests to verify the arbiter state.
    pub fn owner(&self, port: u16) -> Option<ServerId> {
        self.claims.get(&port)
    }
}

impl std::fmt::Debug for SharedPortClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedPortClaims")
            .field("next_id", &self.next_id.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
