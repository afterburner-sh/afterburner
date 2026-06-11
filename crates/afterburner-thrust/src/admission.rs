// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Token-bucket admission control - plan §8, T4.
//!
//! Per-tenant GCRA (Generic Cell Rate Algorithm - semantically a leaky
//! bucket) implemented lock-free over a single `AtomicU64` per tenant.
//! Nothing here uses `std::sync::Mutex` or `parking_lot`; tenant state
//! lives in a `kovan_map::HopscotchMap` keyed by `TenantId`.
//!
//! ### Capabilities note
//!
//! No POSIX real-time scheduling, no signals, no `timerfd` - just
//! `Instant::now()`. Safe under default Docker capability set. See
//! project memory `project_docker_cap_constraint`.
//!
//! ### Stale-tenant sweep (P3)
//!
//! A dedicated background thread (`afterburner-admission-sweep`)
//! periodically walks the bucket map and evicts tenants that haven't
//! advanced their TAT in `IDLE_THRESHOLD` (default 5 minutes). Bounds
//! map growth under multi-tenant churn - without it, a workload that
//! cycles through millions of distinct tenants would leak indefinitely.
//!
//! Sweep cadence is 30 s; shutdown is interruptible (100 ms-granular
//! sleep that re-checks the shutdown flag), so `Drop` returns within
//! ~100 ms even when the sweep is mid-sleep.

use kovan_map::HopscotchMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::TenantId;

/// How often the sweep thread runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Buckets idle for at least this long get evicted on the next sweep.
/// Five minutes covers normal traffic gaps without being so short that
/// periodically-active tenants pay the bucket-rebuild cost on every cycle.
const IDLE_THRESHOLD: Duration = Duration::from_secs(300);

/// Granularity of the interruptible sleep inside the sweep loop. Caps
/// `Drop`-time wait at this value.
const SHUTDOWN_POLL_GRANULARITY: Duration = Duration::from_millis(100);

/// Lock-free per-tenant GCRA. Cheap to construct; one atomic RMW on
/// the common accept path. Owns a background sweep thread that evicts
/// tenants idle past [`IDLE_THRESHOLD`].
pub(crate) struct TokenBucketAdmission {
    /// Nanoseconds per token (≈ 1 / rate).
    period_ns: u64,
    /// How far ahead of `now` the theoretical-arrival-time may drift
    /// before a request is rejected. Equivalently: the burst capacity
    /// expressed in nanoseconds.
    burst_ns: u64,
    /// Monotonic anchor for TAT (theoretical arrival time) values.
    epoch: Instant,
    /// Per-tenant TAT (ns since `epoch`). `Arc<AtomicU64>` so every
    /// caller hitting the same tenant CASes the same slot.
    /// `Arc<HopscotchMap<…>>` so the sweep thread can hold a clone.
    buckets: Arc<HopscotchMap<TenantId, Arc<AtomicU64>>>,
    /// Set on `Drop` to ask the sweep thread to exit at its next poll.
    sweep_shutdown: Arc<AtomicBool>,
    /// Joined on `Drop`. `Option` so `Drop` can `take()` it.
    sweep_thread: Option<JoinHandle<()>>,
}

impl TokenBucketAdmission {
    /// Build with `tokens_per_sec` refill rate and `burst_tokens` burst
    /// capacity. A `burst_tokens` of `0` is treated as `1` so a tenant
    /// that arrives exactly on the refill boundary isn't falsely
    /// rejected by rounding.
    pub fn new(tokens_per_sec: u64, burst_tokens: u64) -> Self {
        Self::new_with_intervals(tokens_per_sec, burst_tokens, IDLE_THRESHOLD, SWEEP_INTERVAL)
    }

    /// Same as [`Self::new`] but lets the caller override the sweep
    /// timing knobs. Used by tests that can't wait the production 5-minute
    /// idle threshold + 30-second cadence.
    pub fn new_with_intervals(
        tokens_per_sec: u64,
        burst_tokens: u64,
        idle_threshold: Duration,
        sweep_interval: Duration,
    ) -> Self {
        let tokens_per_sec = tokens_per_sec.max(1);
        let burst_tokens = burst_tokens.max(1);
        let period_ns = 1_000_000_000u64 / tokens_per_sec;
        let burst_ns = burst_tokens.saturating_mul(period_ns);
        let epoch = Instant::now();
        let buckets: Arc<HopscotchMap<TenantId, Arc<AtomicU64>>> = Arc::new(HopscotchMap::new());
        let sweep_shutdown = Arc::new(AtomicBool::new(false));

        let sweep_thread = {
            let buckets = buckets.clone();
            let shutdown = sweep_shutdown.clone();
            let idle_threshold_ns = idle_threshold.as_nanos() as u64;
            thread::Builder::new()
                .name("afterburner-admission-sweep".into())
                .spawn(move || {
                    sweep_loop(buckets, epoch, idle_threshold_ns, sweep_interval, shutdown)
                })
                .ok()
        };

        Self {
            period_ns,
            burst_ns,
            epoch,
            buckets,
            sweep_shutdown,
            sweep_thread,
        }
    }

    /// Number of currently-tracked tenant buckets. Useful for tests
    /// and for ops dashboards (memory pressure proxy).
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    #[inline]
    fn now_ns(&self) -> u64 {
        // Instant::elapsed is monotonic on Linux; safe against wall-clock
        // jumps. u128 → u64 truncation gives ~584 years of headroom from
        // process start, which is comfortably plenty.
        self.epoch.elapsed().as_nanos() as u64
    }

    /// Lookup-or-initialize a tenant's TAT slot. Safe against races -
    /// two concurrent first-touches coalesce onto whichever
    /// `insert_if_absent` won the insert.
    fn bucket(&self, tenant: TenantId) -> Arc<AtomicU64> {
        if let Some(b) = self.buckets.get(&tenant) {
            return b;
        }
        let fresh = Arc::new(AtomicU64::new(self.now_ns()));
        match self.buckets.insert_if_absent(tenant, fresh.clone()) {
            None => fresh,
            Some(existing) => existing,
        }
    }

    /// Attempt to admit one request. `Ok(())` = allowed;
    /// `Err(retry_after_ms)` = rate-limited.
    ///
    /// GCRA step:
    /// ```text
    /// tat_new = max(tat, now) + period
    /// if (tat_new - now) > burst: reject, retry after (tat_new - now - burst) ms
    /// else: CAS tat -> tat_new
    /// ```
    pub fn try_acquire(&self, tenant: TenantId) -> Result<(), u64> {
        let bucket = self.bucket(tenant);
        loop {
            let now = self.now_ns();
            let tat = bucket.load(Ordering::Relaxed);
            let tat_base = tat.max(now);
            let tat_new = tat_base.saturating_add(self.period_ns);
            let ahead = tat_new.saturating_sub(now);
            if ahead > self.burst_ns {
                let over_ns = ahead - self.burst_ns;
                // Round up to next ms so callers don't retry 0 ms early.
                let retry_ms = over_ns.div_ceil(1_000_000).max(1);
                return Err(retry_ms);
            }
            match bucket.compare_exchange(tat, tat_new, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Ok(()),
                // Contention: another thread updated tat. Retry with the
                // fresher value.
                Err(_) => continue,
            }
        }
    }
}

impl std::fmt::Debug for TokenBucketAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBucketAdmission")
            .field("period_ns", &self.period_ns)
            .field("burst_ns", &self.burst_ns)
            .field("buckets", &self.buckets.len())
            .finish_non_exhaustive()
    }
}

impl Drop for TokenBucketAdmission {
    fn drop(&mut self) {
        self.sweep_shutdown.store(true, Ordering::Release);
        if let Some(h) = self.sweep_thread.take() {
            let _ = h.join();
        }
    }
}

/// Walks the bucket map at [`SWEEP_INTERVAL`] and evicts entries whose
/// TAT lies more than `idle_threshold_ns` behind `now`. Re-checks the
/// TAT just before removal so a bucket that became active in the
/// interval isn't dropped - small races may still flap a freshly
/// rebuilt bucket, with the only effect being one full burst budget
/// for that tenant. Acceptable for a 5-minute idle window.
fn sweep_loop(
    buckets: Arc<HopscotchMap<TenantId, Arc<AtomicU64>>>,
    epoch: Instant,
    idle_threshold_ns: u64,
    sweep_interval: Duration,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        sleep_interruptible(sweep_interval, &shutdown);
        if shutdown.load(Ordering::Acquire) {
            break;
        }

        let now_ns = epoch.elapsed().as_nanos() as u64;
        let cutoff = now_ns.saturating_sub(idle_threshold_ns);

        // Collect candidates first (the iterator borrows the map; we
        // can't mutate while iterating).
        let stale: Vec<TenantId> = buckets
            .iter()
            .filter_map(|(t, tat)| {
                if tat.load(Ordering::Relaxed) < cutoff {
                    Some(t)
                } else {
                    None
                }
            })
            .collect();

        for t in stale {
            // Re-check before remove - bucket may have woken up.
            if let Some(tat) = buckets.get(&t)
                && tat.load(Ordering::Relaxed) < cutoff
            {
                buckets.remove(&t);
            }
        }
    }
}

/// Sleep for `total` but wake up every [`SHUTDOWN_POLL_GRANULARITY`]
/// to re-check the shutdown flag. Bounds `Drop`-time wait at the
/// granularity, not the full sweep interval.
fn sleep_interruptible(total: Duration, shutdown: &AtomicBool) {
    let mut elapsed = Duration::ZERO;
    while elapsed < total {
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        let chunk = SHUTDOWN_POLL_GRANULARITY.min(total - elapsed);
        thread::sleep(chunk);
        elapsed += chunk;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    fn tid(n: u32) -> TenantId {
        TenantId::new(n).unwrap()
    }

    #[test]
    fn allows_up_to_burst_then_rejects() {
        // 100 tokens/sec, burst 5 → period 10 ms, burst window 50 ms.
        // Five tight-loop acquires complete in <1 ms even on a loaded
        // box, well inside the 50 ms window - so the 6th deterministically
        // rejects. Earlier the test used 1 000 tokens/sec (1 ms period,
        // 5 ms window), which raced with debug-mode HopscotchMap
        // lookups under CI load and occasionally allowed the 6th call.
        let adm = TokenBucketAdmission::new(100, 5);
        let t = tid(1);
        for i in 0..5 {
            adm.try_acquire(t)
                .unwrap_or_else(|_| panic!("call {i} should allow"));
        }
        // The 6th is over the burst and must be rejected.
        assert!(adm.try_acquire(t).is_err());
    }

    #[test]
    fn distinct_tenants_are_isolated() {
        // 10 tokens/sec, burst 1: each tenant allowed once, then rejected.
        let adm = TokenBucketAdmission::new(10, 1);
        let a = tid(1);
        let b = tid(2);
        adm.try_acquire(a).unwrap();
        assert!(adm.try_acquire(a).is_err());
        // b is untouched - must still have one token.
        adm.try_acquire(b).unwrap();
        assert!(adm.try_acquire(b).is_err());
    }

    #[test]
    fn reports_sensible_retry_after() {
        // 100 tokens/sec → 10ms period. burst 1. Reject → retry ≤ 10ms.
        let adm = TokenBucketAdmission::new(100, 1);
        let t = tid(3);
        adm.try_acquire(t).unwrap();
        let ms = adm.try_acquire(t).unwrap_err();
        assert!(
            (1..=15).contains(&ms),
            "retry_after_ms out of expected band: {ms}"
        );
    }

    #[test]
    fn refill_allows_retry_after_waiting() {
        // 500 tokens/sec, burst 1.
        let adm = TokenBucketAdmission::new(500, 1);
        let t = tid(4);
        adm.try_acquire(t).unwrap();
        // Wait for one refill period (2ms) plus slack.
        thread::sleep(Duration::from_millis(10));
        adm.try_acquire(t).unwrap();
    }

    #[test]
    fn zero_rate_does_not_panic() {
        // Sanity: constructor normalizes zero to 1, never divides by 0.
        let adm = TokenBucketAdmission::new(0, 0);
        let t = tid(5);
        // First call allowed (single burst slot). Second rejected.
        adm.try_acquire(t).unwrap();
        assert!(adm.try_acquire(t).is_err());
    }

    #[test]
    fn stale_tenants_are_evicted_by_sweep() {
        // 100ms idle threshold + 50ms sweep cadence so the test runs
        // in well under a second. Production defaults are 5min/30s.
        let adm = TokenBucketAdmission::new_with_intervals(
            1_000,
            5,
            Duration::from_millis(100),
            Duration::from_millis(50),
        );
        // Touch three tenants - each gets a bucket entry.
        adm.try_acquire(tid(101)).unwrap();
        adm.try_acquire(tid(102)).unwrap();
        adm.try_acquire(tid(103)).unwrap();
        assert_eq!(adm.bucket_count(), 3);

        // Wait long enough for the bucket TATs to be older than the
        // 100ms idle threshold, then for at least one sweep cycle to
        // run. 300ms covers idle + 1-2 sweep ticks comfortably.
        thread::sleep(Duration::from_millis(300));
        assert_eq!(
            adm.bucket_count(),
            0,
            "sweep should have evicted all idle tenants"
        );
    }

    #[test]
    fn active_tenants_are_not_evicted() {
        let adm = TokenBucketAdmission::new_with_intervals(
            1_000,
            5,
            Duration::from_millis(100),
            Duration::from_millis(50),
        );
        let t = tid(201);
        adm.try_acquire(t).unwrap();

        // Re-touch the bucket continuously so its TAT stays fresh.
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(300) {
            // Keep TAT current. Some calls will be rate-limited (only 5
            // burst slots); we don't care about the result, just the
            // TAT advance side-effect.
            let _ = adm.try_acquire(t);
            thread::sleep(Duration::from_millis(20));
        }

        assert_eq!(
            adm.bucket_count(),
            1,
            "active tenant must survive sweep cycles"
        );
    }

    #[test]
    fn drop_joins_sweep_thread_promptly() {
        let adm = TokenBucketAdmission::new_with_intervals(
            10,
            1,
            Duration::from_secs(60),
            // Long sweep - Drop must interrupt the sleep, not wait it out.
            Duration::from_secs(60),
        );
        adm.try_acquire(tid(301)).unwrap();
        let t0 = Instant::now();
        drop(adm);
        let took = t0.elapsed();
        assert!(
            took < Duration::from_secs(1),
            "Drop took too long ({took:?}); interruptible sleep failed"
        );
    }
}
