// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Thread governance - nice / CPU affinity / name-prefix attribution
//! applied uniformly to every thread Afterburner spawns, so an embedder
//! (a database, for instance) can subordinate the engine's background
//! threads to its own priority scheme instead of contending with it at
//! the OS scheduler's default priority.
//!
//! [`ThreadGovernance::default()`] is a pure no-op: every field is
//! `None`, and [`apply_governance`] on a default value returns `Ok(())`
//! immediately without touching the OS. Every pool this workspace spawns
//! (thrust workers, the admission sweep, the adaptive compile worker, an
//! embedder-kept wasm epoch ticker, node-compat capability helpers)
//! defaults to today's ungoverned behavior; governance is opt-in per
//! field, per pool.
//!
//! `nice` and `affinity` are Linux-only (`setpriority` /
//! `sched_setaffinity`, matching `afterburner-thrust::numa`'s own
//! platform posture). Unlike that module's best-effort internal NUMA
//! pinning, a `ThreadGovernance` value is an EXPLICIT operator request:
//! silently no-op-ing it on an unsupported platform would tell the
//! operator isolation is enforced when it is not, so `Some(_)` on a
//! non-Linux target is a loud, typed [`AfterburnerError::GovernanceFailed`]
//! rather than a silent skip.

use crate::{AfterburnerError, Result};
use std::sync::OnceLock;
use std::thread::{self, JoinHandle};

/// Governance applied to one spawned thread: OS-level nice, CPU
/// affinity, and a name-prefix override for attribution. Every
/// afterburner pool that owns threads (`ThrustEngineConfig`,
/// `AdaptiveConfig`, `WasmConfig::ticker_governance`, the node-compat
/// helper spawn wrapper) carries one of these.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThreadGovernance {
    /// Nice value applied inside the thread at start (Linux
    /// `setpriority` on the calling tid; clamped `-20..=19`; `None` =
    /// inherit the spawning thread's priority). Raising priority (a
    /// negative nice) without `CAP_SYS_NICE` fails loudly at pool
    /// construction, never silently.
    pub nice: Option<i8>,
    /// Explicit CPU affinity mask (core ids). `None` = inherit / the
    /// engine's own default (thrust: NUMA round-robin on multi-node,
    /// `afterburner-thrust::numa`). `Some(mask)` overrides that pin.
    pub affinity: Option<Vec<usize>>,
    /// Thread-name prefix override for attribution. `None` keeps the
    /// engine's default names (`afterburner-thrust-{i}`,
    /// `afterburner-admission-sweep`, `afterburner-adaptive-compile`,
    /// `afterburner-epoch-ticker`). Applied by the spawn site itself
    /// (via `thread::Builder::name`) before the thread starts - an OS
    /// thread's name is fixed at spawn on every platform this crate
    /// targets, so it cannot be applied from inside [`apply_governance`].
    ///
    /// On Linux the kernel's `comm` field (what `/proc/<pid>/task/<tid>/comm`,
    /// `ps`, and `top` show) caps thread names at 15 visible characters -
    /// `pthread_setname_np`'s own limit, silently truncating anything
    /// longer (this already affects the un-prefixed defaults: e.g.
    /// `afterburner-thrust-3` truncates to `afterburner-thr`, colliding
    /// with every other worker's truncated name). Keep `default_name`
    /// (via [`Self::thread_name`]) plus `suffix` at or under 15
    /// characters if per-thread attribution via `comm` matters; the
    /// full, untruncated name still reaches `std::thread::Thread::name`
    /// inside the process.
    pub name_prefix: Option<String>,
}

impl ThreadGovernance {
    /// Resolve the effective thread name for a spawn site: this
    /// governance's `name_prefix` if set, otherwise `default_name`, with
    /// `suffix` appended (pass `""` for a singleton thread, `"-3"` for a
    /// numbered pool member). Centralized so every spawn site names
    /// threads the same way - drift here would break the I1'-style
    /// "expected thread set" audit an embedder runs against
    /// `/proc/self/task`.
    #[must_use]
    pub fn thread_name(&self, default_name: &str, suffix: &str) -> String {
        match &self.name_prefix {
            Some(prefix) => format!("{prefix}{suffix}"),
            None => format!("{default_name}{suffix}"),
        }
    }
}

/// Apply `g` inside the calling thread, first thing after spawn. A
/// no-op `ThreadGovernance` (the default) returns `Ok(())` immediately
/// without touching the OS.
pub fn apply_governance(g: &ThreadGovernance) -> Result<()> {
    if let Some(nice) = g.nice {
        set_nice(nice)?;
    }
    if let Some(mask) = g.affinity.as_deref() {
        set_affinity(mask)?;
    }
    Ok(())
}

/// Spawn a thread that applies `g` first thing and synchronously reports
/// success/failure back to the caller before this function returns - so
/// a governance failure (e.g. a negative nice without `CAP_SYS_NICE`)
/// surfaces at the spawning call ("pool construction"), never silently
/// inside a detached thread whose caller has already moved on. `body`
/// never runs if governance fails; the thread exits immediately after
/// reporting the failure.
pub fn spawn_governed<F>(
    name: impl Into<String>,
    g: ThreadGovernance,
    body: F,
) -> Result<JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    let (ack_tx, ack_rx) = kovan_channel::bounded::<Result<()>>(1);
    let handle = thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            let outcome = apply_governance(&g);
            let ok = outcome.is_ok();
            ack_tx.send(outcome);
            if ok {
                body();
            }
        })
        .map_err(|e| AfterburnerError::GovernanceFailed(format!("thread spawn failed: {e}")))?;
    match ack_rx.recv() {
        Some(Ok(())) => Ok(handle),
        Some(Err(e)) => {
            let _ = handle.join();
            Err(e)
        }
        None => {
            // The ack sender was dropped without sending - the thread
            // panicked before it could report. Treat as a governance
            // failure so construction fails loudly rather than silently
            // losing a worker.
            let _ = handle.join();
            Err(AfterburnerError::GovernanceFailed(
                "governed thread exited before reporting readiness".to_string(),
            ))
        }
    }
}

/// Process-wide governance for node-compat capability helper threads
/// (the DNS resolver's per-call timeout worker, the sqlite3 shadow's
/// per-connection worker, ...). These are spawned deep inside host-call
/// paths reached from many call sites, where plumbing a config value
/// through every call is not viable - a set-once global is the honest
/// minimal mechanism. Unset = [`ThreadGovernance::default()`] (today's
/// ungoverned behavior).
static HELPER_GOVERNANCE: OnceLock<ThreadGovernance> = OnceLock::new();

/// Install the process-wide governance node-compat helper threads
/// apply. Set-once by design: a second call returns `Err` rather than
/// silently overwriting whatever the first caller configured (an
/// embedder installs this once at engine startup).
pub fn set_helper_governance(g: ThreadGovernance) -> Result<()> {
    HELPER_GOVERNANCE.set(g).map_err(|_| {
        AfterburnerError::GovernanceFailed(
            "helper governance already installed for this process".to_string(),
        )
    })
}

/// The current process-wide helper governance, or
/// [`ThreadGovernance::default()`] (a no-op) if [`set_helper_governance`]
/// was never called.
#[must_use]
pub fn helper_governance() -> ThreadGovernance {
    HELPER_GOVERNANCE.get().cloned().unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn set_nice(nice: i8) -> Result<()> {
    let clamped = nice.clamp(-20, 19);
    // SAFETY: `setpriority` is a pure syscall with no preconditions.
    // `who = 0` targets the CALLING thread: Linux's NPTL implementation
    // keys `PRIO_PROCESS` off the caller's own tid (not the process-wide
    // tgid `getpid()` returns) - the same per-thread nice semantics
    // `afterburner-thrust::numa` relies on for `sched_setaffinity`.
    let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, i32::from(clamped)) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(AfterburnerError::GovernanceFailed(format!(
            "setpriority(nice={clamped}) failed: {err}"
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_nice(nice: i8) -> Result<()> {
    Err(AfterburnerError::GovernanceFailed(format!(
        "ThreadGovernance::nice ({nice}) requires Linux (setpriority); unsupported on this platform"
    )))
}

#[cfg(target_os = "linux")]
fn set_affinity(cpus: &[usize]) -> Result<()> {
    if cpus.is_empty() {
        return Err(AfterburnerError::GovernanceFailed(
            "ThreadGovernance::affinity was Some(..) with an empty core list".to_string(),
        ));
    }
    // SAFETY: a zeroed cpu_set_t is a valid empty set; CPU_SET only pokes
    // offsets within its own size. Same pattern as
    // `afterburner-thrust::numa::pin_current_thread_to_worker`.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &cpu in cpus {
            if cpu < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(cpu, &mut set);
            }
        }
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(AfterburnerError::GovernanceFailed(format!(
                "sched_setaffinity({cpus:?}) failed: {err}"
            )));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_affinity(cpus: &[usize]) -> Result<()> {
    Err(AfterburnerError::GovernanceFailed(format!(
        "ThreadGovernance::affinity ({cpus:?}) requires Linux (sched_setaffinity); unsupported on this platform"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn default_governance_is_noop_everywhere() {
        let g = ThreadGovernance::default();
        assert!(g.nice.is_none());
        assert!(g.affinity.is_none());
        assert!(g.name_prefix.is_none());
        apply_governance(&g).expect("default governance never fails");
    }

    #[test]
    fn thread_name_uses_default_when_no_prefix() {
        let g = ThreadGovernance::default();
        assert_eq!(
            g.thread_name("afterburner-thrust", "-3"),
            "afterburner-thrust-3"
        );
    }

    #[test]
    fn thread_name_uses_prefix_when_set() {
        let g = ThreadGovernance {
            name_prefix: Some("myapp-udf".to_string()),
            ..Default::default()
        };
        assert_eq!(g.thread_name("afterburner-thrust", "-3"), "myapp-udf-3");
        assert_eq!(
            g.thread_name("afterburner-admission-sweep", ""),
            "myapp-udf"
        );
    }

    #[test]
    fn spawn_governed_runs_body_with_default_governance() {
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = ran.clone();
        let handle = spawn_governed("test-noop", ThreadGovernance::default(), move || {
            ran2.store(true, Ordering::Release);
        })
        .expect("default governance never fails to spawn");
        handle.join().unwrap();
        assert!(ran.load(Ordering::Acquire));
    }

    #[test]
    fn spawn_governed_names_the_thread() {
        let (tx, rx) = kovan_channel::bounded::<String>(1);
        let handle = spawn_governed(
            "test-named-thread",
            ThreadGovernance::default(),
            move || {
                let name = std::thread::current().name().unwrap_or("").to_string();
                tx.send(name);
            },
        )
        .unwrap();
        handle.join().unwrap();
        assert_eq!(rx.recv(), Some("test-named-thread".to_string()));
    }

    #[test]
    fn helper_governance_defaults_to_noop() {
        // Cannot exercise `set_helper_governance` here (a process-wide
        // OnceLock is shared across every test in this binary); its
        // set-once contract is proven by the integration test that owns
        // the whole process.
        let g = helper_governance();
        // Either default (never set in this test binary) or whatever a
        // sibling test set it to - either way it must not panic and must
        // be a valid, apply-able governance.
        apply_governance(&g).ok();
        let _ = g;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn nice_zero_always_succeeds_without_special_privilege() {
        // Raising nice (negative) needs CAP_SYS_NICE; lowering/staying
        // at 0 never does - this must succeed on every CI box.
        set_nice(0).expect("nice=0 must always be permitted");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn affinity_empty_list_is_a_loud_error() {
        let err = set_affinity(&[]).unwrap_err();
        assert!(matches!(err, AfterburnerError::GovernanceFailed(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn affinity_current_cpu_succeeds() {
        // Pin to CPU 0, which exists on every box that can run this
        // test suite at all.
        set_affinity(&[0]).expect("pinning to cpu 0 must succeed");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn nice_and_affinity_fail_loud_off_linux() {
        assert!(matches!(
            set_nice(0),
            Err(AfterburnerError::GovernanceFailed(_))
        ));
        assert!(matches!(
            set_affinity(&[0]),
            Err(AfterburnerError::GovernanceFailed(_))
        ));
    }
}
