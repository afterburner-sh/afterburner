// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Proof that `ThrustEngineConfig::governance` actually reaches the OS
//! attributes of the threads `ThrustEngine` spawns (compute workers,
//! the admission sweep) - nice value, CPU affinity, and name -
//! read back from `/proc/self/task`, the same zero-dependency
//! ground-truth source `thread_isolation_knobs.rs` uses for the wasm
//! epoch ticker / rayon proof.
//!
//! Linux-only: `nice`/`affinity` are only implemented on Linux
//! (`afterburner_core::governance`); this file is a dedicated
//! integration binary so thread-count deltas are never polluted by
//! another test's threads.
#![cfg(target_os = "linux")]

use afterburner_core::governance::ThreadGovernance;
use afterburner_thrust::{ThrustEngine, ThrustEngineConfig};

fn thread_names() -> Vec<String> {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("comm")).ok())
        .map(|name| name.trim().to_string())
        .collect()
}

/// `(tid, comm)` for every thread in this process right now.
fn tasks() -> Vec<(u32, String)> {
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let tid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let comm = std::fs::read_to_string(entry.path().join("comm")).ok()?;
            Some((tid, comm.trim().to_string()))
        })
        .collect()
}

/// Field 19 (1-indexed) of `/proc/self/task/<tid>/stat` - the nice
/// value. `comm` (field 2) is parenthesized and may itself contain
/// spaces/parens, so we split on the *last* `)` and count fields in
/// the remainder (`state` is the first field after it, i.e. field 3).
fn read_nice(tid: u32) -> i64 {
    let stat =
        std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).expect("read task stat");
    let after_comm = stat.rsplit_once(')').expect("stat has a comm field").1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // fields[0] = state (field 3) ... fields[16] = nice (field 19).
    fields[16].parse().expect("nice field parses as i64")
}

/// `Cpus_allowed_list` from `/proc/self/task/<tid>/status`, e.g. `"0"`
/// or `"0-7"` or `"0,2,4"`.
fn read_affinity_list(tid: u32) -> String {
    let status =
        std::fs::read_to_string(format!("/proc/self/task/{tid}/status")).expect("read task status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .expect("status has Cpus_allowed_list")
        .trim()
        .to_string()
}

/// The first CPU id in *this* process's own allowed set - always a
/// legal affinity target in whatever environment the test runs
/// (container, CI runner with a restricted cpuset, ...), unlike a
/// hardcoded `0`.
fn a_legal_cpu() -> usize {
    let list = read_affinity_list(std::process::id());
    let first = list.split(['-', ',']).next().expect("non-empty list");
    first.parse().expect("cpu id parses")
}

/// The kernel's `comm` field is capped at `TASK_COMM_LEN - 1` = 15
/// visible characters (`pthread_setname_np`'s own limit); a longer
/// `thread::Builder::name` is silently truncated by the OS, not by
/// Rust. `"afterburner-thrust-0"` (21 chars) and
/// `"afterburner-admission-sweep"` (27 chars) both exceed it, so
/// lookups here must compare against the truncated form - the same
/// adjustment `thread_isolation_knobs.rs` makes via
/// `starts_with("afterburner-epo")` for the (24-char) epoch ticker.
const LINUX_COMM_LEN: usize = 15;

fn linux_comm_truncate(name: &str) -> String {
    name.chars().take(LINUX_COMM_LEN).collect()
}

fn tid_for_name(name: &str) -> u32 {
    let truncated = linux_comm_truncate(name);
    tasks()
        .into_iter()
        .find(|(_, comm)| *comm == truncated)
        .unwrap_or_else(|| {
            panic!(
                "no thread named {name:?} (kernel-truncated: {truncated:?}); tasks={:?}",
                thread_names()
            )
        })
        .0
}

#[test]
fn default_governance_leaves_workers_unpinned_and_default_nice() {
    let engine = ThrustEngine::new(ThrustEngineConfig {
        compute_workers: 1,
        ..Default::default()
    })
    .unwrap();
    let tid = tid_for_name("afterburner-thrust-0");
    // Default governance never calls setpriority/sched_setaffinity -
    // the worker inherits the constructing thread's nice (0 for a
    // normal test process) and its full affinity set (unpinned).
    assert_eq!(read_nice(tid), 0, "ungoverned worker must keep nice 0");
    assert_eq!(
        read_affinity_list(tid),
        read_affinity_list(std::process::id()),
        "ungoverned worker must keep the process's own (unpinned) affinity"
    );
    drop(engine);
}

#[test]
fn nice_governance_reaches_the_worker_thread() {
    // A positive (higher) nice never needs CAP_SYS_NICE, so this must
    // pass on every CI box regardless of privilege.
    let engine = ThrustEngine::new(ThrustEngineConfig {
        compute_workers: 1,
        governance: ThreadGovernance {
            nice: Some(10),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    let tid = tid_for_name("afterburner-thrust-0");
    assert_eq!(read_nice(tid), 10);
    drop(engine);
}

#[test]
fn affinity_governance_pins_the_worker_thread() {
    let cpu = a_legal_cpu();
    let engine = ThrustEngine::new(ThrustEngineConfig {
        compute_workers: 1,
        governance: ThreadGovernance {
            affinity: Some(vec![cpu]),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    let tid = tid_for_name("afterburner-thrust-0");
    assert_eq!(
        read_affinity_list(tid),
        cpu.to_string(),
        "explicit affinity must pin to exactly the requested core, overriding the NUMA pin"
    );
    drop(engine);
}

#[test]
fn name_prefix_applies_to_workers_and_admission_sweep() {
    let engine = ThrustEngine::new(ThrustEngineConfig {
        compute_workers: 2,
        admission_tokens_per_sec: Some(1_000),
        governance: ThreadGovernance {
            name_prefix: Some("myapp-udf".to_string()),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    let names = thread_names();
    assert!(
        names.iter().any(|n| n == "myapp-udf-0"),
        "expected myapp-udf-0 among {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "myapp-udf-1"),
        "expected myapp-udf-1 among {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "myapp-udf"),
        "admission sweep (no numeric suffix) expected among {names:?}"
    );
    // The engine's default names (kernel-truncated to 15 chars) must be
    // completely absent - no drift between the two attribution schemes.
    assert!(
        !names
            .iter()
            .any(|n| *n == linux_comm_truncate("afterburner-thrust-0"))
    );
    assert!(
        !names
            .iter()
            .any(|n| *n == linux_comm_truncate("afterburner-admission-sweep"))
    );
    drop(engine);
}

#[test]
fn governance_failure_at_construction_leaves_no_worker_threads_behind() {
    let baseline = thread_names().len();
    // An affinity mask with no CPU below CPU_SETSIZE resolves to an
    // empty effective mask, which sched_setaffinity rejects (EINVAL) -
    // a deterministic, privilege-independent way to exercise the
    // fail-loud-at-construction path without needing CAP_SYS_NICE.
    let err = ThrustEngine::new(ThrustEngineConfig {
        compute_workers: 4,
        governance: ThreadGovernance {
            affinity: Some(vec![usize::MAX]),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap_err();
    assert!(
        matches!(err, afterburner_core::AfterburnerError::GovernanceFailed(_)),
        "expected GovernanceFailed, got {err}"
    );
    // No partially-governed pool survives the failed construction: the
    // thread count returns to exactly the pre-call baseline.
    assert_eq!(
        thread_names().len(),
        baseline,
        "a failed construction must leave zero worker threads behind; names={:?}",
        thread_names()
    );
}
