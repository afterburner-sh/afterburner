// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! NUMA topology discovery and per-worker affinity - P7.
//!
//! On **Linux** we read `/sys/devices/system/node/nodeN/cpulist` to learn
//! how many NUMA nodes exist and which CPUs belong to each, then call
//! `sched_setaffinity` from the worker thread to pin it to its assigned
//! node's CPU set. On **macOS, Windows, FreeBSD, etc.** the module
//! returns a single-node topology and skips affinity entirely - the
//! scheduler's own balancing keeps steady-state throughput close to
//! optimal on the hardware commodity users typically deploy.
//!
//! ### Why no external deps
//!
//! `hwloc`-backed crates are heavy and require a C toolchain. Linux
//! sysfs is trivial to parse and covers 99% of multi-socket
//! deployments. Non-Linux fallback is a clean `impl Default`.
//!
//! ### Docker capabilities
//!
//! `sched_setaffinity` is unprivileged - no `CAP_SYS_NICE`. Parsing
//! `/sys/devices/system/node/*` requires only read permission on
//! `/sys`, which default container configs grant. If the sysfs tree
//! is missing (chroot/jail/seccomp), detection degrades gracefully to
//! a 1-node topology.

#[cfg(target_os = "linux")]
use std::fs;

use afterburner_core::{AfterburnerError, Result};

/// How [`ThrustEngine`](crate::ThrustEngine) assigns compute workers to
/// NUMA nodes (E8 - exposed so an embedder can co-plan its OWN
/// affinity around what this engine detects, e.g. a host excluding
/// its query-worker cores from the pool's round-robin).
///
/// `Default` is [`NumaMode::Auto`] - byte-identical to this crate's
/// pre-E8 behavior (unconditional detect + round-robin pin).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NumaMode {
    /// Detect real topology; round-robin workers across every detected
    /// node and pin each to its assigned node's CPU set (today's
    /// unconditional behavior, unchanged).
    #[default]
    Auto,
    /// Force single-node behavior regardless of real hardware: no
    /// worker is NUMA-pinned (the steal sweep also stops
    /// locality-ordering peers). Workers remain governable through
    /// `ThreadGovernance::affinity` exactly as on genuinely
    /// single-socket hardware - this only turns off the AUTOMATIC pin.
    Off,
    /// Restrict round-robin + pin to this explicit subset of the REAL
    /// detected NUMA node numbers (e.g. `[0]` to keep the pool off a
    /// node an embedder reserves for something else). Validated at
    /// construction: an empty list or a node id detection didn't find
    /// is a loud [`AfterburnerError::Engine`], never a silent
    /// fallback.
    ExplicitNodes(Vec<usize>),
}

/// Per-worker NUMA assignment + topology summary. Always constructs
/// successfully via [`NumaTopology::detect`]; on platforms/environments
/// where detection fails, it reports `node_count = 1` and every worker
/// maps to node 0.
///
/// Public (E8) so an embedder can query real hardware topology to
/// co-plan its own affinity decisions independently of building a
/// [`ThrustEngine`](crate::ThrustEngine) - the read API below
/// (`nodes`/`worker_to_node`/`cpus_per_node`) is deliberately decoupled
/// from this type's internal field layout.
#[derive(Debug, Clone)]
pub struct NumaTopology {
    /// Number of NUMA nodes detected. `1` means either a single-socket
    /// box or a system where detection wasn't available.
    pub(crate) node_count: usize,
    /// `worker_to_node[worker_id]` = the NUMA node that worker is
    /// assigned to. Length = number of workers.
    pub(crate) worker_to_node: Vec<usize>,
    /// For each node, the `cpulist` that belongs to it. Used by
    /// `pin_current_thread_to_worker`. On non-Linux / detection-fail,
    /// this is empty and pinning is a no-op.
    pub(crate) node_cpus: Vec<Vec<usize>>,
}

impl NumaTopology {
    /// Build the topology for `n_workers`. Detects nodes; round-robins
    /// workers across them. Equivalent to
    /// `detect_with_mode(n_workers, &NumaMode::Auto)`, kept infallible
    /// (this mode can never fail validation) so existing callers keep
    /// their `-> Self` signature.
    pub fn detect(n_workers: usize) -> Self {
        let nodes = detect_nodes();
        let node_count = nodes.len().max(1);
        let worker_to_node = (0..n_workers).map(|i| i % node_count).collect();
        let node_cpus = nodes.into_iter().map(|(_, cpus)| cpus).collect();
        Self {
            node_count,
            worker_to_node,
            node_cpus,
        }
    }

    /// Build the topology honoring an explicit [`NumaMode`] (E8).
    /// `Auto` matches [`NumaTopology::detect`] exactly; `Off` forces a
    /// single-node topology; `ExplicitNodes` validates every requested
    /// node id against real detection and fails loudly (never silently
    /// widens or narrows) when the request cannot be honored.
    pub fn detect_with_mode(n_workers: usize, mode: &NumaMode) -> Result<Self> {
        match mode {
            NumaMode::Auto => Ok(Self::detect(n_workers)),
            NumaMode::Off => Ok(Self {
                node_count: 1,
                worker_to_node: vec![0; n_workers],
                node_cpus: Vec::new(),
            }),
            NumaMode::ExplicitNodes(ids) => {
                if ids.is_empty() {
                    return Err(AfterburnerError::Engine(
                        "NumaMode::ExplicitNodes requires at least one node id".to_string(),
                    ));
                }
                let detected = detect_nodes();
                let mut node_cpus = Vec::with_capacity(ids.len());
                for &id in ids {
                    match detected.iter().find(|(n, _)| *n == id) {
                        Some((_, cpus)) => node_cpus.push(cpus.clone()),
                        None => {
                            let available: Vec<usize> = detected.iter().map(|(n, _)| *n).collect();
                            return Err(AfterburnerError::Engine(format!(
                                "NumaMode::ExplicitNodes requested node {id}, but detected nodes are {available:?}"
                            )));
                        }
                    }
                }
                let node_count = node_cpus.len();
                let worker_to_node = (0..n_workers).map(|i| i % node_count).collect();
                Ok(Self {
                    node_count,
                    worker_to_node,
                    node_cpus,
                })
            }
        }
    }

    /// Returns `true` when detection found more than one node and we
    /// actually have per-node CPU lists to pin against. Used to decide
    /// whether it's worth doing the locality-preferring steal sweep.
    pub fn multi_node(&self) -> bool {
        self.node_count > 1 && !self.node_cpus.is_empty()
    }

    /// Number of NUMA nodes this topology spans. `1` on single-socket
    /// hardware, when detection is unavailable, or under
    /// [`NumaMode::Off`].
    pub fn nodes(&self) -> usize {
        self.node_count
    }

    /// The NUMA node `worker_id` is assigned to (round-robin order).
    /// An out-of-range id resolves to node `0`, matching this type's
    /// own internal pinning/steal-order lookups.
    pub fn worker_to_node(&self, worker_id: usize) -> usize {
        self.worker_to_node.get(worker_id).copied().unwrap_or(0)
    }

    /// CPU ids belonging to `node`. Empty when `node` is out of range
    /// or when per-node CPU lists were not available at detection time
    /// (non-Linux, sysfs unreadable, or [`NumaMode::Off`]).
    pub fn cpus_per_node(&self, node: usize) -> &[usize] {
        self.node_cpus.get(node).map_or(&[][..], Vec::as_slice)
    }
}

/// Called from inside each worker thread to pin itself to its assigned
/// NUMA node's CPU set. No-op on non-Linux or when detection reported
/// a single node.
#[cfg(target_os = "linux")]
pub(crate) fn pin_current_thread_to_worker(topo: &NumaTopology, worker_id: usize) {
    if !topo.multi_node() {
        return;
    }
    let node = topo.worker_to_node.get(worker_id).copied().unwrap_or(0);
    let Some(cpus) = topo.node_cpus.get(node) else {
        return;
    };
    if cpus.is_empty() {
        return;
    }

    // Build a libc::cpu_set_t with just this node's CPUs.
    // SAFETY: zeroed cpu_set_t is valid; we only poke at offsets within
    // the sizeof<cpu_set_t>() range.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &cpu in cpus {
            // CPU_SET is safe even for cpus beyond the default 1024 on
            // glibc, but out-of-range indices on very large boxes may
            // silently no-op; fine for our best-effort purpose.
            if cpu < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(cpu, &mut set);
            }
        }
        // Pid 0 = current thread (sched_setaffinity on Linux acts on the
        // calling kernel task, which for Rust's std threads is the
        // thread, not the process).
        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Non-Linux: no-op. Keeps the call site clean.
#[cfg(not(target_os = "linux"))]
pub(crate) fn pin_current_thread_to_worker(_topo: &NumaTopology, _worker_id: usize) {}

// ── sysfs parse ──────────────────────────────────────────────────────────

/// Real detected NUMA nodes as `(node_number, cpulist)` pairs, sorted by
/// node number. The node number is preserved (rather than collapsed to
/// a positional index) so [`NumaMode::ExplicitNodes`] can validate
/// operator-supplied ids against the SAME numbers `/sys/devices/system/node`
/// exposes.
#[cfg(target_os = "linux")]
fn detect_nodes() -> Vec<(usize, Vec<usize>)> {
    let base = "/sys/devices/system/node";
    let Ok(entries) = fs::read_dir(base) else {
        return Vec::new();
    };
    let mut nodes: Vec<(usize, Vec<usize>)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(num_str) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(node_num) = num_str.parse::<usize>() else {
            continue;
        };
        let cpulist_path = format!("{base}/node{node_num}/cpulist");
        let Ok(content) = fs::read_to_string(&cpulist_path) else {
            continue;
        };
        let cpus = parse_cpulist(content.trim());
        if !cpus.is_empty() {
            nodes.push((node_num, cpus));
        }
    }
    nodes.sort_by_key(|(n, _)| *n);
    nodes
}

#[cfg(not(target_os = "linux"))]
fn detect_nodes() -> Vec<(usize, Vec<usize>)> {
    Vec::new()
}

/// Parse a Linux `cpulist` (e.g. `"0-7,16-23"`) into an expanded
/// `Vec<usize>`. Returns an empty vec on any parse error.
fn parse_cpulist(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for group in s.split(',') {
        let group = group.trim();
        if group.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = group.split_once('-') {
            let Ok(lo) = lo.parse::<usize>() else {
                return Vec::new();
            };
            let Ok(hi) = hi.parse::<usize>() else {
                return Vec::new();
            };
            if hi < lo {
                return Vec::new();
            }
            for cpu in lo..=hi {
                out.push(cpu);
            }
        } else if let Ok(cpu) = group.parse::<usize>() {
            out.push(cpu);
        } else {
            return Vec::new();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_cpu() {
        assert_eq!(parse_cpulist("0"), vec![0]);
        assert_eq!(parse_cpulist("7"), vec![7]);
    }

    #[test]
    fn parse_range() {
        assert_eq!(parse_cpulist("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpulist("10-12"), vec![10, 11, 12]);
    }

    #[test]
    fn parse_mixed() {
        assert_eq!(parse_cpulist("0-3,8,10-11"), vec![0, 1, 2, 3, 8, 10, 11]);
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse_cpulist("not-a-number").is_empty());
        assert!(parse_cpulist("5-2").is_empty()); // reverse range
    }

    #[test]
    fn topology_always_has_at_least_one_node() {
        let t = NumaTopology::detect(4);
        assert!(t.node_count >= 1);
        assert_eq!(t.worker_to_node.len(), 4);
        for &n in &t.worker_to_node {
            assert!(n < t.node_count);
        }
    }

    #[test]
    fn worker_to_node_is_round_robin() {
        // Force a fake topology by hand.
        let t = NumaTopology {
            node_count: 3,
            worker_to_node: (0..9).map(|i| i % 3).collect(),
            node_cpus: vec![vec![0], vec![1], vec![2]],
        };
        assert_eq!(t.worker_to_node, vec![0, 1, 2, 0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn pin_is_callable_and_noops_on_single_node() {
        // Produces a single-node topology (even on a multi-socket box,
        // we force it by constructing directly). pin should noop.
        let t = NumaTopology {
            node_count: 1,
            worker_to_node: vec![0],
            node_cpus: vec![],
        };
        pin_current_thread_to_worker(&t, 0); // must not panic
    }

    // ── E8: public read API ────────────────────────────────────────────

    #[test]
    fn read_api_matches_internal_fields() {
        let t = NumaTopology {
            node_count: 2,
            worker_to_node: vec![0, 1, 0],
            node_cpus: vec![vec![0, 1], vec![2, 3]],
        };
        assert_eq!(t.nodes(), 2);
        assert_eq!(t.worker_to_node(0), 0);
        assert_eq!(t.worker_to_node(1), 1);
        assert_eq!(t.worker_to_node(2), 0);
        assert_eq!(
            t.worker_to_node(99),
            0,
            "out-of-range worker resolves to node 0"
        );
        assert_eq!(t.cpus_per_node(0).to_vec(), vec![0, 1]);
        assert_eq!(t.cpus_per_node(1).to_vec(), vec![2, 3]);
        assert!(
            t.cpus_per_node(99).is_empty(),
            "out-of-range node resolves to an empty cpu list"
        );
    }

    // ── E8: NumaMode ────────────────────────────────────────────────────

    #[test]
    fn numa_mode_default_is_auto() {
        assert_eq!(NumaMode::default(), NumaMode::Auto);
    }

    #[test]
    fn auto_mode_matches_plain_detect() {
        let a = NumaTopology::detect_with_mode(4, &NumaMode::Auto).unwrap();
        let b = NumaTopology::detect(4);
        assert_eq!(a.node_count, b.node_count);
        assert_eq!(a.worker_to_node, b.worker_to_node);
        assert_eq!(a.node_cpus, b.node_cpus);
    }

    #[test]
    fn off_mode_forces_single_node_regardless_of_hardware() {
        let t = NumaTopology::detect_with_mode(4, &NumaMode::Off).unwrap();
        assert_eq!(t.node_count, 1);
        assert_eq!(t.worker_to_node, vec![0, 0, 0, 0]);
        assert!(!t.multi_node());
        assert!(t.cpus_per_node(0).is_empty());
    }

    #[test]
    fn explicit_nodes_rejects_empty_list() {
        let err = NumaTopology::detect_with_mode(2, &NumaMode::ExplicitNodes(vec![])).unwrap_err();
        assert!(matches!(err, AfterburnerError::Engine(_)));
    }

    #[test]
    fn explicit_nodes_rejects_an_undetected_node_id() {
        // usize::MAX is never a real node number detect_nodes() would
        // report (empty detection or a bounded real list either way),
        // so this is a loud error on every platform/environment.
        let err = NumaTopology::detect_with_mode(2, &NumaMode::ExplicitNodes(vec![usize::MAX]))
            .unwrap_err();
        assert!(matches!(err, AfterburnerError::Engine(_)));
    }

    #[test]
    fn explicit_nodes_succeeds_for_a_really_detected_node() {
        let real = detect_nodes();
        let Some((first_id, first_cpus)) = real.first() else {
            // No sysfs / non-Linux / detection unavailable in this
            // environment - ExplicitNodes has nothing real to validate
            // against here. The rejection tests above still hold
            // unconditionally on every platform; this positive case is
            // honestly skippable rather than faked.
            return;
        };
        let t =
            NumaTopology::detect_with_mode(4, &NumaMode::ExplicitNodes(vec![*first_id])).unwrap();
        assert_eq!(t.node_count, 1);
        assert_eq!(t.cpus_per_node(0).to_vec(), *first_cpus);
        assert_eq!(t.worker_to_node, vec![0, 0, 0, 0]);
    }
}
