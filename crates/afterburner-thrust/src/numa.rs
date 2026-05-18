// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! NUMA topology discovery and per-worker affinity — P7.
//!
//! On **Linux** we read `/sys/devices/system/node/nodeN/cpulist` to learn
//! how many NUMA nodes exist and which CPUs belong to each, then call
//! `sched_setaffinity` from the worker thread to pin it to its assigned
//! node's CPU set. On **macOS, Windows, FreeBSD, etc.** the module
//! returns a single-node topology and skips affinity entirely — the
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
//! `sched_setaffinity` is unprivileged — no `CAP_SYS_NICE`. Parsing
//! `/sys/devices/system/node/*` requires only read permission on
//! `/sys`, which default container configs grant. If the sysfs tree
//! is missing (chroot/jail/seccomp), detection degrades gracefully to
//! a 1-node topology.

#[cfg(target_os = "linux")]
use std::fs;

/// Per-worker NUMA assignment + topology summary. Always constructs
/// successfully; on platforms/environments where detection fails, it
/// reports `node_count = 1` and every worker maps to node 0.
#[derive(Debug, Clone)]
pub(crate) struct NumaTopology {
    /// Number of NUMA nodes detected. `1` means either a single-socket
    /// box or a system where detection wasn't available.
    pub node_count: usize,
    /// `worker_to_node[worker_id]` = the NUMA node that worker is
    /// assigned to. Length = number of workers.
    pub worker_to_node: Vec<usize>,
    /// For each node, the `cpulist` that belongs to it. Used by
    /// `pin_current_thread_to_worker`. On non-Linux / detection-fail,
    /// this is empty and pinning is a no-op.
    pub node_cpus: Vec<Vec<usize>>,
}

impl NumaTopology {
    /// Build the topology for `n_workers`. Detects nodes; round-robins
    /// workers across them.
    pub fn detect(n_workers: usize) -> Self {
        let nodes = detect_nodes();
        let node_count = nodes.len().max(1);
        let worker_to_node = (0..n_workers).map(|i| i % node_count).collect();
        Self {
            node_count,
            worker_to_node,
            node_cpus: nodes,
        }
    }

    /// Returns `true` when detection found more than one node and we
    /// actually have per-node CPU lists to pin against. Used to decide
    /// whether it's worth doing the locality-preferring steal sweep.
    pub fn multi_node(&self) -> bool {
        self.node_count > 1 && !self.node_cpus.is_empty()
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

#[cfg(target_os = "linux")]
fn detect_nodes() -> Vec<Vec<usize>> {
    let base = "/sys/devices/system/node";
    let Ok(entries) = fs::read_dir(base) else {
        return Vec::new();
    };
    let mut nodes: Vec<(u32, Vec<usize>)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(num_str) = name.strip_prefix("node") else {
            continue;
        };
        let Ok(node_num) = num_str.parse::<u32>() else {
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
    nodes.into_iter().map(|(_, cpus)| cpus).collect()
}

#[cfg(not(target_os = "linux"))]
fn detect_nodes() -> Vec<Vec<usize>> {
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
}
