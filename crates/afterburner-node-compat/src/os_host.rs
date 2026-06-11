// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `os.*` host functions. Trivial wrappers over `std::env`; no Manifold
//! gating (these leak very little about the host).

pub fn platform() -> &'static str {
    std::env::consts::OS
}

pub fn arch() -> &'static str {
    std::env::consts::ARCH
}

pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "afterburner".into())
}

pub fn tmpdir() -> String {
    std::env::temp_dir().to_string_lossy().into_owned()
}

pub fn cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

pub fn total_mem() -> u64 {
    // Conservative default - getting accurate total memory cross-platform
    // requires platform-specific syscalls we're not pulling in for Phase 2.
    0
}

pub fn free_mem() -> u64 {
    0
}

pub fn home_dir() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default()
}

pub fn uptime() -> u64 {
    0
}
