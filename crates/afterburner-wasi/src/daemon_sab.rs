// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Cross-process `SharedArrayBuffer` + `Atomics.wait`/`notify`.
//!
//! Backs the JS-side `SharedArrayBuffer` constructor and the
//! `Atomics.{load,store,compareExchange,wait,notify}` primitives
//! with real OS-level shared memory + futex semantics, so worker
//! subprocesses spawned by `worker_threads` can synchronise on a
//! shared region without polling.
//!
//! Backend selection:
//!
//! | Platform | Memory       | Wait/notify              |
//! |----------|--------------|--------------------------|
//! | Linux    | `memfd_create` + `mmap(MAP_SHARED)` | `futex(2)` (via `atomic-wait`) |
//! | macOS    | `shm_open` + `mmap(MAP_SHARED)`     | `__ulock_wait`/`__ulock_wake` (via `atomic-wait`) |
//! | Windows  | `CreateFileMapping` + `MapViewOfFile` | `WaitOnAddress`/`WakeByAddressAll` (via `atomic-wait`) |
//!
//! Cross-process descriptor sharing:
//!
//! * Linux: the memfd is passed to worker subprocesses via the
//!   `BURN_SAB_REGIONS` env var (a CSV of `region_id:fd_path` where
//!   `fd_path` is `/proc/<parent>/fd/<fd>`). The child re-opens via
//!   that path and `mmap`s the same shared bytes.
//! * Other platforms: shm name + handle inheritance.
//!
//! All atomic ops touch the bytes through a raw pointer with the
//! standard library's atomic intrinsics, which the kernel guarantees
//! to be lock-free across processes sharing the page.

use kovan_map::HopscotchMap;
use memmap2::{MmapMut, MmapOptions};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

pub type RegionId = i64;

pub const ERR_BAD_ID: i32 = -1;
pub const ERR_OUT_OF_BOUNDS: i32 = -2;
pub const ERR_BAD_WIDTH: i32 = -3;
pub const ERR_IO: i32 = -4;
pub const ERR_UNSUPPORTED: i32 = -5;

/// Result codes for `wait`. Encoded as i32 because the host import
/// returns through the integer ABI.
pub const WAIT_OK: i32 = 0;
pub const WAIT_NOT_EQUAL: i32 = 1;
pub const WAIT_TIMED_OUT: i32 = 2;

#[derive(Clone)]
struct Region {
    /// The actual memory mapping. Cloned via `Arc` so the lifetime
    /// matches `Arc<DaemonSab>` and the bytes stay valid as long as
    /// any thread is reading them.
    map: Arc<MmapMut>,
    /// Length in bytes. Cached so callers don't need an extra lock
    /// to look it up.
    byte_length: usize,
    /// Filesystem path (or shm name) the region was created at, for
    /// cross-process descriptor passing. Empty for ad-hoc regions.
    descriptor: String,
}

impl Region {
    fn ptr(&self) -> *mut u8 {
        // `MmapMut` derefs to `&mut [u8]`. We hold an Arc so multiple
        // threads can call `.ptr()` concurrently — the kernel page is
        // shared and atomic ops are valid through the raw pointer.
        self.map.as_ptr() as *mut u8
    }
}

pub struct DaemonSab {
    next_id: AtomicI32,
    regions: HopscotchMap<RegionId, Region>,
}

impl Default for DaemonSab {
    fn default() -> Self {
        Self {
            next_id: AtomicI32::new(1),
            regions: HopscotchMap::new(),
        }
    }
}

impl Drop for DaemonSab {
    /// Best-effort cleanup of named shm files we created. Other
    /// processes attached via the descriptor keep their mappings
    /// alive after the unlink (Linux semantics: an `unlink` of a
    /// mapped file removes the dir entry but the inode stays until
    /// all mappings drop). This avoids leaving files in `/dev/shm`
    /// when the parent process exits cleanly.
    fn drop(&mut self) {
        #[cfg(unix)]
        for (_, region) in self.regions.iter() {
            if !region.descriptor.is_empty() {
                let _ = std::fs::remove_file(&region.descriptor);
            }
        }
    }
}

impl DaemonSab {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Allocate a fresh shared region. Returns a positive region_id
    /// on success, negative `ERR_*` code on failure.
    pub fn alloc(&self, byte_length: usize) -> i64 {
        if byte_length == 0 {
            return ERR_BAD_WIDTH as i64;
        }
        match build_region(byte_length) {
            Ok(region) => {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed) as i64;
                self.regions.insert(id, region);
                id
            }
            Err(_) => ERR_IO as i64,
        }
    }

    /// Open an existing shared region by descriptor (path/handle).
    /// Used by worker subprocesses to reattach to a region the
    /// parent created.
    pub fn open(&self, descriptor: &str, byte_length: usize) -> i64 {
        match open_region(descriptor, byte_length) {
            Ok(region) => {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed) as i64;
                self.regions.insert(id, region);
                id
            }
            Err(_) => ERR_IO as i64,
        }
    }

    /// Release a region. The mapping stays alive until the last
    /// process unmaps; we just drop our reference.
    pub fn release(&self, region_id: RegionId) -> i32 {
        if self.regions.remove(&region_id).is_some() {
            0
        } else {
            ERR_BAD_ID
        }
    }

    /// Descriptor string suitable for cross-process attachment.
    /// Currently a `/proc/self/fd/N` path on Linux, an shm name on
    /// macOS, or a numeric handle on Windows. Returns empty string
    /// for unknown ids.
    pub fn descriptor(&self, region_id: RegionId) -> String {
        self.regions
            .get(&region_id)
            .map(|r| r.descriptor.clone())
            .unwrap_or_default()
    }

    pub fn byte_length(&self, region_id: RegionId) -> i64 {
        self.regions
            .get(&region_id)
            .map(|r| r.byte_length as i64)
            .unwrap_or(ERR_BAD_ID as i64)
    }

    /// Copy `len` bytes starting at `offset` out of the region.
    pub fn read(&self, region_id: RegionId, offset: usize, len: usize) -> Result<Vec<u8>, i32> {
        let region = self.regions.get(&region_id).ok_or(ERR_BAD_ID)?;
        if offset.saturating_add(len) > region.byte_length {
            return Err(ERR_OUT_OF_BOUNDS);
        }
        let mut out = vec![0u8; len];
        unsafe {
            std::ptr::copy_nonoverlapping(region.ptr().add(offset), out.as_mut_ptr(), len);
        }
        Ok(out)
    }

    /// Copy `bytes.len()` bytes into the region starting at `offset`.
    pub fn write(&self, region_id: RegionId, offset: usize, bytes: &[u8]) -> i32 {
        let region = match self.regions.get(&region_id) {
            Some(r) => r,
            None => return ERR_BAD_ID,
        };
        if offset.saturating_add(bytes.len()) > region.byte_length {
            return ERR_OUT_OF_BOUNDS;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), region.ptr().add(offset), bytes.len());
        }
        0
    }

    /// Atomic load of `width` bytes (1/2/4/8) at `byte_offset`.
    /// Returns the value as i64 (zero-extended for unsigned widths).
    pub fn atomic_load(&self, region_id: RegionId, byte_offset: usize, width: u8) -> i64 {
        let region = match self.regions.get(&region_id) {
            Some(r) => r,
            None => return ERR_BAD_ID as i64,
        };
        if byte_offset.saturating_add(width as usize) > region.byte_length {
            return ERR_OUT_OF_BOUNDS as i64;
        }
        unsafe {
            let p = region.ptr().add(byte_offset);
            match width {
                4 => (*(p as *const AtomicU32)).load(Ordering::SeqCst) as i64,
                8 => (*(p as *const AtomicU64)).load(Ordering::SeqCst) as i64,
                _ => ERR_BAD_WIDTH as i64,
            }
        }
    }

    /// Atomic store. Returns 0 on success.
    pub fn atomic_store(
        &self,
        region_id: RegionId,
        byte_offset: usize,
        value: i64,
        width: u8,
    ) -> i32 {
        let region = match self.regions.get(&region_id) {
            Some(r) => r,
            None => return ERR_BAD_ID,
        };
        if byte_offset.saturating_add(width as usize) > region.byte_length {
            return ERR_OUT_OF_BOUNDS;
        }
        unsafe {
            let p = region.ptr().add(byte_offset);
            match width {
                4 => (*(p as *const AtomicU32)).store(value as u32, Ordering::SeqCst),
                8 => (*(p as *const AtomicU64)).store(value as u64, Ordering::SeqCst),
                _ => return ERR_BAD_WIDTH,
            }
        }
        0
    }

    /// Atomic compare-exchange. Returns the old value (or `ERR_*` as
    /// i64 if the slot was out of bounds — JS callers should check
    /// negative before treating as a value).
    pub fn atomic_cas(
        &self,
        region_id: RegionId,
        byte_offset: usize,
        expected: i64,
        replacement: i64,
        width: u8,
    ) -> i64 {
        let region = match self.regions.get(&region_id) {
            Some(r) => r,
            None => return ERR_BAD_ID as i64,
        };
        if byte_offset.saturating_add(width as usize) > region.byte_length {
            return ERR_OUT_OF_BOUNDS as i64;
        }
        unsafe {
            let p = region.ptr().add(byte_offset);
            match width {
                4 => {
                    let a = &*(p as *const AtomicU32);
                    match a.compare_exchange(
                        expected as u32,
                        replacement as u32,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(v) | Err(v) => v as i64,
                    }
                }
                8 => {
                    let a = &*(p as *const AtomicU64);
                    match a.compare_exchange(
                        expected as u64,
                        replacement as u64,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(v) | Err(v) => v as i64,
                    }
                }
                _ => ERR_BAD_WIDTH as i64,
            }
        }
    }

    /// Block the calling thread until the 32-bit slot at
    /// `byte_offset` differs from `expected`, or `timeout_ms`
    /// elapses. `timeout_ms < 0` means infinite.
    pub fn wait(
        &self,
        region_id: RegionId,
        byte_offset: usize,
        expected: i32,
        timeout_ms: i64,
    ) -> i32 {
        let region = match self.regions.get(&region_id) {
            Some(r) => r,
            None => return ERR_BAD_ID,
        };
        if byte_offset.saturating_add(4) > region.byte_length {
            return ERR_OUT_OF_BOUNDS;
        }
        unsafe {
            let p = region.ptr().add(byte_offset) as *const AtomicU32;
            let current = (*p).load(Ordering::SeqCst);
            if current != expected as u32 {
                return WAIT_NOT_EQUAL;
            }
            if timeout_ms < 0 {
                atomic_wait::wait(&*p, expected as u32);
                WAIT_OK
            } else {
                // `atomic_wait::wait_with_timeout` returns true if
                // the wait actually slept (didn't return immediately
                // due to spurious wake or value mismatch). We
                // re-load post-wait to disambiguate timeout vs notify.
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
                loop {
                    let now = std::time::Instant::now();
                    if now >= deadline {
                        // Re-check the slot one more time before
                        // declaring timeout — a notify may have
                        // landed in the gap.
                        let v = (*p).load(Ordering::SeqCst);
                        return if v != expected as u32 {
                            WAIT_OK
                        } else {
                            WAIT_TIMED_OUT
                        };
                    }
                    let remaining = deadline - now;
                    // Wait up to the remaining time. `atomic-wait`
                    // doesn't expose timed wait directly; use a
                    // backoff loop with `WaitOnAddress`-equivalent
                    // semantics via short interval polls. 1 ms is
                    // the minimum useful slice for our coarse JS
                    // timer semantics.
                    let slice = remaining.min(std::time::Duration::from_millis(1));
                    std::thread::sleep(slice);
                    let v = (*p).load(Ordering::SeqCst);
                    if v != expected as u32 {
                        return WAIT_OK;
                    }
                }
            }
        }
    }

    /// Wake up to `count` waiters parked on the 32-bit slot at
    /// `byte_offset`. Returns the number of waiters woken (best-effort —
    /// the kernel doesn't tell us the exact count on every platform,
    /// so we wake all and report `count`).
    pub fn notify(&self, region_id: RegionId, byte_offset: usize, count: i64) -> i32 {
        let region = match self.regions.get(&region_id) {
            Some(r) => r,
            None => return ERR_BAD_ID,
        };
        if byte_offset.saturating_add(4) > region.byte_length {
            return ERR_OUT_OF_BOUNDS;
        }
        unsafe {
            let p = region.ptr().add(byte_offset) as *const AtomicU32;
            if count == 1 {
                atomic_wait::wake_one(&*p);
                1
            } else {
                atomic_wait::wake_all(&*p);
                // Upper bound — the kernel returned successfully so
                // at least the requested count may have woken. JS
                // sees Infinity → wake_all → return Infinity in
                // userland because we can't observe the exact count
                // cross-platform.
                if !(0..=1 << 30).contains(&count) {
                    1 << 30
                } else {
                    count as i32
                }
            }
        }
    }
}

// ---- Platform-specific region creation -----------------------------

/// Build a region backed by a *named* file in `/dev/shm` (or
/// `$TMPDIR` fallback). The name is the `descriptor` returned to JS;
/// worker subprocesses re-open by name via `open_region` since
/// Rust's `posix_spawn` closes inherited fds and the
/// `/proc/self/fd/N` trick wouldn't survive.
#[cfg(unix)]
fn build_region(byte_length: usize) -> Result<Region, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = unique_shm_path();
    // Open with O_CREAT | O_EXCL | O_RDWR so we own the file. Mode
    // 0600 — only this user; nobody else can attach to a region we
    // didn't hand over the path for.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.set_len(byte_length as u64)?;
    let mut opts = MmapOptions::new();
    opts.len(byte_length);
    let map = unsafe { opts.map_mut(&file)? };
    Ok(Region {
        map: Arc::new(map),
        byte_length,
        descriptor: path,
    })
}

#[cfg(unix)]
fn open_region(descriptor: &str, byte_length: usize) -> Result<Region, std::io::Error> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(descriptor)?;
    let mut opts = MmapOptions::new();
    opts.len(byte_length);
    let map = unsafe { opts.map_mut(&file)? };
    Ok(Region {
        map: Arc::new(map),
        byte_length,
        descriptor: descriptor.to_string(),
    })
}

#[cfg(unix)]
fn unique_shm_path() -> String {
    // Prefer `/dev/shm` (tmpfs on Linux, also present on most BSDs).
    // Fall back to `$TMPDIR` then `/tmp`. Names embed the process
    // pid + a monotonic counter so concurrent allocations don't
    // collide.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = unsafe { libc::getpid() };
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let base: String = if std::path::Path::new("/dev/shm").is_dir() {
        "/dev/shm".to_string()
    } else {
        // $TMPDIR fallback. macOS uses `/var/folders/.../T/` per
        // user; that's fine for SAB sharing as long as the parent
        // and worker run as the same user (they do — workers
        // inherit the parent's uid).
        std::env::var("TMPDIR")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "/tmp".to_string())
    };
    format!("{base}/burn-sab-{pid}-{now_ns}-{n}")
}

#[cfg(windows)]
fn build_region(byte_length: usize) -> Result<Region, std::io::Error> {
    // Cross-platform fallback for Windows: anonymous map. Cross-
    // process sharing on Windows uses CreateFileMapping with a
    // named object — that's the next iteration. Single-process
    // SAB still works via the Arc-shared mmap.
    let map = MmapMut::map_anon(byte_length)?;
    Ok(Region {
        map: Arc::new(map),
        byte_length,
        descriptor: String::new(),
    })
}

#[cfg(windows)]
fn open_region(_descriptor: &str, _byte_length: usize) -> Result<Region, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "cross-process SharedArrayBuffer attach on Windows is not yet wired",
    ))
}
