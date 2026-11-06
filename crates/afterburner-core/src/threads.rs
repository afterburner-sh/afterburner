// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The one way afterburner starts a thread. An embedding engine installs
//! [`ThreadHooks`] and a [`ThreadBudget`] once, before the first call, and
//! every thread afterburner starts is then named, sized and placed through
//! them, with its pool clamped to the budget so the embedder's cores are
//! never oversubscribed. Without an install threads start unplaced and pools
//! size from [`ThreadBudget::for_cores`]; the standalone `burn` binary calls
//! [`install_pinned`], which pins each kind to its own cores.
//!
//! Invariant: the installed state is one `OnceLock`; a spawn reads it once
//! and takes no lock.

use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};

/// What a thread afterburner starts is for: the embedder places and sizes each kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ThreadKind {
    /// A daemon accept/dispatch shard.
    DaemonShard,
    /// A daemon worker (request execution, worker pool member).
    DaemonWorker,
    /// An OS thread backing a guest pthread.
    GuestThread,
    /// A native compile thread.
    NativeCompile,
    /// Any other helper or progress thread.
    Background,
}

/// One thread about to start: its kind, its index among its kind's threads, its name.
pub struct ThreadSpec<'a> {
    /// The kind of thread.
    pub kind: ThreadKind,
    /// Its index among the threads of its kind.
    pub index: usize,
    /// Its OS-visible name.
    pub name: &'a str,
}

/// The embedder's placement of afterburner's threads, installed once.
pub trait ThreadHooks: Send + Sync + 'static {
    /// Runs first on every new thread, before its body: pin it, set its priority, account for it.
    fn on_start(&self, spec: &ThreadSpec<'_>);
    /// The stack size for a thread of `kind`; `None` keeps afterburner's own.
    fn stack_size(&self, _kind: ThreadKind) -> Option<usize> {
        None
    }
}

/// How many threads of each kind afterburner may run at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadBudget {
    /// Daemon shard threads.
    pub daemon_shards: usize,
    /// Daemon worker threads.
    pub daemon_workers: usize,
    /// Guest pthread OS threads.
    pub guest_threads: usize,
    /// Native compile threads.
    pub native_compile: usize,
    /// Background helper threads.
    pub background: usize,
}

impl ThreadBudget {
    /// A budget for `cores` cores when no embedder installed one (the standalone `burn` binary): every kind at least one.
    #[must_use]
    pub fn for_cores(cores: usize) -> Self {
        let cores = cores.max(1);
        Self {
            daemon_shards: cores,
            daemon_workers: cores,
            guest_threads: cores,
            native_compile: cores,
            background: (cores / 2).max(1),
        }
    }

    /// The cap for `kind`.
    #[must_use]
    pub fn of(&self, kind: ThreadKind) -> usize {
        match kind {
            ThreadKind::DaemonShard => self.daemon_shards,
            ThreadKind::DaemonWorker => self.daemon_workers,
            ThreadKind::GuestThread => self.guest_threads,
            ThreadKind::NativeCompile => self.native_compile,
            ThreadKind::Background => self.background,
        }
    }
}

/// A second [`install`] in one process.
#[derive(Debug)]
pub struct AlreadyInstalled;

impl std::fmt::Display for AlreadyInstalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("thread hooks and budget are already installed for this process")
    }
}

impl std::error::Error for AlreadyInstalled {}

struct Installed {
    hooks: Arc<dyn ThreadHooks>,
    budget: ThreadBudget,
}

static INSTALLED: OnceLock<Installed> = OnceLock::new();
static DEFAULT_BUDGET: OnceLock<ThreadBudget> = OnceLock::new();

/// Install the embedder's hooks and budget, once per process, before afterburner starts a thread.
pub fn install(hooks: Arc<dyn ThreadHooks>, budget: ThreadBudget) -> Result<(), AlreadyInstalled> {
    INSTALLED
        .set(Installed { hooks, budget })
        .map_err(|_| AlreadyInstalled)
}

/// The budget in force: the installed one, else `ThreadBudget::for_cores` of the available parallelism.
#[must_use]
pub fn budget() -> ThreadBudget {
    match INSTALLED.get() {
        Some(i) => i.budget,
        None => *DEFAULT_BUDGET.get_or_init(|| {
            ThreadBudget::for_cores(thread::available_parallelism().map_or(1, |n| n.get()))
        }),
    }
}

/// The hooks (if installed) and a named, sized builder for a thread of `kind`.
fn prepare(kind: ThreadKind, name: &str) -> (Option<Arc<dyn ThreadHooks>>, thread::Builder) {
    let hooks = INSTALLED.get().map(|i| Arc::clone(&i.hooks));
    let mut builder = thread::Builder::new().name(name.to_owned());
    if let Some(size) = hooks.as_ref().and_then(|h| h.stack_size(kind)) {
        builder = builder.stack_size(size);
    }
    (hooks, builder)
}

fn run_start(hooks: Option<&Arc<dyn ThreadHooks>>, kind: ThreadKind, index: usize, name: &str) {
    if let Some(h) = hooks {
        h.on_start(&ThreadSpec { kind, index, name });
    }
}

/// Start a thread of `kind`: named, sized and placed through the installed hooks. The one way afterburner starts a thread.
pub fn spawn<F, T>(
    kind: ThreadKind,
    index: usize,
    name: String,
    body: F,
) -> std::io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (hooks, builder) = prepare(kind, &name);
    builder.spawn(move || {
        run_start(hooks.as_ref(), kind, index, &name);
        body()
    })
}

/// [`spawn`] for a thread inside a `std::thread::scope`: the same name, stack size and `on_start` placement.
pub fn spawn_scoped<'scope, 'env, F, T>(
    s: &'scope thread::Scope<'scope, 'env>,
    kind: ThreadKind,
    index: usize,
    name: String,
    body: F,
) -> std::io::Result<thread::ScopedJoinHandle<'scope, T>>
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    let (hooks, builder) = prepare(kind, &name);
    builder.spawn_scoped(s, move || {
        run_start(hooks.as_ref(), kind, index, &name);
        body()
    })
}

/// Parse a kernel cpu list such as `0-3,8,10-11`; malformed pieces are skipped.
fn parse_cpulist(s: &str) -> Vec<usize> {
    s.trim()
        .split(',')
        .flat_map(|p| {
            let (lo, hi) = p.split_once('-').unwrap_or((p, p));
            match (lo.trim().parse::<usize>(), hi.trim().parse::<usize>()) {
                (Ok(lo), Ok(hi)) if lo <= hi => lo..hi + 1,
                _ => 0..0,
            }
        })
        .collect()
}

/// The CPUs the calling process may run on, ascending.
#[cfg(target_os = "linux")]
fn affinity_mask() -> Vec<usize> {
    // SAFETY: a zeroed cpu_set_t is a valid empty set; the kernel fills it and
    // CPU_ISSET reads only offsets below CPU_SETSIZE.
    let set = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return Vec::new();
        }
        set
    };
    (0..libc::CPU_SETSIZE as usize)
        // SAFETY: `c` is below CPU_SETSIZE.
        .filter(|&c| unsafe { libc::CPU_ISSET(c, &set) })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn affinity_mask() -> Vec<usize> {
    Vec::new()
}

/// Sort key of `cpu`: SMT rank, NUMA node, physical core, cpu id; unreadable topology keys on the cpu id alone.
fn topology_key(cpu: usize) -> (usize, usize, usize, usize) {
    let base = format!("/sys/devices/system/cpu/cpu{cpu}");
    let siblings = std::fs::read_to_string(format!("{base}/topology/thread_siblings_list"))
        .map(|s| parse_cpulist(&s))
        .unwrap_or_default();
    let rank = siblings.iter().position(|&c| c == cpu).unwrap_or(0);
    let leader = siblings.iter().copied().min().unwrap_or(cpu);
    let node = std::fs::read_dir(&base)
        .ok()
        .and_then(|d| {
            d.flatten().find_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_prefix("node")?
                    .parse::<usize>()
                    .ok()
            })
        })
        .unwrap_or(0);
    (rank, node, leader, cpu)
}

/// The process's allowed CPUs in topology order: one thread per physical core first (node by node), then the SMT siblings.
/// Falls back to the affinity-mask order when `/sys` is unreadable, and to `0..available_parallelism` without a mask.
#[must_use]
pub fn cores() -> &'static [usize] {
    static CORES: OnceLock<Vec<usize>> = OnceLock::new();
    CORES.get_or_init(|| {
        let mut mask = affinity_mask();
        if mask.is_empty() {
            mask = (0..thread::available_parallelism().map_or(1, |n| n.get())).collect();
        }
        mask.sort_by_key(|&c| topology_key(c));
        mask
    })
}

/// Pin the calling thread to exactly `core`. A no-op answering `Ok` on a platform without thread affinity.
pub fn pin_current_to(core: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if core >= libc::CPU_SETSIZE as usize {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        // SAFETY: a zeroed cpu_set_t is a valid empty set and `core` is below CPU_SETSIZE.
        let ret = unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(core, &mut set);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = core;
    Ok(())
}

const KINDS: usize = 5;

/// Slot of `kind` in layout order: shards first, then workers, guest, compile, background last.
fn slot(kind: ThreadKind) -> usize {
    match kind {
        ThreadKind::DaemonShard => 0,
        ThreadKind::DaemonWorker => 1,
        ThreadKind::GuestThread => 2,
        ThreadKind::NativeCompile => 3,
        ThreadKind::Background => 4,
    }
}

/// [`ThreadHooks`] that pins every thread to its kind's own slice of a core list, so threads never spread on start.
pub struct Pinned {
    cores: Vec<usize>,
    /// (first core index, length) per slot.
    slices: [(usize, usize); KINDS],
}

impl Pinned {
    /// Lay `budget`'s kinds over `cores`: each kind gets its own consecutive slice (its budget while the budget fits,
    /// else scaled down to at least one core), and a kind with more threads than its slice wraps round within it.
    #[must_use]
    pub fn for_budget(budget: &ThreadBudget, cores: &[usize]) -> Self {
        const ORDER: [ThreadKind; KINDS] = [
            ThreadKind::DaemonShard,
            ThreadKind::DaemonWorker,
            ThreadKind::GuestThread,
            ThreadKind::NativeCompile,
            ThreadKind::Background,
        ];
        let n = cores.len();
        let want = ORDER.map(|k| budget.of(k).max(1));
        let total: usize = want.iter().sum();
        let mut slices = [(0, 0); KINDS];
        let mut start = 0;
        for (i, w) in want.iter().enumerate() {
            let len = if total <= n {
                *w
            } else {
                (w * n / total).max(1)
            };
            slices[i] = (start % n.max(1), len);
            start += len;
        }
        Self {
            cores: cores.to_vec(),
            slices,
        }
    }

    /// The core thread `index` of `kind` pins to; `None` when the core list is empty.
    #[must_use]
    pub fn core_for(&self, kind: ThreadKind, index: usize) -> Option<usize> {
        let (start, len) = self.slices[slot(kind)];
        let n = self.cores.len();
        (n > 0).then(|| self.cores[(start + index % len.max(1)) % n])
    }
}

impl ThreadHooks for Pinned {
    fn on_start(&self, spec: &ThreadSpec<'_>) {
        let Some(core) = self.core_for(spec.kind, spec.index) else {
            return;
        };
        if let Err(e) = pin_current_to(core) {
            eprintln!(
                "thread {} could not be pinned to core {core}: {e}",
                spec.name
            );
        }
    }
}

/// [`install`] with [`Pinned`] over [`cores`]: the standalone binary's way to pin every thread it starts.
pub fn install_pinned(budget: ThreadBudget) -> Result<(), AlreadyInstalled> {
    install(Arc::new(Pinned::for_budget(&budget, cores())), budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_cores_scales_and_never_gives_a_kind_zero() {
        let kinds = [
            ThreadKind::DaemonShard,
            ThreadKind::DaemonWorker,
            ThreadKind::GuestThread,
            ThreadKind::NativeCompile,
            ThreadKind::Background,
        ];
        for k in kinds {
            assert_eq!(ThreadBudget::for_cores(0).of(k), 1);
            assert!(ThreadBudget::for_cores(64).of(k) >= ThreadBudget::for_cores(4).of(k));
        }
        assert_eq!(ThreadBudget::for_cores(16).daemon_shards, 16);
        assert_eq!(ThreadBudget::for_cores(16).of(ThreadKind::Background), 8);
    }

    #[test]
    fn of_maps_each_kind_to_its_field() {
        let b = ThreadBudget {
            daemon_shards: 1,
            daemon_workers: 2,
            guest_threads: 3,
            native_compile: 4,
            background: 5,
        };
        assert_eq!(b.of(ThreadKind::DaemonShard), 1);
        assert_eq!(b.of(ThreadKind::DaemonWorker), 2);
        assert_eq!(b.of(ThreadKind::GuestThread), 3);
        assert_eq!(b.of(ThreadKind::NativeCompile), 4);
        assert_eq!(b.of(ThreadKind::Background), 5);
    }

    // One test owns the process-wide install: hook sees each spec once on the
    // new thread before the body, stack sizes apply, a second install is refused.
    #[test]
    fn installed_hooks_place_every_thread_once_before_its_body() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Rec {
            seen: Mutex<Vec<(ThreadKind, usize, String, thread::ThreadId)>>,
            starts: AtomicUsize,
        }
        struct H(Arc<Rec>);
        impl ThreadHooks for H {
            fn on_start(&self, spec: &ThreadSpec<'_>) {
                self.0.starts.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut v) = self.0.seen.lock() {
                    v.push((
                        spec.kind,
                        spec.index,
                        spec.name.to_string(),
                        thread::current().id(),
                    ));
                }
            }
            fn stack_size(&self, kind: ThreadKind) -> Option<usize> {
                (kind == ThreadKind::GuestThread).then_some(8 << 20)
            }
        }

        let rec = Arc::new(Rec {
            seen: Mutex::new(Vec::new()),
            starts: AtomicUsize::new(0),
        });
        let budget = ThreadBudget::for_cores(3);
        install(Arc::new(H(rec.clone())), budget).expect("first install");
        assert!(install(Arc::new(H(rec.clone())), budget).is_err());
        assert_eq!(super::budget(), budget);

        let starts = rec.clone();
        let (id, started_before_body) =
            spawn(ThreadKind::DaemonShard, 7, "ab-test".into(), move || {
                (thread::current().id(), starts.starts.load(Ordering::SeqCst))
            })
            .expect("spawn")
            .join()
            .expect("join");
        assert_eq!(started_before_body, 1);
        let seen = rec.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, ThreadKind::DaemonShard);
        assert_eq!(seen[0].1, 7);
        assert_eq!(seen[0].2, "ab-test");
        assert_eq!(seen[0].3, id);
        drop(seen);

        let size = spawn(ThreadKind::GuestThread, 0, "ab-guest".into(), || {
            // A stack frame of this size only fits when the hook's size applied.
            let buf = [1u8; 4 << 20];
            buf.iter().map(|&b| usize::from(b)).sum::<usize>()
        })
        .expect("spawn")
        .join()
        .expect("join");
        assert_eq!(size, 4 << 20);

        thread::scope(|s| {
            spawn_scoped(s, ThreadKind::Background, 3, "ab-scoped".into(), || ())
                .expect("spawn scoped")
                .join()
                .expect("join");
        });
        let seen = rec.seen.lock().expect("lock");
        assert!(
            seen.iter()
                .any(|e| e.0 == ThreadKind::Background && e.1 == 3 && e.2 == "ab-scoped")
        );
    }

    #[test]
    fn parse_cpulist_reads_ranges_and_singles() {
        assert_eq!(parse_cpulist("0-2,5,7-8\n"), vec![0, 1, 2, 5, 7, 8]);
        assert_eq!(parse_cpulist("3"), vec![3]);
        assert!(parse_cpulist("x,2-1").is_empty());
    }

    #[test]
    fn cores_is_non_empty_and_inside_the_mask() {
        let c = cores();
        assert!(!c.is_empty());
        let mask = affinity_mask();
        if !mask.is_empty() {
            assert!(c.iter().all(|x| mask.contains(x)));
            assert_eq!(c.len(), mask.len());
        }
        let mut sorted = c.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), c.len());
    }

    #[test]
    fn pinned_gives_kinds_disjoint_cores_while_there_are_enough() {
        let cores: Vec<usize> = (0..10).collect();
        let b = ThreadBudget {
            daemon_shards: 3,
            daemon_workers: 3,
            guest_threads: 1,
            native_compile: 1,
            background: 2,
        };
        let p = Pinned::for_budget(&b, &cores);
        let kinds = [
            ThreadKind::DaemonShard,
            ThreadKind::DaemonWorker,
            ThreadKind::GuestThread,
            ThreadKind::NativeCompile,
            ThreadKind::Background,
        ];
        let mut used = std::collections::HashSet::new();
        for k in kinds {
            for i in 0..b.of(k) {
                let core = p.core_for(k, i).expect("core");
                assert!(used.insert(core), "core {core} shared");
            }
            // Past the slice, the index wraps inside the kind's own cores.
            assert_eq!(p.core_for(k, b.of(k)), p.core_for(k, 0));
        }
        assert_eq!(used.len(), 10);
    }

    #[test]
    fn pinned_oversubscribed_budget_still_pins_every_kind() {
        let p = Pinned::for_budget(&ThreadBudget::for_cores(16), &[4, 5]);
        for k in [ThreadKind::DaemonShard, ThreadKind::Background] {
            assert!(matches!(p.core_for(k, 9), Some(4 | 5)));
        }
        let none = Pinned::for_budget(&ThreadBudget::for_cores(2), &[]);
        assert_eq!(none.core_for(ThreadKind::Background, 0), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_pinned_thread_has_exactly_its_core() {
        let core = cores()[0];
        let got = thread::spawn(move || {
            pin_current_to(core).expect("pin");
            affinity_mask()
        })
        .join()
        .expect("join");
        assert_eq!(got, vec![core]);
    }
}
