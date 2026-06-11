// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Concurrent installs. The resolved, content-addressed set is fetched across a
//! pool of worker threads. Lock-free: atomics for the work cursor and
//! cancellation, a `kovan_channel` for results (no shared locks). Progress
//! goes through [`Progress`] and IO through [`Installer`], so the pool is
//! testable without a network or a terminal.

use crate::cache;
use crate::client::RegistryClient;
use crate::error::{CloudError, Result};
use kovan_channel::flavors::unbounded::channel;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// One package to install: a `namespace/name`, its version, and its content
/// digest (`sha256:<hex>` or bare hex).
#[derive(Debug, Clone)]
pub struct InstallItem {
    pub coord: String,
    pub version: String,
    pub digest: String,
}

impl InstallItem {
    pub fn new(
        coord: impl Into<String>,
        version: impl Into<String>,
        digest: impl Into<String>,
    ) -> Self {
        Self {
            coord: coord.into(),
            version: version.into(),
            digest: digest.into(),
        }
    }
    fn digest_hex(&self) -> &str {
        self.digest.trim_start_matches("sha256:")
    }
}

/// What happened to one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Freshly downloaded + verified + cached.
    Installed,
    /// Already present in the content-addressed cache (skipped).
    Cached,
}

/// Does the actual "ensure this item is in the cache" work. The real impl
/// downloads + verifies + stores; tests use a mock. Must be `Sync` (shared
/// across worker threads). Returns the outcome and an optional non-fatal note.
pub trait Installer: Sync {
    fn ensure(&self, item: &InstallItem) -> Result<(Outcome, Option<String>)>;
}

/// Progress sink, called from worker threads (so `Sync`). Default no-ops let an
/// impl override only what it needs. Implementors must coordinate lock-free
/// (atomics / channels) - these hooks must never block.
pub trait Progress: Sync {
    fn begin(&self, _total: usize) {}
    fn started(&self, _coord: &str) {}
    fn done(&self, _coord: &str, _outcome: &Outcome) {}
    fn failed(&self, _coord: &str, _err: &str) {}
    fn finish(&self) {}
}

/// A `Progress` that does nothing.
pub struct NoProgress;
impl Progress for NoProgress {}

/// What an install run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InstallSummary {
    /// Coords freshly downloaded this run (sorted).
    pub installed: Vec<String>,
    /// Coords that were already cached (sorted).
    pub cached: Vec<String>,
    /// `(coord, note)` warnings (e.g. needs a newer runtime).
    pub warnings: Vec<(String, String)>,
}

/// One worker's report for a single item, shipped back over the channel.
enum Report {
    Ok {
        coord: String,
        outcome: Outcome,
        warning: Option<String>,
    },
    Err(CloudError),
}

/// Install `items` concurrently across `jobs` workers. Already-cached digests
/// are skipped. On the first failure, in-flight work drains and the error is
/// returned (no partial-success ambiguity for the caller).
pub fn install_concurrent(
    items: &[InstallItem],
    installer: &dyn Installer,
    jobs: usize,
    progress: &dyn Progress,
) -> Result<InstallSummary> {
    progress.begin(items.len());
    if items.is_empty() {
        progress.finish();
        return Ok(InstallSummary::default());
    }

    let jobs = jobs.clamp(1, items.len());
    let next = AtomicUsize::new(0);
    let abort = AtomicBool::new(false);
    let (tx, rx) = channel::<Report>();

    std::thread::scope(|scope| {
        // `&` so each `move` closure captures a copy; the atomics aren't `Copy`.
        let (next, abort) = (&next, &abort);
        for _ in 0..jobs {
            let tx = tx.clone();
            scope.spawn(move || {
                while !abort.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    let item = &items[i];
                    progress.started(&item.coord);
                    match installer.ensure(item) {
                        Ok((outcome, warning)) => {
                            progress.done(&item.coord, &outcome);
                            tx.send(Report::Ok {
                                coord: item.coord.clone(),
                                outcome,
                                warning,
                            });
                        }
                        Err(e) => {
                            progress.failed(&item.coord, &e.to_string());
                            abort.store(true, Ordering::Relaxed);
                            tx.send(Report::Err(e));
                            break;
                        }
                    }
                }
            });
        }
    });
    // Worker clones are gone after the scope join; drop ours so the drain ends.
    drop(tx);
    progress.finish();

    let mut summary = InstallSummary::default();
    let mut first_err = None;
    while let Some(report) = rx.try_recv() {
        match report {
            Report::Ok {
                coord,
                outcome,
                warning,
            } => {
                match outcome {
                    Outcome::Installed => summary.installed.push(coord.clone()),
                    Outcome::Cached => summary.cached.push(coord.clone()),
                }
                if let Some(w) = warning {
                    summary.warnings.push((coord, w));
                }
            }
            Report::Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    summary.installed.sort();
    summary.cached.sort();
    summary.warnings.sort();
    Ok(summary)
}

/// The real installer: content-cache check, then download + verify + store.
pub struct CacheInstaller<'a> {
    pub client: &'a RegistryClient,
}

impl Installer for CacheInstaller<'_> {
    fn ensure(&self, item: &InstallItem) -> Result<(Outcome, Option<String>)> {
        let digest = item.digest_hex();
        if cache::contains(digest) {
            return Ok((Outcome::Cached, None));
        }
        let (ns, name) = item
            .coord
            .split_once('/')
            .ok_or_else(|| CloudError::BadCoord(item.coord.clone()))?;
        let bytes = self.client.download(ns, name, &item.version)?;
        let stored = cache::verify_and_store(digest, &bytes)?;
        Ok((Outcome::Installed, stored.warning))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Counts how many `ensure` calls it saw and the peak concurrency; returns
    /// `Cached` for a configured set, an error for a configured coord, else
    /// `Installed`. Entirely lock-free (atomics only).
    struct MockInstaller {
        calls: AtomicUsize,
        cached: HashSet<String>,
        fail: Option<String>,
        concurrent_peak: AtomicUsize,
        in_flight: AtomicUsize,
    }
    impl MockInstaller {
        fn new(cached: &[&str], fail: Option<&str>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                cached: cached.iter().map(|s| s.to_string()).collect(),
                fail: fail.map(String::from),
                concurrent_peak: AtomicUsize::new(0),
                in_flight: AtomicUsize::new(0),
            }
        }
    }
    impl Installer for MockInstaller {
        fn ensure(&self, item: &InstallItem) -> Result<(Outcome, Option<String>)> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.concurrent_peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(5));
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if self.fail.as_deref() == Some(item.coord.as_str()) {
                return Err(CloudError::Transport(format!("boom on {}", item.coord)));
            }
            if self.cached.contains(&item.coord) {
                Ok((Outcome::Cached, None))
            } else {
                Ok((Outcome::Installed, None))
            }
        }
    }

    /// Lock-free progress recorder: pure atomic counters.
    struct CountingProgress {
        begun: AtomicUsize,
        done: AtomicUsize,
        finished: AtomicBool,
    }
    impl CountingProgress {
        fn new() -> Self {
            Self {
                begun: AtomicUsize::new(0),
                done: AtomicUsize::new(0),
                finished: AtomicBool::new(false),
            }
        }
    }
    impl Progress for CountingProgress {
        fn begin(&self, total: usize) {
            self.begun.store(total, Ordering::SeqCst);
        }
        fn done(&self, _c: &str, _o: &Outcome) {
            self.done.fetch_add(1, Ordering::SeqCst);
        }
        fn finish(&self) {
            self.finished.store(true, Ordering::SeqCst);
        }
    }

    fn items(coords: &[&str]) -> Vec<InstallItem> {
        coords
            .iter()
            .map(|c| InstallItem::new(*c, "1.0.0", "deadbeef"))
            .collect()
    }

    #[test]
    fn installs_all_concurrently_with_progress() {
        let its = items(&["a/1", "a/2", "a/3", "a/4", "a/5", "a/6"]);
        let inst = MockInstaller::new(&[], None);
        let prog = CountingProgress::new();
        let s = install_concurrent(&its, &inst, 4, &prog).unwrap();
        assert_eq!(s.installed.len(), 6);
        assert_eq!(inst.calls.load(Ordering::SeqCst), 6);
        assert_eq!(prog.begun.load(Ordering::SeqCst), 6);
        assert_eq!(prog.done.load(Ordering::SeqCst), 6);
        assert!(prog.finished.load(Ordering::SeqCst));
        // Proof of actual concurrency: more than one ensure() ran at once.
        assert!(
            inst.concurrent_peak.load(Ordering::SeqCst) >= 2,
            "expected concurrent work"
        );
    }

    #[test]
    fn results_are_sorted_and_split_by_outcome() {
        let its = items(&["a/3", "a/1", "a/2"]);
        let inst = MockInstaller::new(&["a/2"], None);
        let s = install_concurrent(&its, &inst, 3, &NoProgress).unwrap();
        assert_eq!(s.cached, vec!["a/2".to_string()]);
        assert_eq!(s.installed, vec!["a/1".to_string(), "a/3".to_string()]);
    }

    #[test]
    fn first_error_aborts_and_propagates() {
        let its = items(&["a/1", "a/2", "a/3", "a/4"]);
        let inst = MockInstaller::new(&[], Some("a/3"));
        let err = install_concurrent(&its, &inst, 2, &NoProgress).unwrap_err();
        assert!(matches!(err, CloudError::Transport(_)), "got {err:?}");
    }

    #[test]
    fn empty_set_is_ok() {
        let inst = MockInstaller::new(&[], None);
        let s = install_concurrent(&[], &inst, 8, &NoProgress).unwrap();
        assert_eq!(s, InstallSummary::default());
    }

    #[test]
    fn jobs_is_clamped() {
        // jobs=0 and jobs>len must both work.
        let its = items(&["a/1", "a/2"]);
        let inst = MockInstaller::new(&[], None);
        assert_eq!(
            install_concurrent(&its, &inst, 0, &NoProgress)
                .unwrap()
                .installed
                .len(),
            2
        );
        let inst2 = MockInstaller::new(&[], None);
        assert_eq!(
            install_concurrent(&its, &inst2, 99, &NoProgress)
                .unwrap()
                .installed
                .len(),
            2
        );
    }
}
