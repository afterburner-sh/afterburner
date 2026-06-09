// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Concurrent installs. Packages are content-addressed and independent, so the
//! resolved set is fetched in parallel across a small pool of worker threads
//! (the client is `ureq`/blocking, so threads are the right tool). The
//! orchestrator is UI-free: progress is reported through a [`Progress`] trait so
//! the CLI can plug in an `indicatif` bar, and the IO sits behind [`Installer`]
//! so the concurrency is unit-testable without a network or a real cache.

use crate::cache;
use crate::client::RegistryClient;
use crate::error::Result;
use std::sync::Mutex;
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
    pub fn new(coord: impl Into<String>, version: impl Into<String>, digest: impl Into<String>) -> Self {
        Self { coord: coord.into(), version: version.into(), digest: digest.into() }
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
/// impl override only what it needs.
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
    let summary = Mutex::new(InstallSummary::default());
    let first_err = Mutex::new(None);

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                while !abort.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    let item = &items[i];
                    progress.started(&item.coord);
                    match installer.ensure(item) {
                        Ok((outcome, warning)) => {
                            let mut s = summary.lock().unwrap();
                            match outcome {
                                Outcome::Installed => s.installed.push(item.coord.clone()),
                                Outcome::Cached => s.cached.push(item.coord.clone()),
                            }
                            if let Some(w) = warning {
                                s.warnings.push((item.coord.clone(), w));
                            }
                            drop(s);
                            progress.done(&item.coord, &outcome);
                        }
                        Err(e) => {
                            progress.failed(&item.coord, &e.to_string());
                            let mut fe = first_err.lock().unwrap();
                            if fe.is_none() {
                                *fe = Some(e);
                            }
                            abort.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            });
        }
    });

    progress.finish();
    if let Some(e) = first_err.into_inner().unwrap() {
        return Err(e);
    }
    let mut s = summary.into_inner().unwrap();
    s.installed.sort();
    s.cached.sort();
    s.warnings.sort();
    Ok(s)
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
            .ok_or_else(|| crate::error::CloudError::BadCoord(item.coord.clone()))?;
        let bytes = self.client.download(ns, name, &item.version)?;
        let stored = cache::verify_and_store(digest, &bytes)?;
        Ok((Outcome::Installed, stored.warning))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CloudError;
    use std::collections::HashSet;
    use std::sync::Mutex as StdMutex;

    /// Records which items it saw; returns Cached for a configured set, an error
    /// for a configured coord, else Installed.
    struct MockInstaller {
        seen: StdMutex<Vec<String>>,
        cached: HashSet<String>,
        fail: Option<String>,
        concurrent_peak: AtomicUsize,
        in_flight: AtomicUsize,
    }
    impl MockInstaller {
        fn new(cached: &[&str], fail: Option<&str>) -> Self {
            Self {
                seen: StdMutex::new(vec![]),
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
            self.seen.lock().unwrap().push(item.coord.clone());
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

    struct CountingProgress {
        begun: AtomicUsize,
        done: AtomicUsize,
        finished: AtomicBool,
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
        coords.iter().map(|c| InstallItem::new(*c, "1.0.0", "deadbeef")).collect()
    }

    #[test]
    fn installs_all_concurrently_with_progress() {
        let its = items(&["a/1", "a/2", "a/3", "a/4", "a/5", "a/6"]);
        let inst = MockInstaller::new(&[], None);
        let prog = CountingProgress {
            begun: AtomicUsize::new(0),
            done: AtomicUsize::new(0),
            finished: AtomicBool::new(false),
        };
        let s = install_concurrent(&its, &inst, 4, &prog).unwrap();
        assert_eq!(s.installed.len(), 6);
        assert_eq!(inst.seen.lock().unwrap().len(), 6);
        assert_eq!(prog.begun.load(Ordering::SeqCst), 6);
        assert_eq!(prog.done.load(Ordering::SeqCst), 6);
        assert!(prog.finished.load(Ordering::SeqCst));
        // Proof of actual concurrency: more than one ensure() ran at once.
        assert!(inst.concurrent_peak.load(Ordering::SeqCst) >= 2, "expected concurrent work");
    }

    #[test]
    fn cached_are_skipped_not_reinstalled() {
        let its = items(&["a/1", "a/2", "a/3"]);
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
        assert_eq!(install_concurrent(&its, &inst, 0, &NoProgress).unwrap().installed.len(), 2);
        let inst2 = MockInstaller::new(&[], None);
        assert_eq!(install_concurrent(&its, &inst2, 99, &NoProgress).unwrap().installed.len(), 2);
    }
}
