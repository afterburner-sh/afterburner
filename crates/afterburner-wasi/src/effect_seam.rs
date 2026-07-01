// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The record/replay seam for host-mediated effects on the JS (WASM) substrate.
//!
//! Every `afterburner:host` import that performs an external side effect (a
//! file op, an HTTP call, an env read, a child process) routes through
//! [`seam`]. It builds the canonical
//! [`HostEffect`], consults the embedder's
//! [`HostContext::on_host_call`], and either **replays** a recorded result
//! (running no real effect) or runs the real effect and **records** a
//! [`HostEffectRecord`]. When no host
//! context is attached the closure runs directly with zero journaling
//! overhead - the sealed-runtime hot path pays nothing.
//!
//! # What the recorded `output` bytes are
//!
//! The seam records the **canonical content** the effect produced, not the
//! per-op guest wire form (base64 for a file read, a JSON envelope for an
//! HTTP response). The wire transform is applied by the call site *after* the
//! seam returns, identically on the record and replay paths, so a file's
//! recorded `output` is its raw bytes and its content-address matches the
//! same bytes seen anywhere else (the record/replay parity crux). Effects
//! that are inherently multi-field with no single "content" (a child process
//! yields status + stdout + stderr) record their exact guest-visible result
//! envelope instead - lossless, and never cross-referenced with a file
//! content-address, so parity does not apply.
//!
//! # The borrowed-host bridge
//!
//! [`Combustor::run_with_result`](afterburner_core::Combustor::run_with_result)
//! hands the substrate a `&dyn HostContext`, but the Wasmtime `Store` that
//! threads the host into every import is `'static`. `BorrowedHostContext`
//! erases the borrow's lifetime into a `'static` `Arc` for exactly the
//! duration of one run; its safety invariant is upheld by the single caller.

use std::sync::Arc;
use std::time::Instant;

use afterburner_core::effect::{EffectStatus, HostEffect, HostEffectRecord};
use afterburner_core::error::AfterburnerError;
use afterburner_core::host::HostContext;

/// A success status carrying no effect-native code (`code = 0`) and no row
/// count - the common case for filesystem ops whose only result is their
/// content bytes.
pub const fn ok() -> EffectStatus {
    EffectStatus::Ok {
        code: 0,
        rows: None,
    }
}

/// A success status carrying an effect-native `code` (an HTTP status, a
/// process exit code) and no row count.
pub const fn ok_code(code: i64) -> EffectStatus {
    EffectStatus::Ok { code, rows: None }
}

/// What the seam resolved to, from the call site's perspective. The call site
/// maps `Output` to the guest wire form and the two error shapes to the
/// import's negative error code.
pub enum Seamed {
    /// Success (freshly run or replayed): the canonical content `bytes` plus
    /// the terminal `status` (carries the code for ops that need it, e.g. the
    /// HTTP status). The call site applies the guest wire transform.
    Output {
        bytes: Vec<u8>,
        status: EffectStatus,
    },
    /// A live failure from the real effect. The call site maps it to a guest
    /// error code (via `map_err`); the seam already journaled it as an
    /// [`EffectStatus::Err`] on the record path.
    LiveError(AfterburnerError),
    /// A replayed failure: the recorded error payload bytes. The call site
    /// records them as `last_error` and returns its op's error code.
    ReplayedError(Vec<u8>),
}

/// Run `effect` through the record/replay seam.
///
/// * No host context attached -> `real` runs, nothing is journaled.
/// * `on_host_call` returns `Some(record)` -> **replay**: `real` does NOT
///   run; the recorded result is returned.
/// * otherwise -> **record**: `real` runs, is wall-clock timed, and a
///   [`HostEffectRecord`] is appended via `record_host_effect`.
///
/// `real` receives the built `&HostEffect` so a write can borrow its `input`
/// bytes rather than the call site cloning the payload.
pub fn seam<F>(host: Option<Arc<dyn HostContext>>, effect: HostEffect, real: F) -> Seamed
where
    F: FnOnce(&HostEffect) -> Result<(Vec<u8>, EffectStatus), AfterburnerError>,
{
    let Some(hc) = host else {
        // Sealed / non-recording path: run the real effect, journal nothing.
        return match real(&effect) {
            Ok((bytes, status)) => Seamed::Output { bytes, status },
            Err(e) => Seamed::LiveError(e),
        };
    };

    // Replay: a recorded result short-circuits the real effect entirely.
    if let Some(record) = hc.on_host_call(&effect) {
        return match record.status {
            EffectStatus::Err(msg) => Seamed::ReplayedError(msg),
            status @ EffectStatus::Ok { .. } => Seamed::Output {
                bytes: record.output,
                status,
            },
        };
    }

    // Record: run the real effect, time it, journal the outcome (success or
    // failure - a failure path emits the same record a success does).
    let start = Instant::now();
    let outcome = real(&effect);
    let duration_ms = start.elapsed().as_millis() as u64;
    match outcome {
        Ok((bytes, status)) => {
            hc.record_host_effect(HostEffectRecord::new(
                effect,
                bytes.clone(),
                duration_ms,
                status.clone(),
            ));
            Seamed::Output { bytes, status }
        }
        Err(e) => {
            hc.record_host_effect(HostEffectRecord::new(
                effect,
                Vec::new(),
                duration_ms,
                EffectStatus::Err(e.to_string().into_bytes()),
            ));
            Seamed::LiveError(e)
        }
    }
}

/// A `'static` [`HostContext`] that forwards to a borrowed one for the
/// lifetime of a single
/// [`WasmCombustor::run_with_result`](crate::wasm_engine::WasmCombustor::run_with_result)
/// call.
///
/// The Wasmtime `Store` that carries the host into every import is `'static`,
/// but the `Combustor::run_with_result` contract hands the substrate a
/// `&dyn HostContext`. This forwarder bridges the two by erasing the borrow's
/// lifetime.
///
/// # Safety invariant
///
/// The wrapped reference MUST outlive every clone of the `Arc` returned by
/// [`BorrowedHostContext::wrap`]. `run_with_result` upholds this: it is the
/// sole caller; the `Store` (the only long-lived owner of the `Arc`) and
/// every transient clone the effect seam makes are dropped before the call
/// returns - including on an unwinding trap, since the `Store` is a local -
/// which is strictly before the borrowed reference's lifetime ends (the
/// reference is a parameter that outlives the whole call). No clone escapes
/// the synchronous run.
struct BorrowedHostContext {
    /// Lifetime-erased pointer to the borrowed host. Only dereferenced while
    /// the safety invariant holds.
    inner: *const (dyn HostContext + 'static),
}

// SAFETY: the pointee is `HostContext: Send + Sync`, and the pointer is only
// dereferenced on the calling thread within the scoped lifetime the safety
// invariant guarantees. wasmtime runs the guest synchronously on this thread;
// the `Store` is never moved to another thread during the call.
unsafe impl Send for BorrowedHostContext {}
unsafe impl Sync for BorrowedHostContext {}

impl BorrowedHostContext {
    /// Wrap a borrowed [`HostContext`] in a `'static` [`Arc`] for the
    /// duration of one run.
    ///
    /// # Safety
    ///
    /// The caller MUST guarantee `host` outlives every clone of the returned
    /// `Arc` (see the type-level safety invariant).
    pub unsafe fn wrap(host: &dyn HostContext) -> Arc<dyn HostContext> {
        // Erase the borrow lifetime to 'static. A `&dyn T` and a
        // `*const (dyn T + 'static)` share an identical runtime representation
        // (data pointer + vtable pointer); only the compile-time lifetime
        // differs. Sound only under the safety invariant above.
        let erased: *const (dyn HostContext + 'static) = unsafe {
            core::mem::transmute::<*const dyn HostContext, *const (dyn HostContext + 'static)>(
                host as *const dyn HostContext,
            )
        };
        Arc::new(BorrowedHostContext { inner: erased })
    }

    /// Borrow the wrapped host. Safe under the type's invariant.
    fn get(&self) -> &(dyn HostContext + 'static) {
        // SAFETY: upheld by the type-level invariant - the pointee outlives
        // every clone of the owning `Arc`, so it is live for this call.
        unsafe { &*self.inner }
    }
}

impl HostContext for BorrowedHostContext {
    fn log(&self, level: afterburner_core::LogLevel, message: &str) {
        self.get().log(level, message)
    }

    fn read_column(&self, name: &str) -> Vec<serde_json::Value> {
        self.get().read_column(name)
    }

    fn emit_row(&self, row: serde_json::Value) {
        self.get().emit_row(row)
    }

    fn get_env(&self, key: &str) -> Option<String> {
        self.get().get_env(key)
    }

    #[cfg(feature = "host-http")]
    fn http_request(
        &self,
        url: &str,
        method: afterburner_core::HttpMethod,
        body: Option<&str>,
    ) -> afterburner_core::Result<afterburner_core::HttpResponse> {
        self.get().http_request(url, method, body)
    }

    fn on_host_call(&self, effect: &HostEffect) -> Option<HostEffectRecord> {
        self.get().on_host_call(effect)
    }

    fn record_host_effect(&self, record: HostEffectRecord) {
        self.get().record_host_effect(record)
    }

    fn get_effect_log(&self) -> Vec<HostEffectRecord> {
        self.get().get_effect_log()
    }
}

/// Bridge a borrowed [`HostContext`] into a `'static` [`Arc`] for one run.
///
/// # Safety
///
/// `host` MUST outlive every clone of the returned `Arc`. See
/// `BorrowedHostContext` for the full invariant; `run_with_result` is the
/// only caller and upholds it.
pub unsafe fn borrow_host(host: &dyn HostContext) -> Arc<dyn HostContext> {
    unsafe { BorrowedHostContext::wrap(host) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afterburner_core::effect::{EffectDetail, EffectKind, FileOp, fs_target};
    use std::sync::Mutex;

    /// A recording + optionally-replaying host for the seam tests.
    #[derive(Default)]
    struct TestHost {
        /// Records appended by `record_host_effect`, in call order.
        recorded: Mutex<Vec<HostEffectRecord>>,
        /// When set, `on_host_call` returns this for any effect (replay).
        replay: Mutex<Option<HostEffectRecord>>,
    }

    impl HostContext for TestHost {
        fn on_host_call(&self, _effect: &HostEffect) -> Option<HostEffectRecord> {
            self.replay.lock().unwrap().clone()
        }
        fn record_host_effect(&self, record: HostEffectRecord) {
            self.recorded.lock().unwrap().push(record);
        }
        fn get_effect_log(&self) -> Vec<HostEffectRecord> {
            self.recorded.lock().unwrap().clone()
        }
    }

    fn read_effect() -> HostEffect {
        HostEffect::new(
            EffectKind::Fs(FileOp::Read),
            fs_target("/x"),
            Vec::new(),
            EffectDetail::None,
            None,
        )
    }

    #[test]
    fn no_host_runs_real_and_journals_nothing() {
        let seamed = seam(None, read_effect(), |_| Ok((b"live".to_vec(), ok())));
        match seamed {
            Seamed::Output { bytes, .. } => assert_eq!(bytes, b"live"),
            _ => panic!("expected Output"),
        }
    }

    #[test]
    fn record_path_runs_real_and_journals_the_output() {
        let host: Arc<dyn HostContext> = Arc::new(TestHost::default());
        let seamed = seam(Some(host.clone()), read_effect(), |_| {
            Ok((b"disk-bytes".to_vec(), ok()))
        });
        match seamed {
            Seamed::Output { bytes, .. } => assert_eq!(bytes, b"disk-bytes"),
            _ => panic!("expected Output"),
        }
        let log = host.get_effect_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].output, b"disk-bytes");
        // output_hash is BLAKE3(output), computed by HostEffectRecord::new.
        assert_eq!(
            log[0].output_hash,
            afterburner_core::content_hash(b"disk-bytes")
        );
    }

    #[test]
    fn replay_substitutes_recorded_output_without_running_real() {
        let recorded = HostEffectRecord::new(read_effect(), b"recorded".to_vec(), 3, ok());
        let host = Arc::new(TestHost::default());
        *host.replay.lock().unwrap() = Some(recorded);
        let host_dyn: Arc<dyn HostContext> = host.clone();

        let mut ran = false;
        let seamed = seam(Some(host_dyn), read_effect(), |_| {
            ran = true;
            Ok((b"should-not-run".to_vec(), ok()))
        });
        assert!(!ran, "real effect must not run on replay");
        match seamed {
            Seamed::Output { bytes, .. } => assert_eq!(bytes, b"recorded"),
            _ => panic!("expected replayed Output"),
        }
        // Replay journals nothing new.
        assert!(host.get_effect_log().is_empty());
    }

    #[test]
    fn live_error_is_journaled_and_surfaced() {
        let host: Arc<dyn HostContext> = Arc::new(TestHost::default());
        let seamed = seam(Some(host.clone()), read_effect(), |_| {
            Err(AfterburnerError::Host("boom".into()))
        });
        assert!(matches!(seamed, Seamed::LiveError(_)));
        let log = host.get_effect_log();
        assert_eq!(log.len(), 1);
        assert!(matches!(log[0].status, EffectStatus::Err(_)));
    }

    #[test]
    fn replayed_error_reproduces_the_recorded_failure() {
        let recorded = HostEffectRecord::new(
            read_effect(),
            Vec::new(),
            1,
            EffectStatus::Err(b"ENOENT".to_vec()),
        );
        let host = Arc::new(TestHost::default());
        *host.replay.lock().unwrap() = Some(recorded);
        let host_dyn: Arc<dyn HostContext> = host;
        let seamed = seam(Some(host_dyn), read_effect(), |_| {
            panic!("real must not run on replay")
        });
        match seamed {
            Seamed::ReplayedError(msg) => assert_eq!(msg, b"ENOENT"),
            _ => panic!("expected ReplayedError"),
        }
    }

    #[test]
    fn borrowed_host_forwards_and_stays_sound_within_scope() {
        let real = TestHost::default();
        // Bridge a borrow into a 'static Arc, use it, drop it - all before
        // `real`'s borrow ends. This mirrors run_with_result's usage.
        {
            let bridged = unsafe { borrow_host(&real) };
            bridged.record_host_effect(HostEffectRecord::new(
                read_effect(),
                b"via-borrow".to_vec(),
                0,
                ok(),
            ));
        }
        assert_eq!(real.get_effect_log().len(), 1);
        assert_eq!(real.get_effect_log()[0].output, b"via-borrow");
    }
}
