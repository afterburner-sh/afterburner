// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Ceiling-bounded stdout capture with structured overflow reporting.
//!
//! [`CapturePipe`] replaces the bare `MemoryOutputPipe` as the guest's
//! stdout. The upstream pipe enforces its capacity by failing the
//! over-budget `fd_write` with `StreamError::Closed` / `Trap`, which
//! WASI p1 maps to errno 29 (`EIO`) — the guest's `Javy.IO.writeSync`
//! then throws and the whole call surfaces as an opaque
//! `wasm trap: unreachable` with "os error 29" buried in stderr. That
//! gave results a hard 1 MiB cliff with no structured diagnosis.
//!
//! `CapturePipe` keeps the guest-visible contract (an over-ceiling
//! write still fails fast, so a runaway script stops paying for output
//! it can never deliver) but additionally records the overflow in a
//! flag the host consults after the run: `chamber::fire` and the
//! script-mode path map a set flag to
//! [`AfterburnerError::OutputTooLarge`](afterburner_core::AfterburnerError::OutputTooLarge)
//! instead of an opaque trap. Storage grows on demand — nothing is
//! pre-allocated at the ceiling; a small result on a 64 MiB ceiling
//! costs what the result costs.
//!
//! Concurrency: one writer (the guest, single-threaded per `Store`),
//! reads only after the call completes. The byte storage delegates to
//! the upstream `MemoryOutputPipe` (which is the pipe this type
//! replaces); the ceiling accounting is a plain atomic counter so the
//! hot `fd_write` path adds two relaxed atomic ops, no locking of its
//! own. Not a throughput path in the PERFORMANCE.md rule-7 sense —
//! the result crosses once per call.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::p2::{OutputStream, Pollable, StreamError};

/// Growable result-capture pipe with a hard byte ceiling and a
/// host-readable overflow flag. See the module docs for the contract.
#[derive(Clone)]
pub struct CapturePipe {
    /// Byte storage. Constructed with capacity == `ceiling`, so the
    /// inner capacity check can never fire — [`CapturePipe::write`]
    /// rejects over-ceiling writes before they reach it.
    inner: MemoryOutputPipe,
    /// Hard cap on total bytes accepted. `FuelGauge::output_ceiling()`
    /// resolved by the caller that builds the `HostState`.
    ceiling: usize,
    /// Total bytes accepted so far, shared across clones (the WASI
    /// descriptor table holds one clone, `HostState` another).
    written: Arc<AtomicUsize>,
    /// Set when a write past the ceiling was rejected. The host maps
    /// a set flag to `AfterburnerError::OutputTooLarge`.
    overflow: Arc<AtomicBool>,
}

impl CapturePipe {
    /// New pipe accepting at most `ceiling` bytes in total.
    pub fn new(ceiling: usize) -> Self {
        Self {
            inner: MemoryOutputPipe::new(ceiling),
            ceiling,
            written: Arc::new(AtomicUsize::new(0)),
            overflow: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Snapshot of everything captured so far.
    pub fn contents(&self) -> Bytes {
        self.inner.contents()
    }

    /// `true` once any write past the ceiling was rejected — the
    /// capture is then truncated and the call's result is void.
    pub fn overflowed(&self) -> bool {
        self.overflow.load(Ordering::Acquire)
    }

    /// The ceiling this pipe was built with.
    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Remaining budget below the ceiling.
    fn remaining(&self) -> usize {
        self.ceiling
            .saturating_sub(self.written.load(Ordering::Relaxed))
    }

    /// Record an over-ceiling attempt and produce the stream error the
    /// guest sees (WASI p1 maps it to errno 29, same failure shape the
    /// fixed-capacity pipe produced — the structured mapping happens
    /// host-side off the flag).
    fn reject(&self) -> StreamError {
        self.overflow.store(true, Ordering::Release);
        StreamError::LastOperationFailed(wasmtime::format_err!(
            "script output exceeded the {} byte ceiling (FuelGauge::output_bytes)",
            self.ceiling
        ))
    }
}

#[wasmtime_wasi::async_trait]
impl OutputStream for CapturePipe {
    fn write(&mut self, bytes: Bytes) -> Result<(), StreamError> {
        if bytes.len() > self.remaining() {
            return Err(self.reject());
        }
        self.inner.write(bytes.clone())?;
        self.written.fetch_add(bytes.len(), Ordering::Relaxed);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StreamError> {
        self.inner.flush()
    }

    /// Never reports the stream as closed: a zero permit would make
    /// the p1 write loop error on its *leading* readiness check while
    /// the *trailing* post-flush check at an exactly-full capture (a
    /// legal, complete result) takes the identical path — the two are
    /// indistinguishable here. Reporting a ≥1-byte permit instead
    /// routes the overflow decision through [`Self::write`], the one
    /// place that knows bytes are actually pending, so an exact-fit
    /// result succeeds and only a true over-ceiling write trips the
    /// flag.
    fn check_write(&mut self) -> Result<usize, StreamError> {
        Ok(self.remaining().max(1))
    }
}

#[wasmtime_wasi::async_trait]
impl Pollable for CapturePipe {
    async fn ready(&mut self) {}
}

impl IsTerminal for CapturePipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CapturePipe {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }

    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

impl tokio::io::AsyncWrite for CapturePipe {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        let remaining = self.remaining();
        if remaining == 0 {
            let err = self.reject();
            return std::task::Poll::Ready(Err(std::io::Error::other(format!("{err}"))));
        }
        let amt = buf.len().min(remaining);
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &buf[..amt]) {
            std::task::Poll::Ready(Ok(n)) => {
                this.written.fetch_add(n, Ordering::Relaxed);
                std::task::Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_up_to_ceiling_exactly() {
        let mut p = CapturePipe::new(8);
        assert!(p.write(Bytes::from_static(b"12345678")).is_ok());
        assert!(!p.overflowed());
        assert_eq!(&p.contents()[..], b"12345678");
        // Trailing readiness probe at exactly-full must not trip the flag.
        assert!(p.check_write().is_ok());
        assert!(!p.overflowed());
    }

    #[test]
    fn rejects_past_ceiling_and_sets_flag() {
        let mut p = CapturePipe::new(8);
        assert!(p.write(Bytes::from_static(b"1234567")).is_ok());
        assert!(p.write(Bytes::from_static(b"89")).is_err());
        assert!(p.overflowed());
        // Earlier bytes are retained (truncated capture), later rejected.
        assert_eq!(&p.contents()[..], b"1234567");
    }

    #[test]
    fn check_write_reports_at_least_one_byte() {
        let mut p = CapturePipe::new(4);
        assert_eq!(p.check_write().ok(), Some(4));
        assert!(p.write(Bytes::from_static(b"1234")).is_ok());
        // Full: permit stays ≥1 so the next real write takes the
        // reject path (with the flag) instead of an anonymous Closed.
        assert_eq!(p.check_write().ok(), Some(1));
        assert!(p.write(Bytes::from_static(b"5")).is_err());
        assert!(p.overflowed());
    }
}
