// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! A persistent JS (WASM) [`Session`]: a runtime whose filesystem root and
//! cross-invocation key/value store survive across successive
//! [`run`](Session::run) calls (R4).
//!
//! The session owns one [`WasmCombustor`] and one host directory root:
//!
//! * **FS persistence** is the real filesystem. Each [`run`](Session::run)
//!   grants [`FsAccess::ReadWrite`] rooted at the session dir and pins
//!   `process.cwd()` to it, so a script that writes under `process.cwd()` is
//!   visible to the next run and to the host-side [`fs_read`](Session::fs_read)
//!   / [`fs_write`](Session::fs_write) accessors, which go straight to
//!   `fs_host` on the same root (never through guest code).
//! * **State persistence** is the combustor's shared state store: the one
//!   `WasmCombustor` is reused across runs, so `require('afterburner:state')`
//!   in a later run observes what an earlier run stored.
//!
//! Path convention: every path passed to a `fs_*` accessor is interpreted
//! **relative to the session root** (a leading `/` is root-relative, never
//! host-absolute) - the session FS is a sandbox, not a window onto the host
//! filesystem. Guest scripts reach the same files through absolute paths under
//! `process.cwd()`.
//!
//! Language support: this is the JS substrate, so [`run`](Session::run)
//! accepts [`Language::Js`]. `Ts` needs the facade's transpiler (this crate
//! has no TS lowering); other languages have no source path. Both surface a
//! typed error rather than a silent no-op.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use afterburner_core::{
    AfterburnerError, Combustor, FsAccess, FuelGauge, Language, Manifold, NullHost, Result,
    RunResult, ScriptInvocation, Session,
};
use afterburner_node_compat::fs_host;

use crate::wasm_engine::{WasmCombustor, WasmConfig};

/// A persistent JS run session over a byte-exact filesystem root plus a
/// reused cross-invocation state store. Implements [`Session`].
pub struct WasmSession {
    /// The one engine, reused across runs so its [`SharedStateStore`] persists.
    ///
    /// [`SharedStateStore`]: afterburner_core::SharedStateStore
    combustor: WasmCombustor,
    /// The persistent host directory backing the session FS.
    root: PathBuf,
    /// Base per-run limits. The FS grant is set to the session root on every
    /// run; everything else (fuel, memory, timeout, net, env) is the caller's.
    limits: FuelGauge,
    /// Whether [`Drop`] removes [`Self::root`]. `true` for an auto-created
    /// temp root, `false` for a caller-supplied one.
    cleanup: bool,
}

impl WasmSession {
    /// Open a session with a fresh, auto-removed root under the OS temp dir
    /// and the given base limits. The FS grant is applied per run; pass
    /// `limits` with the fuel / memory / timeout / net / env profile you want
    /// every run to inherit (its `fs` field is overwritten per run).
    pub fn new(limits: FuelGauge) -> Result<Self> {
        let combustor = WasmCombustor::new(WasmConfig::default())?;
        let root = unique_session_dir();
        std::fs::create_dir_all(&root).map_err(|e| {
            AfterburnerError::Engine(format!("session: create root {}: {e}", root.display()))
        })?;
        Ok(Self {
            combustor,
            root,
            limits,
            cleanup: true,
        })
    }

    /// Open a session rooted at an explicit, caller-owned directory. The
    /// directory is created if absent and is **not** removed on drop, so a
    /// session can be resumed by re-opening the same root.
    pub fn with_root(root: PathBuf, limits: FuelGauge) -> Result<Self> {
        let combustor = WasmCombustor::new(WasmConfig::default())?;
        std::fs::create_dir_all(&root).map_err(|e| {
            AfterburnerError::Engine(format!("session: create root {}: {e}", root.display()))
        })?;
        Ok(Self {
            combustor,
            root,
            limits,
            cleanup: false,
        })
    }

    /// The persistent session root on the host filesystem.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The per-run manifold: the base limits' capabilities with the FS axis
    /// pinned to read-write access rooted at the session dir.
    fn session_manifold(&self) -> Manifold {
        let mut m = self.limits.manifold.clone();
        m.fs = FsAccess::ReadWrite(vec![self.root.clone()]);
        m
    }

    /// Resolve a session-relative path to an absolute host path under the
    /// session root. A leading `/` is stripped (root-relative), so a session
    /// path can never address the host filesystem outside the root - the FS
    /// host's `resolve_within` then rejects any residual `..` escape.
    fn resolve(&self, path: &str) -> PathBuf {
        let rel = path.strip_prefix('/').unwrap_or(path);
        self.root.join(rel)
    }

    /// The absolute session path as a `&str`, or a typed error for a
    /// non-UTF-8 path (unrepresentable on the guest wire).
    fn resolved_str(&self, path: &str) -> Result<(PathBuf, String)> {
        let abs = self.resolve(path);
        let s = abs
            .to_str()
            .ok_or_else(|| {
                AfterburnerError::Engine(format!(
                    "session: path {path:?} resolves to a non-UTF-8 host path"
                ))
            })?
            .to_owned();
        Ok((abs, s))
    }
}

impl Session for WasmSession {
    fn run(&mut self, code: &[u8], lang: Language) -> Result<RunResult> {
        let source = match lang {
            Language::Js => code,
            Language::Ts => {
                return Err(AfterburnerError::Engine(
                    "session.run: TypeScript must be transpiled to JS before running \
                     (the WASM substrate has no TS lowering; use the facade's \
                     run_source for TS, or pre-transpile)."
                        .into(),
                ));
            }
            other => {
                return Err(AfterburnerError::Engine(format!(
                    "session.run: {other:?} has no source-interpreter path; \
                     compile to wasm32-wasip1 and use register_precompiled."
                )));
            }
        };

        let mut limits = self.limits.clone();
        limits.manifold = self.session_manifold();

        let invocation = ScriptInvocation {
            argv: Vec::new(),
            env: Default::default(),
            // Pin process.cwd() to the session root so scripts address session
            // files through `path.join(process.cwd(), name)`.
            cwd: self.root.to_string_lossy().into_owned(),
        };

        // A plain session run records no effect journal (NullHost); the
        // recording seam is exercised by callers that pass their own host to
        // `run_with_result` directly.
        self.combustor
            .run_with_result(source, &invocation, &limits, &NullHost)
    }

    fn fs_read(&self, path: &str) -> Result<Vec<u8>> {
        let (_, abs) = self.resolved_str(path)?;
        fs_host::read_file_sync(&abs, &self.session_manifold())
    }

    fn fs_write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let (_, abs) = self.resolved_str(path)?;
        fs_host::write_file_sync(&abs, data, &self.session_manifold())
    }

    fn fs_exists(&self, path: &str) -> bool {
        match self.resolved_str(path) {
            Ok((_, abs)) => fs_host::exists_sync(&abs, &self.session_manifold()),
            Err(_) => false,
        }
    }
}

impl Drop for WasmSession {
    fn drop(&mut self) {
        if self.cleanup {
            // Best-effort: a leaked temp dir is not worth surfacing an error
            // from a destructor.
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

/// A process-unique session directory under the OS temp dir. Combines the pid,
/// a nanosecond clock read, and a monotonic counter so concurrent sessions in
/// one process never collide.
fn unique_session_dir() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("afterburner-session-{}-{nanos}-{n}", std::process::id());
    std::env::temp_dir().join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> WasmSession {
        WasmSession::new(FuelGauge::unlimited()).expect("build session")
    }

    #[test]
    fn fs_write_then_read_roundtrips_bytes() {
        let mut s = session();
        let payload = b"\x00\xff binary \xc3\x28 payload";
        assert!(!s.fs_exists("data.bin"));
        s.fs_write("data.bin", payload).expect("write");
        assert!(s.fs_exists("data.bin"));
        assert_eq!(s.fs_read("data.bin").expect("read"), payload);
    }

    #[test]
    fn leading_slash_is_root_relative_not_host_absolute() {
        let mut s = session();
        s.fs_write("/rooted.txt", b"ok").expect("write");
        // Same file, addressed with and without the leading slash.
        assert_eq!(s.fs_read("rooted.txt").expect("read"), b"ok");
        // It landed under the session root, not at host `/rooted.txt`.
        assert!(s.root().join("rooted.txt").exists());
    }

    #[test]
    fn guest_run_writes_are_visible_to_the_host_and_persist_across_runs() {
        let mut s = session();
        // Run 1: write a file under process.cwd() (the session root).
        let write_src = r#"
            const fs = require('fs');
            const path = require('path');
            fs.writeFileSync(path.join(process.cwd(), 'note.txt'), 'from-run-1');
        "#;
        let r1 = s.run(write_src.as_bytes(), Language::Js).expect("run 1");
        assert_eq!(
            r1.exit_code,
            0,
            "stderr: {}",
            String::from_utf8_lossy(&r1.stderr)
        );

        // The host sees the guest's write.
        assert_eq!(s.fs_read("note.txt").expect("host read"), b"from-run-1");

        // Run 2: read the file the previous run wrote - FS persisted.
        let read_src = r#"
            const fs = require('fs');
            const path = require('path');
            process.stdout.write(fs.readFileSync(path.join(process.cwd(), 'note.txt'), 'utf8'));
        "#;
        let r2 = s.run(read_src.as_bytes(), Language::Js).expect("run 2");
        assert_eq!(
            r2.exit_code,
            0,
            "stderr: {}",
            String::from_utf8_lossy(&r2.stderr)
        );
        // Byte-exact persistence is asserted host-side above; the runtime
        // frames captured stdout with a trailing newline, so trim it here.
        assert_eq!(String::from_utf8_lossy(&r2.stdout).trim_end(), "from-run-1");
    }

    #[test]
    fn non_js_language_is_a_typed_error_not_a_silent_noop() {
        let mut s = session();
        assert!(s.run(b"puts 1", Language::Ruby).is_err());
        assert!(s.run(b"const x: number = 1", Language::Ts).is_err());
    }
}
