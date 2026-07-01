// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! A persistent WASI-command [`Session`] (R4): a Ruby runtime whose filesystem
//! root survives across successive [`run`](Session::run) calls, byte-exact.
//!
//! The session owns one host directory (the session root) and one recording /
//! replaying [`HostContext`]. Every run:
//!
//! * mounts the session root read-write at guest `/pkg` (the package mount),
//!   so a script that writes under its `__dir__` (i.e. `/pkg/...`) leaves files
//!   the next run - and the host-side [`fs_read`](Session::fs_read) /
//!   [`fs_write`](Session::fs_write) accessors - can see, and
//! * threads the session host into the effect seam
//!   ([`run_ruby_package_with_host`]), so `clock_time_get` / `random_get` are
//!   recorded on the original run and replayed on a re-run (R1), and the typed
//!   return value comes back through the `/.afb` file-frame (R2/R3).
//!
//! Path convention: every path handed to a `fs_*` accessor is interpreted
//! **relative to the session root** (a leading `/` is root-relative, never
//! host-absolute, and a `..` component is rejected) - the session FS is a
//! sandbox, not a window onto the host filesystem. Guest scripts reach the same
//! files through absolute paths under the `/pkg` mount.
//!
//! Language support: this is the WASI-command substrate, so
//! [`run`](Session::run) accepts [`Language::Ruby`] (the one command language
//! with an in-runtime source path). `Rust` / `Go` / `C` / `Cpp` have no source
//! interpreter (they compile to a `wasm32-wasip1` module and run through
//! `register_precompiled`); they surface a typed error here rather than a silent
//! no-op.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use afterburner_core::{
    AfterburnerError, HostContext, Language, NullHost, Result, RunResult, Session,
};

use crate::ruby_runner::{RubyRuntime, resolve_ruby_runtime, run_ruby_package_with_host};

/// The entry file every session run is staged as, under the session root.
const SESSION_ENTRY: &str = "main.rb";

/// A persistent WASI-command run session over a byte-exact filesystem root.
/// Implements [`Session`]. See the module docs.
pub struct WasiCommandSession {
    /// The host directory that persists across runs; mounted at guest `/pkg`.
    root: PathBuf,
    /// The Ruby runtime, resolved lazily on the first [`run`](Session::run) so
    /// a FS-only session (or a test) never touches the network. `Clone` is
    /// cheap (two paths).
    rt: Option<RubyRuntime>,
    /// The record/replay seam consulted by every run.
    host: Arc<dyn HostContext>,
}

impl WasiCommandSession {
    /// Create a session rooted at `root` (created if absent), threading `host`
    /// into every run. The Ruby runtime is resolved lazily on the first
    /// [`run`](Session::run).
    pub fn new(root: impl Into<PathBuf>, host: Arc<dyn HostContext>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .map_err(|e| AfterburnerError::Engine(format!("create {}: {e}", root.display())))?;
        Ok(Self {
            root,
            rt: None,
            host,
        })
    }

    /// A sealed session (a [`NullHost`] seam): runs are deterministic and
    /// nothing is recorded. Convenience for callers that want only the
    /// persistent FS root.
    pub fn sealed(root: impl Into<PathBuf>) -> Result<Self> {
        Self::new(root, Arc::new(NullHost))
    }

    /// The session root on the host.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve (and cache) the Ruby runtime.
    fn runtime(&mut self) -> Result<RubyRuntime> {
        if self.rt.is_none() {
            self.rt = Some(resolve_ruby_runtime()?);
        }
        // Cheap clone (two `PathBuf`s); lets the borrow of `self` end before the
        // run borrows `self.root`.
        Ok(self.rt.as_ref().expect("just set").clone())
    }

    /// Resolve a session-relative path to a host path under [`root`](Self::root),
    /// rejecting an absolute-escape or a `..` component. A leading `/` is
    /// treated as root-relative.
    fn resolve(&self, path: &str) -> Result<PathBuf> {
        let rel = path.strip_prefix('/').unwrap_or(path);
        let rel_path = Path::new(rel);
        for comp in rel_path.components() {
            match comp {
                Component::Normal(_) | Component::CurDir => {}
                _ => {
                    return Err(AfterburnerError::Engine(format!(
                        "session path {path:?} escapes the session root (only \
                         root-relative paths without `..` are allowed)"
                    )));
                }
            }
        }
        Ok(self.root.join(rel_path))
    }
}

impl Session for WasiCommandSession {
    fn run(&mut self, code: &[u8], lang: Language) -> Result<RunResult> {
        match lang {
            Language::Ruby => {
                let src = std::str::from_utf8(code).map_err(|_| {
                    AfterburnerError::Engine("ruby session source is not valid UTF-8".into())
                })?;
                // Stage (overwrite) the entry at the session root, then run it.
                let entry = self.root.join(SESSION_ENTRY);
                std::fs::write(&entry, src).map_err(|e| {
                    AfterburnerError::Engine(format!("write {}: {e}", entry.display()))
                })?;
                let rt = self.runtime()?;
                let out = run_ruby_package_with_host(
                    &rt,
                    &self.root,
                    SESSION_ENTRY,
                    Some(self.host.clone()),
                )?;
                Ok(RunResult {
                    stdout: out.stdout,
                    stderr: out.stderr,
                    exit_code: out.exit_code,
                    output: out.output,
                })
            }
            Language::Rust | Language::Go | Language::C | Language::Cpp => {
                Err(AfterburnerError::Engine(format!(
                    "{lang:?} has no source interpreter: compile it to a \
                     wasm32-wasip1 command module and register it via \
                     `register_precompiled`. WasiCommandSession::run accepts \
                     Ruby source."
                )))
            }
            other => Err(AfterburnerError::Engine(format!(
                "WasiCommandSession runs the WASI-command languages; {other:?} \
                 is not one (use the JS or Python session instead)."
            ))),
        }
    }

    fn fs_read(&self, path: &str) -> Result<Vec<u8>> {
        let p = self.resolve(path)?;
        std::fs::read(&p)
            .map_err(|e| AfterburnerError::Engine(format!("read {}: {e}", p.display())))
    }

    fn fs_write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let p = self.resolve(path)?;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AfterburnerError::Engine(format!("create {}: {e}", parent.display()))
            })?;
        }
        std::fs::write(&p, data)
            .map_err(|e| AfterburnerError::Engine(format!("write {}: {e}", p.display())))
    }

    fn fs_exists(&self, path: &str) -> bool {
        self.resolve(path).map(|p| p.exists()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The FS accessors round-trip through the session root, and a later
    /// `fs_read` sees a byte-exact `fs_write` - no runtime needed.
    #[test]
    fn fs_accessors_round_trip_byte_exact() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = WasiCommandSession::sealed(tmp.path()).expect("new");

        assert!(!s.fs_exists("data.bin"));
        let payload = b"\x00\xff\n binary \xc3\x28 not-utf8";
        s.fs_write("data.bin", payload).expect("write");
        assert!(s.fs_exists("data.bin"));
        assert_eq!(s.fs_read("data.bin").expect("read"), payload);

        // Nested path creates parents; leading `/` is root-relative.
        s.fs_write("/sub/dir/x", b"deep").expect("nested write");
        assert_eq!(s.fs_read("sub/dir/x").expect("read nested"), b"deep");

        // The bytes are actually on the host under the root.
        assert!(tmp.path().join("data.bin").exists());
    }

    /// A `..` component (or any non-normal component) is rejected: the session
    /// FS is a sandbox, not a host window.
    #[test]
    fn fs_rejects_parent_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = WasiCommandSession::sealed(tmp.path()).expect("new");
        assert!(s.fs_write("../escape", b"x").is_err());
        assert!(s.fs_read("../../etc/passwd").is_err());
        assert!(!s.fs_exists("../escape"));
    }

    /// A non-command language is a typed error, never a silent no-op. Uses a
    /// path that resolves the runtime lazily only for Ruby, so this stays
    /// offline (the error returns before any runtime resolution).
    #[test]
    fn run_rejects_non_command_language() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = WasiCommandSession::sealed(tmp.path()).expect("new");
        let err = s
            .run(b"console.log(1)", Language::Js)
            .expect_err("js rejected");
        assert!(
            err.to_string().contains("WasiCommandSession"),
            "actionable error: {err}"
        );
        let err = s.run(b"int main(){}", Language::C).expect_err("c rejected");
        assert!(
            err.to_string().contains("register_precompiled"),
            "C directs to register_precompiled: {err}"
        );
    }
}
