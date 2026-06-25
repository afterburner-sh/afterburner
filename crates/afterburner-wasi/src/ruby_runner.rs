// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Helper for running the bundled ruby.wasm interpreter and capturing its
//! stdout.
//!
//! The bundled binary (`usr/local/bin/ruby` from the stock
//! `ruby-3.4-wasm32-unknown-wasip1-full` release) is a plain WASI command
//! module: it exports `_start` and imports only `wasi_snapshot_preview1`. So it
//! runs directly through [`EmbedderVm::run_command`] - no dynamic linking, no
//! exnref translation, no host stubs (unlike the Emscripten/Pyodide path). The
//! source runs as a script FILE (`ruby <file>`): CRuby's `-e <source>` cold-boot
//! path can spin indefinitely under WASI, so the file path is the one reliable
//! path (it is exactly what the package runner uses). The stdlib is mounted
//! read-only at the guest path the binary's compiled-in load path expects, so
//! `require 'json'` (and the rest of the stdlib) resolves with no `RUBYLIB`.
//!
//! CRuby writes program output to fd 1 and diagnostics (an uncaught exception,
//! a syntax error) to fd 2; the embedder captures both, so a failing run shows
//! its reason rather than exiting silently.
//!
//! [`run_ruby`] is the one canonical run path; both `burn run x.rb` and the
//! Ruby REPL call it. When no runtime is available (neither the build-time
//! bundle nor a `BURN_RUBY_RUNTIME` override), the resolver returns an honest,
//! actionable error - never a fake success.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use afterburner_core::{AfterburnerError, Result};

use crate::embedder_vm::{EmbedderVm, WasiCommandOpts};

/// Instruction budget for one `ruby -e` run. CRuby's WASI boot (interpreter
/// init + loading the prelude) is heavy: a measured cold boot of `puts 1 + 1`
/// consumes well under 4e12 instructions, so 8e12 leaves generous headroom for
/// real user code while still bounding a runaway loop (it surfaces as
/// `AfterburnerError::FuelExhausted` rather than hanging the thread).
///
/// vertexia: global fuel budget; a per-phase split (boot vs user code) would
/// let us bound user code tighter once we expose the boot cost separately.
const RUBY_FUEL: u64 = 8_000_000_000_000;

/// Guest mount point for the cached `usr` tree. The standalone binary's
/// compiled-in load path is absolute under `/usr/local/lib/ruby/<abi>`, and
/// CRuby's `gem_prelude` calls `realpath` on the load-path roots up to `/usr`
/// at startup - so the whole `/usr` prefix must resolve. Mounting the cached
/// `usr` here gives CRuby its stdlib with no `RUBYLIB` and no realpath error.
const GUEST_USR_MOUNT: &str = "/usr";

/// Guest mount point for a `burn run <pkg.afb>` Ruby package's source tree.
/// The unpacked `source/` dir is preopened read-only here, added to
/// `$LOAD_PATH` via `-I`, and the entry is run by its path under this prefix -
/// so `require_relative './helper'` (relative to the entry) and
/// `require 'helper'` (via the load path) both resolve sibling modules.
const GUEST_PKG_MOUNT: &str = "/pkg";

/// A fully-resolved Ruby runtime: the standalone interpreter wasm and the
/// stdlib dir to mount read-only.
///
/// Resolved by [`resolve_ruby_runtime`], which prefers the explicit
/// `BURN_RUBY_RUNTIME` override and otherwise loads the self-contained bundle
/// the build script assembled (see [`crate::ruby_bundle`]). So `burn run x.rb`
/// runs with no configuration, while a developer can still point at a custom
/// runtime.
#[derive(Debug, Clone)]
pub struct RubyRuntime {
    /// The standalone `ruby.wasm` (a WASI command module).
    pub wasm_path: PathBuf,
    /// The `usr` tree mounted read-only at guest `/usr`. `None` means run
    /// sealed with no stdlib (bare `puts`/arithmetic still work; a `require` of
    /// a stdlib file would then fail honestly).
    pub usr_dir: Option<PathBuf>,
}

/// Output from a [`run_ruby`] call.
#[derive(Debug, Clone)]
pub struct RubyRunOutput {
    /// Bytes the Ruby process wrote to stdout (fd 1) - `puts`, `print`, `p`.
    pub stdout: Vec<u8>,
    /// Bytes the Ruby process wrote to stderr (fd 2) - an uncaught exception, a
    /// syntax error, `warn`. Empty on a clean run with no diagnostics.
    pub stderr: Vec<u8>,
    /// Process exit code (`0` = success). A Ruby exception exits non-zero.
    pub exit_code: i32,
}

/// Resolve the Ruby runtime to run, honoring (in order):
///
/// 1. `BURN_RUBY_RUNTIME=<dir>` - a directory containing `ruby.wasm`. The `usr`
///    tree (mounted at guest `/usr`) comes from `BURN_RUBY_USR=<dir>` if set,
///    else `<dir>/usr` when present, else none (sealed - bare scripts still
///    run).
/// 2. The self-contained runtime under `~/.burn`, fetched lazily on first use
///    ([`crate::ruby_bundle::resolve`]). The default path, on the CLI and on a
///    programmatic embed alike.
///
/// Returns `Err` (honest, actionable) when neither is available.
pub fn resolve_ruby_runtime() -> Result<RubyRuntime> {
    if let Ok(dir) = std::env::var("BURN_RUBY_RUNTIME") {
        let wasm_path = Path::new(&dir).join("ruby.wasm");
        if !wasm_path.exists() {
            return Err(AfterburnerError::Engine(format!(
                "ruby runtime not found; {} does not exist. BURN_RUBY_RUNTIME must point at a \
                 directory containing ruby.wasm (a wasm32-wasip1 CRuby command module)",
                wasm_path.display()
            )));
        }
        let usr_dir = std::env::var("BURN_RUBY_USR")
            .map(PathBuf::from)
            .ok()
            .or_else(|| {
                let d = Path::new(&dir).join("usr");
                d.exists().then_some(d)
            });
        return Ok(RubyRuntime { wasm_path, usr_dir });
    }

    if let Some(b) = crate::ruby_bundle::resolve() {
        return Ok(RubyRuntime {
            wasm_path: b.wasm_path,
            usr_dir: Some(b.usr_dir),
        });
    }

    Err(AfterburnerError::Engine(
        "ruby runtime not found. The runtime could not be fetched into ~/.burn on first use \
         (network unavailable); set BURN_RUBY_RUNTIME=<dir> with ruby.wasm, or re-run with \
         network access to fetch the stock ruby.wasm release."
            .to_owned(),
    ))
}

/// Run a `.rb` program on the self-contained, zero-config runtime (or a
/// `BURN_RUBY_RUNTIME` override): boot the bundled CRuby WASI module, mount the
/// stdlib read-only, run the source as a script file, and return stdout + exit
/// code.
///
/// This is the entry point behind `burn run x.rb` and the Ruby REPL. It
/// resolves the runtime via [`resolve_ruby_runtime`] (so no env vars are needed
/// on a normal build).
///
/// # Errors
///
/// Returns `Err` when no runtime is available (neither bundled nor via
/// `BURN_RUBY_RUNTIME`), or when boot / run traps (fuel exhaustion, a wasm
/// trap). A Ruby-level error (an exception, a syntax error) is NOT an `Err`: it
/// surfaces as a non-zero `exit_code` with the message on `stderr`, matching
/// the process convention the other native runners use.
pub fn run_ruby(ruby_source: &str) -> Result<RubyRunOutput> {
    let rt = resolve_ruby_runtime()?;
    run_ruby_with(&rt, ruby_source)
}

/// Process-unique, monotonic temp dir: `<tmpdir>/<prefix>-<pid>-<n>`. No
/// wall-clock or RNG (both are unavailable / non-deterministic here); a static
/// counter plus the pid is unique within and across concurrent runs.
fn unique_tmp_dir(prefix: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// Boot a resolved [`RubyRuntime`] and run a single `.rb` source on it, returning
/// stdout + exit code. [`run_ruby`] is a thin shim that resolves the runtime
/// first.
///
/// The source is staged as `main.rb` in a unique temp dir and run via
/// [`run_ruby_package_with`] (i.e. `ruby <file>`), then the dir is removed.
/// CRuby's `-e <source>` cold-boot path can spin indefinitely under WASI, so the
/// script-file path is the one reliable run path - shared with the package
/// runner, so single-file and package runs cannot diverge.
pub fn run_ruby_with(rt: &RubyRuntime, ruby_source: &str) -> Result<RubyRunOutput> {
    let dir = unique_tmp_dir("burn-rb-run");
    std::fs::create_dir_all(&dir)
        .map_err(|e| AfterburnerError::Engine(format!("create {}: {e}", dir.display())))?;
    let entry = dir.join("main.rb");
    let out = std::fs::write(&entry, ruby_source)
        .map_err(|e| AfterburnerError::Engine(format!("write {}: {e}", entry.display())))
        .and_then(|()| run_ruby_package_with(rt, &dir, "main.rb"));
    let _ = std::fs::remove_dir_all(&dir);
    out
}

/// Run a Ruby *package* (a `burn run <pkg.afb>` Ruby package, or a directory of
/// `.rb` files) on the bundled runtime: boot CRuby, preopen `pkg_dir`
/// read-only, add it to `$LOAD_PATH`, and run the entry by its path under the
/// package mount - so sibling modules resolve.
///
/// `entry_rel` is the entry file's path RELATIVE to `pkg_dir` (e.g.
/// `"main.rb"`). Both forms of cross-file load work:
/// - `require_relative './helper'` (resolved relative to the entry's own guest
///   path under [`GUEST_PKG_MOUNT`]), and
/// - `require 'helper'` (resolved via the `-I<mount>` load-path entry).
///
/// This reuses the stdlib-mount machinery of [`run_ruby_with`]: it is the same
/// `preopen_ro` + `WasiCommandOpts` path, with one extra read-only preopen for
/// the package source and the entry passed as a script path instead of `-e`.
///
/// # Errors
///
/// Returns `Err` when no runtime is available, when `pkg_dir` does not exist,
/// or when boot / run traps (a fuel exhaustion, a wasm trap). A Ruby-level
/// error (an exception, a syntax error) is NOT an `Err`: it surfaces as a
/// non-zero `exit_code` with the message on `stderr`.
pub fn run_ruby_package(pkg_dir: &Path, entry_rel: &str) -> Result<RubyRunOutput> {
    let rt = resolve_ruby_runtime()?;
    run_ruby_package_with(&rt, pkg_dir, entry_rel)
}

/// Boot a resolved [`RubyRuntime`] and run a Ruby package rooted at `pkg_dir`
/// with entry `entry_rel`. The one canonical package run path; [`run_ruby_package`]
/// is a thin shim that resolves the runtime first.
pub fn run_ruby_package_with(
    rt: &RubyRuntime,
    pkg_dir: &Path,
    entry_rel: &str,
) -> Result<RubyRunOutput> {
    if !pkg_dir.is_dir() {
        return Err(AfterburnerError::Engine(format!(
            "ruby package directory {} does not exist",
            pkg_dir.display()
        )));
    }

    let wasm_bytes = std::fs::read(&rt.wasm_path)
        .map_err(|e| AfterburnerError::Engine(format!("read {}: {e}", rt.wasm_path.display())))?;

    let vm = EmbedderVm::new()?;
    let module = vm.compile(&wasm_bytes, true, |_| Ok(()))?;

    // The entry's guest path: under the package mount, with forward slashes.
    let entry_fwd = entry_rel.replace('\\', "/");
    let guest_entry = format!("{GUEST_PKG_MOUNT}/{entry_fwd}");

    // Load-path roots, both prepended to `$LOAD_PATH` via `-I`:
    //   - the entry's own directory (e.g. `/pkg/source`), so `require 'helper'`
    //     resolves a sibling sitting next to the entry (the flat-`source/` case);
    //   - the package mount root (`/pkg`), so `require 'source/helper'` (a
    //     subdir-qualified name) also resolves.
    // Running the entry by its real guest path keeps `require_relative` working
    // and sets `__FILE__`/`__dir__` correctly.
    let entry_dir = match entry_fwd.rsplit_once('/') {
        Some((dir, _file)) => format!("{GUEST_PKG_MOUNT}/{dir}"),
        None => GUEST_PKG_MOUNT.to_owned(),
    };
    let i_entry_dir = format!("-I{entry_dir}");
    let i_root = format!("-I{GUEST_PKG_MOUNT}");
    let mut opts = WasiCommandOpts::new().args([
        "ruby",
        i_entry_dir.as_str(),
        i_root.as_str(),
        guest_entry.as_str(),
    ]);

    // Stdlib first (same machinery as `run_ruby_with`), then the package source.
    if let Some(usr) = &rt.usr_dir {
        opts = opts.preopen_ro(usr, GUEST_USR_MOUNT);
    }
    opts = opts.preopen_ro(pkg_dir, GUEST_PKG_MOUNT);

    let out = vm.run_command(&module, opts, Some(RUBY_FUEL))?;
    Ok(RubyRunOutput {
        stdout: out.stdout,
        stderr: out.stderr,
        exit_code: out.result as i32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `resolve_ruby_runtime` is total: `Ok` when a runtime resolves (a
    /// `BURN_RUBY_RUNTIME` override or a populated `~/.burn`), an honest,
    /// actionable `Err` otherwise. Never panics.
    ///
    /// `#[ignore]`: a cold cache makes this fetch the stock runtime into
    /// `~/.burn` over the network, so it is opt-in (run explicitly). The
    /// network-free manifest-resolution logic is covered by
    /// [`crate::ruby_bundle`]'s `resolve_dir` tests.
    #[test]
    #[ignore = "fetches the real ~/.burn Ruby runtime on a cold cache; run explicitly"]
    fn resolve_is_total_and_honest() {
        match resolve_ruby_runtime() {
            Ok(rt) => assert!(rt.wasm_path.exists(), "resolved ruby.wasm must exist"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("ruby runtime not found") && msg.contains("BURN_RUBY_RUNTIME"),
                    "error must be actionable: {msg}"
                );
            }
        }
    }

    /// End-to-end: `ruby -e 'puts 1 + 1'` runs on the resolved runtime and prints
    /// `2`. `#[ignore]`: fetches the stock runtime into `~/.burn` on a cold cache,
    /// so it is opt-in (the CLI cold-download path is the operator's verify).
    #[test]
    #[ignore = "fetches/uses the real ~/.burn Ruby runtime; run explicitly"]
    fn run_ruby_puts_when_bundled() {
        let rt = match resolve_ruby_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!("skip: no ruby runtime assembled in this build");
                return;
            }
        };
        let out = run_ruby_with(&rt, "puts 1 + 1").expect("run_ruby_with");
        let text = String::from_utf8_lossy(&out.stdout);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.exit_code, 0,
            "clean exit; stdout={text:?} stderr={err:?}"
        );
        assert!(
            text.contains('2'),
            "expected 2 in stdout, got {text:?} stderr={err:?}"
        );
    }

    /// `run_ruby_package_with` on a directory that does not exist is an honest
    /// `Err`, not a panic - even with no runtime assembled.
    #[test]
    fn run_ruby_package_missing_dir_errors() {
        let rt = RubyRuntime {
            wasm_path: PathBuf::from("/nonexistent/ruby.wasm"),
            usr_dir: None,
        };
        let err = run_ruby_package_with(&rt, Path::new("/no/such/pkg/dir"), "source/main.rb")
            .expect_err("missing dir must error");
        assert!(
            err.to_string().contains("does not exist"),
            "error must name the missing dir: {err}"
        );
    }

    /// End-to-end multi-file: a package whose entry `require`s a sibling module
    /// runs on the resolved runtime and prints the value computed via the
    /// sibling. Proves the package source tree is on `$LOAD_PATH`. `#[ignore]`:
    /// fetches/uses the real `~/.burn` Ruby runtime, so it is opt-in.
    #[test]
    #[ignore = "fetches/uses the real ~/.burn Ruby runtime; run explicitly"]
    fn run_ruby_package_resolves_sibling_require() {
        let rt = match resolve_ruby_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!("skip: no ruby runtime assembled in this build");
                return;
            }
        };

        // Write a 2-file package to a unique temp dir: main.rb requires helper.rb.
        let root = std::env::temp_dir().join(format!(
            "burn-rb-pkg-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("source");
        std::fs::create_dir_all(&src).expect("create source dir");
        std::fs::write(
            src.join("helper.rb"),
            "module Helper\n  def self.square(n); n * n; end\nend\n",
        )
        .expect("write helper.rb");
        std::fs::write(
            src.join("main.rb"),
            "require 'helper'\nputs \"sq=#{Helper.square(9)}\"\n",
        )
        .expect("write main.rb");

        let out =
            run_ruby_package_with(&rt, &root, "source/main.rb").expect("run_ruby_package_with");
        let _ = std::fs::remove_dir_all(&root);

        let text = String::from_utf8_lossy(&out.stdout);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.exit_code, 0,
            "clean exit; stdout={text:?} stderr={err:?}"
        );
        assert!(
            text.contains("sq=81"),
            "sibling require must resolve (9*9=81), got stdout={text:?} stderr={err:?}"
        );
    }
}
