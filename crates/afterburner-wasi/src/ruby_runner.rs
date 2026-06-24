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
//! runs directly through [`EmbedderVm::run_command`] with argv
//! `["ruby", "-e", <source>]` - no dynamic linking, no exnref translation, no
//! host stubs (unlike the Emscripten/Pyodide path). The stdlib is mounted
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
/// 2. The bundled runtime the build script assembled.
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
        "ruby runtime not found. The bundled ruby.wasm runtime was not assembled at build time \
         (network unavailable); set BURN_RUBY_RUNTIME=<dir> with ruby.wasm, or rebuild with \
         network access to fetch the stock ruby.wasm release."
            .to_owned(),
    ))
}

/// Run a `.rb` program on the self-contained, zero-config runtime (or a
/// `BURN_RUBY_RUNTIME` override): boot the bundled CRuby WASI module with
/// `ruby -e <source>`, mount the stdlib read-only, and return stdout + exit
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

/// Boot a resolved [`RubyRuntime`], run `ruby -e <source>`, return stdout +
/// exit code. The one canonical run path; [`run_ruby`] is a thin shim that
/// resolves the runtime first.
pub fn run_ruby_with(rt: &RubyRuntime, ruby_source: &str) -> Result<RubyRunOutput> {
    let wasm_bytes = std::fs::read(&rt.wasm_path)
        .map_err(|e| AfterburnerError::Engine(format!("read {}: {e}", rt.wasm_path.display())))?;

    let vm = EmbedderVm::new()?;
    let module = vm.compile(&wasm_bytes, true, |_| Ok(()))?;

    // argv: `ruby -e <source>`. The first element is argv[0] (the program
    // name); `-e` takes the program text as the next argument.
    let mut opts = WasiCommandOpts::new().args(["ruby", "-e", ruby_source]);
    if let Some(usr) = &rt.usr_dir {
        opts = opts.preopen_ro(usr, GUEST_USR_MOUNT);
    }

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

    /// `resolve_ruby_runtime` is total: it returns `Ok` when the bundle was
    /// assembled (the normal build) or a `BURN_RUBY_RUNTIME` override is set,
    /// and an honest, actionable `Err` otherwise. Never panics.
    #[test]
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

    /// End-to-end: when the bundle is present, `ruby -e 'puts 1 + 1'` runs and
    /// prints `2`. Skips honestly (never fails) when no runtime was assembled
    /// in this build, so the suite stays green offline.
    #[test]
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
}
