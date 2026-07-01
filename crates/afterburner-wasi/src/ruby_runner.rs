// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use afterburner_core::{AfterburnerError, HostContext, OutputValue, Result, decode_output_value};

use crate::effect_wasi::wire_effect_wrapped_wasi;
use crate::effect_wasi_fs::wire_effect_wrapped_wasi_fs;
use crate::embedder_vm::{EmbedderVm, WasiCommandOpts};

/// Instruction budget for one `ruby -e` run. CRuby's WASI boot (interpreter
/// init + loading the prelude) is heavy: a measured cold boot of `puts 1 + 1`
/// consumes well under 4e12 instructions, so 8e12 leaves generous headroom for
/// real user code while still bounding a runaway loop (it surfaces as
/// `AfterburnerError::FuelExhausted` rather than hanging the thread).
///
/// vertexia: global fuel budget; a per-phase split (boot vs user code) would
/// let us bound user code tighter once we expose the boot cost separately.
/// The fuel budget for a Ruby run (boot + user code). Ruby's WASM port has
/// a substantial startup cost (VM init, require loading). 8 * 10^12 fuel
/// is the shared constant used by all Ruby run paths including the vfs-packed
/// wasm32-wasip1 path in `afterburner::cli::run`.
pub const RUBY_FUEL: u64 = 8_000_000_000_000;

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

/// Guest mount point for vendored gems (FORMAT_MINOR >= 3, section 13.3).
///
/// Each gem's extracted file tree is written under
/// `<host_vendor_dir>/<gem_name>-<version>/` and preopened read-only here.
/// A `-I` flag per gem's `lib/` subdirectory prepends it to `$LOAD_PATH`, so
/// `require 'sinatra'` resolves `lib/sinatra.rb` inside the vendored gem tree
/// without a gem toolchain and without network access. Mirrors the source-tree
/// `-I` mechanism already used at `GUEST_PKG_MOUNT`.
const GUEST_GEM_VENDOR_MOUNT: &str = "/pkg/vendor/gem";

/// Guest mount point for the R2/R3 return channel: a fresh host directory is
/// preopened read-write here for every run. The guest opts in to returning a
/// typed value by writing an `AFBF` frame to `<GUEST_AFB_MOUNT>/output.frame`
/// (Ruby: `File.binwrite`); the host reads and decodes it after `_start`
/// returns. Absent -> no return value. Distinct from the package mount so a
/// script's own files never collide with the return frame.
const GUEST_AFB_MOUNT: &str = "/.afb";

/// File name the guest writes its return frame to, under [`GUEST_AFB_MOUNT`].
const OUTPUT_FRAME_NAME: &str = "output.frame";

/// Guest mount point for a fresh read-write scratch directory, preopened for
/// every run and removed after it. Distinct from the package mount so guest
/// scratch files (`File.binwrite("/work/x.bin", ...)`) never collide with the
/// script's own tree, and it gives a host-backed capture run a writable host
/// root under a stable path.
const GUEST_WORK_MOUNT: &str = "/work";

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
    /// The typed return value the run surfaced via the `/.afb/output.frame`
    /// file-frame (R2/R3), or `OutputValue::Json(Value::Null)` when the script
    /// wrote no frame. See `run_ruby_pkg` for the read/decode path.
    pub output: OutputValue,
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
///   path under `GUEST_PKG_MOUNT`), and
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
    run_ruby_pkg(rt, pkg_dir, entry_rel, None, &[], None)
}

/// Like [`run_ruby_package_with`] but threads a recording / replaying host
/// ([`HostContext`]) into the run (R4). The effect-wrapped `clock_time_get` /
/// `random_get` shims consult it (record on the original run, replay a recorded
/// value on re-run), and the typed return frame is still read from
/// `/.afb/output.frame`. Pass `None` for a sealed run (identical to
/// [`run_ruby_package_with`]).
pub fn run_ruby_package_with_host(
    rt: &RubyRuntime,
    pkg_dir: &Path,
    entry_rel: &str,
    host: Option<Arc<dyn HostContext>>,
) -> Result<RubyRunOutput> {
    run_ruby_pkg(rt, pkg_dir, entry_rel, None, &[], host)
}

/// The one canonical Ruby package run path (DRY): boot CRuby with the
/// effect-wrapped preview1 imports (R1), preopen the stdlib, the package
/// source, any vendored gem tree, and a fresh `/.afb` return dir (R2/R3), run
/// the entry, then read and decode the return frame.
///
/// `gem_host_dir` / `gem_lib_guest_dirs` carry the vendored-gem tree and its
/// `$LOAD_PATH` roots (both empty for a package with no `[gem]` deps). `host`
/// carries the optional record/replay seam (R4).
fn run_ruby_pkg(
    rt: &RubyRuntime,
    pkg_dir: &Path,
    entry_rel: &str,
    gem_host_dir: Option<&Path>,
    gem_lib_guest_dirs: &[String],
    host: Option<Arc<dyn HostContext>>,
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
    // R1 / increment 2: pick the preview1 wiring by host presence.
    //   * host = None  -> sealed run: the clock/random-only shadows over stock
    //     wasmtime-wasi fs. Byte-identical to before (the fs is never shadowed).
    //   * host = Some  -> capture run: the full fs-shadow variant that owns the
    //     fd table over Ruby's real preopens, so File I/O is captured as Fs
    //     effects. `run_command_impl` seeds the host-backed table from the opts
    //     preopens below.
    // Two distinct `fn` items, so the compile call itself is branched.
    let module = if host.is_some() {
        vm.compile(&wasm_bytes, true, wire_effect_wrapped_wasi_fs)?
    } else {
        vm.compile(&wasm_bytes, true, wire_effect_wrapped_wasi)?
    };

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

    // argv: ruby [-I<gem_lib>...] -I<entry_dir> -I<pkg_root> <entry>
    // Gem lib dirs first so a vendored gem shadows nothing in the stdlib.
    let mut args: Vec<String> = vec!["ruby".to_owned()];
    for g in gem_lib_guest_dirs {
        args.push(format!("-I{g}"));
    }
    args.push(i_entry_dir);
    args.push(i_root);
    args.push(guest_entry);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut opts = WasiCommandOpts::new().args(arg_refs);

    // Stdlib and vendored gems are read-only; the package source dir is rw so
    // Ruby scripts can write files under the preopened host path (File.write,
    // CSV output, a tempfile under the pkg tree).
    if let Some(usr) = &rt.usr_dir {
        opts = opts.preopen_ro(usr, GUEST_USR_MOUNT);
    }
    if let Some(gem_dir) = gem_host_dir {
        opts = opts.preopen_ro(gem_dir, GUEST_GEM_VENDOR_MOUNT);
    }
    opts = opts.preopen_rw(pkg_dir, GUEST_PKG_MOUNT);

    // A fresh read-write scratch dir preopened at guest `/work`, removed after
    // the run. Gives guest scratch writes a stable, isolated host-backed root.
    let work_dir = unique_tmp_dir("burn-rb-work");
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| AfterburnerError::Engine(format!("create {}: {e}", work_dir.display())))?;
    opts = opts.preopen_rw(&work_dir, GUEST_WORK_MOUNT);

    // R2/R3: a fresh host dir preopened rw at guest `/.afb`. The guest may write
    // its typed return value there as an AFBF frame; the host reads it back.
    // Added last so `/.afb` is the final preopen (highest fd) - the fd order is
    // irrelevant to correctness but keeps the return channel out of the way of
    // the user-visible mounts.
    let afb_dir = unique_tmp_dir("burn-rb-afb");
    std::fs::create_dir_all(&afb_dir)
        .map_err(|e| AfterburnerError::Engine(format!("create {}: {e}", afb_dir.display())))?;
    opts = opts.preopen_rw(&afb_dir, GUEST_AFB_MOUNT);

    let run_res = vm.run_command_with_host(&module, opts, Some(RUBY_FUEL), host);
    // Read the return frame regardless of the run outcome, then clean the dirs.
    let frame_res = read_output_frame(&afb_dir);
    let _ = std::fs::remove_dir_all(&afb_dir);
    let _ = std::fs::remove_dir_all(&work_dir);

    // A run failure (fuel/trap) takes precedence over a frame-decode failure.
    let out = run_res?;
    let output = frame_res?;
    Ok(RubyRunOutput {
        stdout: out.stdout,
        stderr: out.stderr,
        exit_code: out.result as i32,
        output,
    })
}

/// Read and decode the R2/R3 return frame from a run's `/.afb` host dir.
///
/// Absent frame -> `OutputValue::Json(Value::Null)` (the guest returned
/// nothing). A present-but-malformed frame is a **loud** error
/// ([`decode_output_value`] is total), never a silent `Null`.
fn read_output_frame(afb_dir: &Path) -> Result<OutputValue> {
    let frame_path = afb_dir.join(OUTPUT_FRAME_NAME);
    match std::fs::read(&frame_path) {
        Ok(bytes) => decode_output_value(&bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(OutputValue::Json(serde_json::Value::Null))
        }
        Err(e) => Err(AfterburnerError::Engine(format!(
            "read {}: {e}",
            frame_path.display()
        ))),
    }
}

/// Write the `vendor/gem/**` subset of an `.afb`'s `vendor` map into `dest_dir`
/// and collect the unique gem `lib/` subdirectories that exist within.
///
/// Keys are expected to be of the form `"vendor/gem/<name>-<version>/<rel>"`.
/// The strip of `"vendor/gem/"` gives `"<name>-<version>/<rel>"`, which is
/// written verbatim under `dest_dir`. For each `<name>-<version>` that has at
/// least one file under `<name>-<version>/lib/`, the function records
/// `<name>-<version>/lib` as a `lib/` root to put on `$LOAD_PATH` via `-I`.
///
/// Returns the sorted list of guest lib-dir strings (e.g.
/// `"/pkg/vendor/gem/sinatra-3.1.0/lib"`).
fn write_vendor_gems(vendor: &BTreeMap<String, Vec<u8>>, dest_dir: &Path) -> Result<Vec<String>> {
    const PREFIX: &str = "vendor/gem/";
    let mut lib_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for (archive_key, data) in vendor {
        let Some(rel) = archive_key.strip_prefix(PREFIX) else {
            continue;
        };
        // rel is "<name>-<version>/<file_path>".
        let dest = dest_dir.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AfterburnerError::Engine(format!("vendor gem: create {}: {e}", parent.display()))
            })?;
        }
        std::fs::write(&dest, data).map_err(|e| {
            AfterburnerError::Engine(format!("vendor gem: write {}: {e}", dest.display()))
        })?;

        // If this file lives under `<gem_dir>/lib/`, record the lib root.
        // The gem_dir is everything up to (and including) the first `/`.
        if let Some(slash) = rel.find('/') {
            let gem_dir = &rel[..slash];
            let rest = &rel[slash + 1..];
            if rest.starts_with("lib/") || rest == "lib" {
                lib_dirs.insert(format!("{GUEST_GEM_VENDOR_MOUNT}/{gem_dir}/lib"));
            }
        }
    }

    Ok(lib_dirs.into_iter().collect())
}

/// Boot a resolved [`RubyRuntime`] and run a Ruby package rooted at `pkg_dir`
/// with entry `entry_rel`, mounting vendored gems from the `.afb`'s `vendor`
/// map.
///
/// Vendored gems (keys under `"vendor/gem/**"` in `vendor`) are extracted to a
/// temp subdirectory alongside `pkg_dir`, preopened read-only at
/// `GUEST_GEM_VENDOR_MOUNT`, and each gem's `lib/` root is prepended to
/// `$LOAD_PATH` via a `-I` flag - so `require 'sinatra'` (for example) resolves
/// offline with no gem toolchain and no network. Everything the interpreter
/// imports is already in the preopened host directories before user code runs.
///
/// When `vendor` contains no `"vendor/gem/**"` entries (the common case for
/// packages with no `[gem]` dependencies), this is identical to
/// [`run_ruby_package_with`].
///
/// The temp dir that holds the extracted gem tree is cleaned up after the run,
/// whether it succeeds or fails.
pub fn run_ruby_afb_with(
    rt: &RubyRuntime,
    pkg_dir: &Path,
    entry_rel: &str,
    vendor: &BTreeMap<String, Vec<u8>>,
) -> Result<RubyRunOutput> {
    // Fast path: no vendored gems - delegate directly.
    let has_gems = vendor.keys().any(|k| k.starts_with("vendor/gem/"));
    if !has_gems {
        return run_ruby_package_with(rt, pkg_dir, entry_rel);
    }

    let gem_tmp = unique_tmp_dir("burn-rb-vendor-gem");
    let write_result = write_vendor_gems(vendor, &gem_tmp);
    let lib_dirs = match write_result {
        Ok(dirs) => dirs,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&gem_tmp);
            return Err(e);
        }
    };

    let run_result = run_ruby_package_with_gem_dirs(rt, pkg_dir, entry_rel, &gem_tmp, &lib_dirs);
    let _ = std::fs::remove_dir_all(&gem_tmp);
    run_result
}

/// Inner: run a Ruby package with an already-materialized gem vendor dir and
/// the guest lib-dir list. Called from [`run_ruby_afb_with`] after writing the
/// gem tree to `gem_host_dir`.
fn run_ruby_package_with_gem_dirs(
    rt: &RubyRuntime,
    pkg_dir: &Path,
    entry_rel: &str,
    gem_host_dir: &Path,
    gem_lib_guest_dirs: &[String],
) -> Result<RubyRunOutput> {
    run_ruby_pkg(
        rt,
        pkg_dir,
        entry_rel,
        Some(gem_host_dir),
        gem_lib_guest_dirs,
        None,
    )
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

    /// The `pkg_dir` preopen is read-write: a Ruby script can write files under
    /// `/pkg` and they appear on the host `pkg_dir`. Verifies 5x that the write
    /// persists across runs when the same `pkg_dir` is reused.
    ///
    /// `#[ignore]`: fetches/uses the real `~/.burn` Ruby runtime; run explicitly.
    #[test]
    #[ignore = "fetches/uses the real ~/.burn Ruby runtime; run explicitly"]
    fn pkg_dir_is_rw_preopen() {
        let rt = match resolve_ruby_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!("skip: no ruby runtime assembled in this build");
                return;
            }
        };

        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path();

        std::fs::write(
            pkg.join("main.rb"),
            "out = File.join(File.dirname(__FILE__), 'out.txt')\n\
             File.write(out, \"persisted\")\n\
             puts \"wrote\"\n",
        )
        .unwrap();

        for i in 1u8..=5 {
            let out = run_ruby_package_with(&rt, pkg, "main.rb").expect("run_ruby_package_with");
            let text = String::from_utf8_lossy(&out.stdout);
            let err = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                out.exit_code, 0,
                "run {i}: must exit 0; stdout={text:?} stderr={err:?}"
            );
            let host_file = pkg.join("out.txt");
            assert!(
                host_file.exists(),
                "run {i}: host file must exist after rw write"
            );
            assert_eq!(
                std::fs::read_to_string(&host_file).unwrap(),
                "persisted",
                "run {i}: host file content must match"
            );
        }
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

    /// `write_vendor_gems`: an empty vendor map produces an empty lib-dir list.
    #[test]
    fn write_vendor_gems_empty_vendor() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = write_vendor_gems(&BTreeMap::new(), tmp.path()).expect("no error on empty map");
        assert!(dirs.is_empty());
    }

    /// `write_vendor_gems`: keys not under `"vendor/gem/"` are ignored.
    #[test]
    fn write_vendor_gems_skips_non_gem_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vendor = BTreeMap::new();
        vendor.insert(
            "vendor/pip/requests-2.31.0-py3-none-any.whl".to_owned(),
            b"data".to_vec(),
        );
        vendor.insert("source/main.rb".to_owned(), b"puts 1".to_vec());
        let dirs = write_vendor_gems(&vendor, tmp.path()).expect("no error when only non-gem keys");
        assert!(
            dirs.is_empty(),
            "non-gem keys must not produce lib dirs: {dirs:?}"
        );
    }

    /// `write_vendor_gems`: files under `<gem_dir>/lib/` produce a guest lib-dir
    /// entry, while files outside `lib/` do not.
    #[test]
    fn write_vendor_gems_detects_lib_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let mut vendor = BTreeMap::new();
        vendor.insert(
            "vendor/gem/color-1.0.0/lib/color.rb".to_owned(),
            b"module Color; end".to_vec(),
        );
        vendor.insert(
            "vendor/gem/color-1.0.0/README.md".to_owned(),
            b"# Color".to_vec(),
        );
        vendor.insert(
            "vendor/gem/widget-2.1.3/lib/widget.rb".to_owned(),
            b"module Widget; end".to_vec(),
        );
        let dirs = write_vendor_gems(&vendor, tmp.path()).expect("write succeeds");
        assert_eq!(dirs.len(), 2, "two gems with lib/: {dirs:?}");
        assert!(
            dirs.iter().any(|d| d.ends_with("color-1.0.0/lib")),
            "color lib present: {dirs:?}"
        );
        assert!(
            dirs.iter().any(|d| d.ends_with("widget-2.1.3/lib")),
            "widget lib present: {dirs:?}"
        );
        // Files are written to disk.
        assert!(tmp.path().join("color-1.0.0/lib/color.rb").exists());
        assert!(tmp.path().join("color-1.0.0/README.md").exists());
        assert!(tmp.path().join("widget-2.1.3/lib/widget.rb").exists());
    }

    /// `run_ruby_afb_with` on a missing package directory is an honest `Err`,
    /// not a panic, even when the vendor map has gem entries.
    #[test]
    fn run_ruby_afb_with_missing_dir_errors() {
        let rt = RubyRuntime {
            wasm_path: PathBuf::from("/nonexistent/ruby.wasm"),
            usr_dir: None,
        };
        let mut vendor = BTreeMap::new();
        vendor.insert(
            "vendor/gem/fake-1.0.0/lib/fake.rb".to_owned(),
            b"module Fake; end".to_vec(),
        );
        let err = run_ruby_afb_with(&rt, Path::new("/no/such/pkg/dir"), "main.rb", &vendor)
            .expect_err("missing dir must error");
        assert!(
            err.to_string().contains("does not exist"),
            "error must name the missing dir: {err}"
        );
    }

    /// End-to-end offline gem vendor: a Ruby `.afb` package (source tree in a
    /// temp dir) with a pre-vendored pure-Ruby gem runs offline, `require`s the
    /// gem, and prints the expected output.
    ///
    /// `#[ignore]`: fetches/uses the real `~/.burn` Ruby runtime; run explicitly.
    /// This is the PD integration test: vendored gems mount before user code.
    #[test]
    #[ignore = "fetches/uses the real ~/.burn Ruby runtime; run explicitly"]
    fn run_ruby_afb_with_vendored_gem_offline() {
        let rt = match resolve_ruby_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!("skip: no ruby runtime assembled in this build");
                return;
            }
        };

        // Build a minimal in-memory vendor map: a pure-Ruby gem named `greet`
        // at version 0.1.0 whose single lib file exports `Greet.hello`.
        let mut vendor: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        vendor.insert(
            "vendor/gem/greet-0.1.0/lib/greet.rb".to_owned(),
            b"module Greet\n  def self.hello(name); \"hello #{name}\"; end\nend\n".to_vec(),
        );

        // Write the package source (one file that requires the vendored gem).
        let root = std::env::temp_dir().join(format!(
            "burn-rb-vendor-e2e-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create pkg root");
        std::fs::write(
            root.join("main.rb"),
            "require 'greet'\nputs Greet.hello('world')\n",
        )
        .expect("write main.rb");

        let out = run_ruby_afb_with(&rt, &root, "main.rb", &vendor)
            .expect("run_ruby_afb_with must succeed");
        let _ = std::fs::remove_dir_all(&root);

        let text = String::from_utf8_lossy(&out.stdout);
        let err_text = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.exit_code, 0,
            "clean exit; stdout={text:?} stderr={err_text:?}"
        );
        assert!(
            text.contains("hello world"),
            "vendored gem must be require-able offline; got stdout={text:?} stderr={err_text:?}"
        );
    }

    /// R2/R3: an absent return frame decodes to `Json(Null)` (no value
    /// surfaced) - never an error.
    #[test]
    fn read_output_frame_absent_is_null() {
        let tmp = tempfile::tempdir().unwrap();
        let out = read_output_frame(tmp.path()).expect("absent -> Ok(Null)");
        assert_eq!(out, OutputValue::Json(serde_json::Value::Null));
    }

    /// R2/R3: a present frame decodes to its typed value, byte-exact (a binary
    /// payload with NULs and invalid UTF-8 round-trips).
    #[test]
    fn read_output_frame_present_decodes_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let payload = vec![0u8, 255, 10, 195, 40];
        let frame =
            afterburner_core::encode_output_value(&OutputValue::Bytes(payload.clone())).unwrap();
        std::fs::write(tmp.path().join(OUTPUT_FRAME_NAME), &frame).unwrap();
        let out = read_output_frame(tmp.path()).expect("decode");
        assert_eq!(out, OutputValue::Bytes(payload));
    }

    /// R2/R3 honesty fence: a present-but-malformed frame is a loud error, never
    /// a silent `Null`.
    #[test]
    fn read_output_frame_corrupt_is_loud() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(OUTPUT_FRAME_NAME),
            b"not a valid AFBF frame",
        )
        .unwrap();
        assert!(
            read_output_frame(tmp.path()).is_err(),
            "a corrupt frame must be a loud error, not a silent Null"
        );
    }

    /// End-to-end (R1 + R2/R3 + R4 host): a real CRuby run writes and reads back
    /// a binary file inside the guest (a mismatch would `raise` -> non-zero
    /// exit), then returns a typed value via the `/.afb/output.frame`
    /// file-frame, threaded through a recording host.
    ///
    /// `#[ignore]`: uses the real `~/.burn` Ruby runtime; run explicitly. Ruby
    /// has no stdlib BLAKE3, so the guest writes a frame precomputed host-side -
    /// this still exercises the full guest -> host return channel and decode.
    #[test]
    #[ignore = "uses the real ~/.burn Ruby runtime; run explicitly"]
    fn ruby_roundtrip_binary_file_and_frame_return() {
        let rt = match resolve_ruby_runtime() {
            Ok(rt) => rt,
            Err(_) => {
                eprintln!("skip: no ruby runtime assembled in this build");
                return;
            }
        };

        let payload = vec![0u8, 255, 10, 195, 40, 7, 128];
        let frame =
            afterburner_core::encode_output_value(&OutputValue::Bytes(payload.clone())).unwrap();
        let data_lit = payload
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let frame_lit = frame
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let script = format!(
            "data = [{data_lit}].pack('C*')\n\
             File.binwrite('/pkg/data.bin', data)\n\
             raise 'binary roundtrip mismatch' unless File.binread('/pkg/data.bin') == data\n\
             frame = [{frame_lit}].pack('C*')\n\
             File.binwrite('/.afb/output.frame', frame)\n\
             puts 'ok'\n"
        );

        let pkg = tempfile::tempdir().unwrap();
        std::fs::write(pkg.path().join("main.rb"), &script).unwrap();

        #[derive(Default)]
        struct Rec {
            log: std::sync::Mutex<Vec<afterburner_core::HostEffectRecord>>,
        }
        impl HostContext for Rec {
            fn record_host_effect(&self, r: afterburner_core::HostEffectRecord) {
                self.log.lock().unwrap().push(r);
            }
            fn get_effect_log(&self) -> Vec<afterburner_core::HostEffectRecord> {
                self.log.lock().unwrap().clone()
            }
        }
        let host: Arc<dyn HostContext> = Arc::new(Rec::default());

        let out = run_ruby_package_with_host(&rt, pkg.path(), "main.rb", Some(host.clone()))
            .expect("run_ruby_package_with_host");

        let text = String::from_utf8_lossy(&out.stdout);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.exit_code, 0,
            "clean exit; stdout={text:?} stderr={err:?}"
        );
        assert!(
            text.contains("ok"),
            "script ran; stdout={text:?} stderr={err:?}"
        );
        assert_eq!(
            out.output,
            OutputValue::Bytes(payload),
            "typed value returned via the /.afb file-frame"
        );
        eprintln!(
            "captured {} host effect(s) during the run",
            host.get_effect_log().len()
        );
    }
}
