// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Run one `.afb` to completion as a bounded, captured one-shot.
//!
//! `cli::run::run_package_or_file` (only compiled with the `bin` feature,
//! hence plain text rather than a doc link here) is the CLI's
//! entry point: it takes a `&Cli`, writes to the process's real stdout, and
//! calls `std::process::exit` on a non-zero guest exit. None of that is
//! usable from inside a host process that embeds Afterburner (gents' pack-tool
//! executor is the motivating case): a library caller needs to hand over
//! bytes, get bytes back, and be told *which* bound was hit, without its own
//! stdout getting the guest's output spliced into it and without its own
//! process getting killed by a guest that happened to exit non-zero.
//! [`run_afb_bytes`] is that entry point.
//!
//! ## Why this crate, and why not `cli`
//!
//! `crate::cli` (the `burn` binary's own code) is gated behind the `bin`
//! feature, which also pulls in `clap`, `rustyline`, `tokio`, `crossterm`,
//! `dialoguer`, and `afterburner-cloud` (the registry client) - CLI-only
//! weight no embedder wants. This module lives in `afterburner`'s lib gated
//! behind its own `afb-run` feature instead, because running a `.afb` needs
//! both halves of the runtime this crate already re-exports:
//! [`afterburner_wasi::embedder_vm`] for the compiled-WASM languages, and
//! [`afterburner_wasi::pyodide_runner`] / [`afterburner_wasi::ruby_runner`]
//! for the two interpreted ones. `afterburner-wasi` was already an optional
//! dependency behind `wasm`; the only new dependency `afb-run` adds is
//! `afterburner-afb`, the lean `.afb` pack/unpack crate `afterburner-cloud`
//! itself just re-exports (see its `pub use afterburner_afb::{self, Afb, ...}`),
//! with no registry client, no network, and no `anyhow`. Precedent for "a
//! feature for embedders that skips the CLI deps" already exists in this
//! crate's `daemon` feature; `afb-run` follows the same shape.
//!
//! ## Dispatch
//!
//! [`run_afb_bytes`] dispatches on the package's declared language exactly
//! the way `run_afb` in `cli::run` does:
//!
//! - Rust, Go, C, C++, JS, TS: `precompiled/wasm32-wasip1/main.wasm` is
//!   extracted and run as a WASI command via
//!   [`EmbedderVm::run_command_bounded`][afterburner_wasi::embedder_vm::EmbedderVm::run_command_bounded]
//!   with `stdin`, `fuel`, `memory_bytes`, and the manifold's `fs`/`env`
//!   grants fully wired through.
//! - Ruby, compiled (`[runtime] target = "wasm32-wasip1"`, produced by
//!   `burn compile` via wasi-vfs): the same WASI-command path as above, with
//!   the guest script path convention `cli::compile::ruby_wasm` documents.
//! - Ruby, source (no precompiled member): the bundled CRuby interpreter via
//!   [`afterburner_wasi::ruby_runner::run_ruby_afb_with`], the exact function
//!   `cli::run::run_ruby_afb` calls - no second way to run Ruby source was
//!   invented here.
//! - Python, source: the bundled CPython/Pyodide interpreter via
//!   [`afterburner_wasi::pyodide_runner::run_pyodide_package_with`], the same
//!   function `cli::run::run_python_afb` calls.
//! - Python, compiled (`[runtime] target = "emscripten-pyodide"`, a
//!   self-contained bundle): only reachable with the `bin` feature also
//!   enabled, since reconstructing the bundled Pyodide runtime from an `.afb`
//!   (`cli::compile::python_wasm::reconstruct_runtime_from_afb`) lives behind
//!   that feature gate and reimplementing it here would be exactly the
//!   "invent a second way" this module is supposed to avoid. Without `bin`,
//!   this one case returns a clear, actionable error instead of a silent
//!   failure - every other language and package shape is unaffected.
//!
//! ## Known gaps (honest, not hidden)
//!
//! `AfbRunRequest`'s bounds are fully enforced for the compiled-WASM and
//! compiled-Ruby families (every field: `stdin`, `fuel`, `memory_bytes`, the
//! manifold's `fs`/`env`). For Ruby-source and Python-source they are not:
//!
//! - `stdin` is never delivered to the guest (neither runner exposes a stdin
//!   hook).
//! - `memory_bytes` is never enforced (neither runner wires a
//!   `wasmtime::ResourceLimiter`).
//! - `fuel` cannot be tightened below each runner's fixed internal budget
//!   (`RUBY_FUEL`, `PYODIDE_FUEL`) - the request's fuel is a ceiling that
//!   cannot be lowered for these two families today, only ignored, which
//!   technically widens it for a caller asking for less. This is the sharpest
//!   of the gaps and is called out again on [`AfbRunRequest::fuel`].
//! - the manifold's extra `fs`/`env` grants are not threaded through (both
//!   runners already preopen exactly the package's own source tree plus a
//!   scratch dir, unconditionally, matching how the existing
//!   `cli::run::run_ruby_afb` / `run_python_afb` behave today).
//! - Ruby-source *does* get typed bound classification (`OutOfFuel` /
//!   `Timeout`) because `ruby_runner` already routes through
//!   `EmbedderVm::run_command_with_host`, which classifies traps before this
//!   module ever sees them. Python-source does not: `pyodide_runner`'s own
//!   trap handling stringifies the error before it escapes, so a Python run
//!   that hits `PYODIDE_FUEL` or traps for any other reason always comes back
//!   as [`AfbRunOutcome::Trapped`], never `OutOfFuel`.
//!
//! Closing these needs additive parameters on `ruby_runner`'s and
//! `pyodide_runner`'s package runners (a fuel/stdin/memory-cap override) and,
//! for Python, preserving the trap classification before it is turned into a
//! string - real, scoped follow-up work, not a design limitation of this API.
//!
//! `vertexia:` the two gaps above (fuel ceiling not honored, Python outcome
//! collapsing to `Trapped`) are deliberate scope cuts for this change, not
//! silently dropped work; upgrade path is threading the same bound
//! parameters `EmbedderVm::run_command_bounded` already takes into
//! `ruby_runner::run_ruby_pkg` and `pyodide_runner::run_pyodide_core`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use afterburner_afb::Afb;
use afterburner_core::{AfterburnerError, EnvAccess, FsAccess, Manifold, Result};
use afterburner_wasi::embedder_vm::{
    BoundedCommandOutput, CommandOutcome, EmbedderVm, WasiCommandOpts,
};

/// The wire-format runtime-target string for a self-contained compiled
/// Python `.afb` (mirrors `cli::compile::python_wasm::RUNTIME_TARGET`,
/// duplicated as a stable format constant since that module is behind the
/// `bin` feature).
const PYTHON_WASM_RUNTIME_TARGET: &str = "emscripten-pyodide";

/// The wire-format runtime-target string for a compiled (wasi-vfs-packed)
/// Ruby `.afb`, and the archive path of a precompiled WASI command module -
/// both mirror `cli::run`'s own dispatch constants.
const RUBY_WASM_RUNTIME_TARGET: &str = "wasm32-wasip1";
const PRECOMPILED_WASM_MEMBER: &str = "precompiled/wasm32-wasip1/main.wasm";

/// Monotonic counter for scratch-directory names, so concurrent
/// `run_afb_bytes` calls (from multiple threads in the same embedding
/// process) never collide on a shared temp path. Pid alone (what
/// `cli::run`'s single-process CLI callers rely on) is not enough here: a
/// library embedder is expected to call this function from more than one
/// thread in the same process.
static NEXT_SCRATCH_ID: AtomicU64 = AtomicU64::new(0);

fn unique_scratch_dir(prefix: &str) -> std::path::PathBuf {
    let n = NEXT_SCRATCH_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// What one run may spend and reach.
///
/// The zero value (`stdin` empty, `args` empty, `manifold` sealed, every
/// bound `None`) is the sealed, unbounded-fuel-default posture: no
/// capability, no caller-imposed cap beyond the engine's own default fuel
/// budget.
#[derive(Debug, Clone, Default)]
pub struct AfbRunRequest {
    /// Bytes delivered to the guest on stdin (fd 0). Always wired as an open
    /// pipe (even when empty, which reads as immediate EOF, not a closed
    /// fd) - see [`WasiCommandOpts::stdin`][afterburner_wasi::embedder_vm::WasiCommandOpts::stdin].
    /// Not delivered to a Ruby- or Python-source guest; see the module doc's
    /// "known gaps".
    pub stdin: Vec<u8>,
    /// Extra argv entries appended after the synthetic program name
    /// (the package's `namespace/name`). Not honored by the Ruby- or
    /// Python-source runners (neither takes an argv).
    pub args: Vec<String>,
    /// The capability ceiling for this run. Only the `fs` and `env` axes
    /// have an effect on a WASI command guest (compiled languages, compiled
    /// Ruby) - `net`, `crypto`, `child_process`, and `listen` have no WASI
    /// preview-1 equivalent (see the module doc). Never widened beyond what
    /// is passed here.
    pub manifold: Manifold,
    /// Instruction budget. `None` uses the engine's own default for the
    /// compiled-WASM and compiled-Ruby families. For Ruby-source and
    /// Python-source, this can only ever come out *smaller than or equal to*
    /// each runner's fixed internal budget today (see the module doc's
    /// "known gaps") - it is read as an informational hint there, not
    /// enforced as a ceiling, because neither runner exposes an override.
    pub fuel: Option<u64>,
    /// Linear-memory cap in bytes for a WASI command guest (compiled
    /// languages, compiled Ruby only - see the module doc). `None` applies
    /// no cap.
    pub memory_bytes: Option<u64>,
    /// Wall-clock deadline for the whole run. When set, the run is executed
    /// on a dedicated thread and this call returns
    /// [`AfbRunOutcome::Timeout`] if the deadline elapses first.
    ///
    /// `vertexia:` this is a host-side deadline, not a guest-preemption one:
    /// `EmbedderVm`'s engine intentionally runs without wasmtime epoch
    /// interruption (see `deterministic_engine`'s own doc comment - fuel is
    /// the deterministic budget, epoch ticking is not), so a timed-out run
    /// is not killed, only abandoned - it keeps running on its own thread,
    /// bounded by its own fuel budget, and its eventual result is discarded.
    /// Upgrade path: a dedicated `Engine` with epoch interruption enabled,
    /// driven by a ticker thread, for a caller that needs true preemption
    /// rather than "stop waiting for it".
    pub timeout: Option<Duration>,
}

/// What bound, if any, ended the run.
///
/// Every case is a distinct outcome, not a generic failure: a caller can
/// tell "the guest ran out of fuel" from "the guest exited non-zero" from
/// "the guest hit the memory ceiling" without parsing a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfbRunOutcome {
    /// The guest ran to completion (including a non-zero exit - that is
    /// still the guest's own outcome, not a bound).
    Exited(i32),
    /// The fuel budget was exhausted.
    OutOfFuel,
    /// `memory_bytes` was set and the guest hit it (a `memory.grow` was
    /// denied during the run - see
    /// [`TrackedLimits`][afterburner_wasi::embedder_vm::TrackedLimits]).
    OutOfMemory,
    /// `timeout` elapsed before the run finished.
    Timeout,
    /// The guest trapped for a reason that is not one of the bounds above
    /// (division by zero, unreachable, an indirect-call-signature mismatch,
    /// a Ruby/Python interpreter crash, ...).
    ///
    /// This variant is not in the task's original three-bound shorthand; it
    /// is added because collapsing an arbitrary trap into `Exited` would
    /// require fabricating an exit code a trap never produced (WASI traps
    /// carry no process exit code), which the honesty fence this codebase
    /// runs under forbids outright.
    Trapped(String),
}

/// What came back from one [`run_afb_bytes`] call.
#[derive(Debug, Clone)]
pub struct AfbRunOutput {
    pub outcome: AfbRunOutcome,
    /// Bytes the guest wrote to stdout. Empty (not fabricated - genuinely not
    /// captured) when `outcome` is `OutOfFuel`, `Timeout`, or `Trapped` for a
    /// Ruby- or Python-source run; always populated for the compiled-WASM
    /// and compiled-Ruby families regardless of outcome.
    pub stdout: Vec<u8>,
    /// Bytes the guest wrote to stderr. Same capture caveat as `stdout`.
    pub stderr: Vec<u8>,
    /// Fuel actually consumed. Exact for the compiled-WASM and
    /// compiled-Ruby families on every outcome, and for Ruby-source /
    /// Python-source on a clean exit. On `OutOfFuel` for Ruby-source this is
    /// the fixed `RUBY_FUEL` budget (exhaustion means the whole budget was
    /// spent, so this is exact, not a placeholder). `0` when genuinely not
    /// measured (a Python-source `Trapped` outcome, or a `Timeout` - the run
    /// that owns the number is still running in the background).
    pub fuel_used: u64,
}

/// Runs one `.afb` to completion and captures what it wrote.
///
/// Nothing is written to the calling process's real stdout or stderr, and
/// this never calls `std::process::exit` - a non-zero or trapping guest is
/// reported back in `AfbRunOutput`, never propagated to the host process.
pub fn run_afb_bytes(afb: &[u8], request: AfbRunRequest) -> Result<AfbRunOutput> {
    let parsed =
        Afb::from_bytes(afb).map_err(|e| AfterburnerError::Engine(format!("parsing .afb: {e}")))?;

    match request.timeout {
        Some(timeout) => run_with_timeout(timeout, parsed, request),
        None => dispatch(&parsed, request),
    }
}

/// Run `dispatch` on a dedicated thread and wait at most `timeout` for it.
/// See [`AfbRunRequest::timeout`]'s doc for exactly what "wait at most"
/// means here (a deadline on the caller's patience, not a kill switch).
fn run_with_timeout(timeout: Duration, afb: Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("afb-run-bounded".into())
        .spawn(move || {
            let outcome = dispatch(&afb, request);
            let _ = tx.send(outcome);
        })
        .map_err(|e| AfterburnerError::Engine(format!("spawning bounded run thread: {e}")))?;

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Timeout,
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: 0,
        }),
        // The spawned thread panicked without sending - surface as a
        // trapped outcome rather than a swallowed error.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Trapped("bounded run thread ended without a result".into()),
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: 0,
        }),
    }
}

/// Language dispatch, mirroring `cli::run::run_afb` exactly.
fn dispatch(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    let runtime_target = afb.manifest.runtime.target.as_deref().unwrap_or("");
    if runtime_target == PYTHON_WASM_RUNTIME_TARGET {
        return run_python_wasm(afb, request);
    }

    match afb.manifest.package.language.to_ascii_lowercase().as_str() {
        "python" | "py" => run_python_source(afb, request),
        "ruby" | "rb" if runtime_target == RUBY_WASM_RUNTIME_TARGET => run_ruby_wasm(afb, request),
        "ruby" | "rb" => run_ruby_source(afb, request),
        _ => run_wasm(afb, request),
    }
}

/// Apply the manifold's `fs` and `env` grants to `opts`. `net`, `crypto`,
/// `child_process`, and `listen` have no effect: WASI preview-1 (what
/// `WasiCommandOpts` wires) has no network syscalls, matching
/// `cli::run::wasi_opts_from_cli`'s own documented limitation.
///
/// `vertexia:` wasi-sockets (preview-2) would be needed to honor
/// `Manifold::net` for a WASI command guest; not wired anywhere in the
/// embedder today, CLI path included.
fn manifold_to_wasi_opts(manifold: &Manifold, mut opts: WasiCommandOpts) -> WasiCommandOpts {
    match &manifold.fs {
        FsAccess::None => {}
        FsAccess::ReadOnly(paths) => {
            for p in paths {
                let guest = p.to_string_lossy().into_owned();
                opts = opts.preopen_ro(p, guest);
            }
        }
        FsAccess::ReadWrite(paths) => {
            for p in paths {
                let guest = p.to_string_lossy().into_owned();
                opts = opts.preopen_rw(p, guest);
            }
        }
    }

    match &manifold.env {
        EnvAccess::None => {}
        EnvAccess::AllowList(keys) => {
            for key in keys {
                if let Ok(val) = std::env::var(key) {
                    opts = opts.env_var(key.clone(), val);
                }
            }
        }
        EnvAccess::Full => {
            for (key, val) in std::env::vars() {
                opts = opts.env_var(key, val);
            }
        }
    }

    opts
}

/// Classify a [`BoundedCommandOutput`] into an [`AfbRunOutput`].
/// `memory_limit_hit` takes precedence over the raw `outcome`: the caller
/// asked for a memory ceiling, and it firing is the more actionable fact
/// even when the guest went on to exit cleanly or hit fuel exhaustion too.
fn finish(raw: BoundedCommandOutput) -> AfbRunOutput {
    let outcome = if raw.memory_limit_hit {
        AfbRunOutcome::OutOfMemory
    } else {
        match raw.outcome {
            CommandOutcome::Exited(code) => AfbRunOutcome::Exited(code),
            CommandOutcome::OutOfFuel => AfbRunOutcome::OutOfFuel,
            CommandOutcome::Timeout => AfbRunOutcome::Timeout,
            CommandOutcome::Trapped(msg) => AfbRunOutcome::Trapped(msg),
        }
    };
    AfbRunOutput {
        outcome,
        stdout: raw.stdout,
        stderr: raw.stderr,
        fuel_used: raw.fuel_consumed,
    }
}

/// Rust, Go, C, C++, JS, TS (and compiled Ruby via [`run_ruby_wasm`]):
/// extract `precompiled/wasm32-wasip1/main.wasm` and run it as a WASI
/// command, with every request bound wired through.
fn run_wasm(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    let AfbRunRequest {
        stdin,
        args,
        manifold,
        fuel,
        memory_bytes,
        timeout: _,
    } = request;

    let wasm_bytes = afb.precompiled.get(PRECOMPILED_WASM_MEMBER).ok_or_else(|| {
        AfterburnerError::Engine(format!(
            "{} has no {PRECOMPILED_WASM_MEMBER}; run `burn compile` to produce a native WASM package",
            afb.qualified_name(),
        ))
    })?;

    let vm = EmbedderVm::new()?;
    let module = vm.compile(wasm_bytes, true, |_| Ok(()))?;

    let mut argv = vec![afb.qualified_name()];
    argv.extend(args);
    let mut opts = WasiCommandOpts::new().args(argv).stdin(stdin);
    if let Some(bytes) = memory_bytes {
        opts = opts.max_memory_bytes(bytes as usize);
    }
    opts = manifold_to_wasi_opts(&manifold, opts);

    let raw = vm.run_command_bounded(&module, opts, fuel, None)?;
    Ok(finish(raw))
}

/// Compiled Ruby (`[runtime] target = "wasm32-wasip1"`, produced by
/// `burn compile` via wasi-vfs): same WASI-command path as [`run_wasm`], with
/// the guest script path convention `cli::compile::ruby_wasm` documents
/// (`"/src/" + entry_rel`, duplicated here as a stable wire-format constant
/// since that module is behind the `bin` feature).
fn run_ruby_wasm(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    const GUEST_SRC_MOUNT: &str = "/src";

    let AfbRunRequest {
        stdin,
        args,
        manifold,
        fuel,
        memory_bytes,
        timeout: _,
    } = request;

    let wasm_bytes = afb.precompiled.get(PRECOMPILED_WASM_MEMBER).ok_or_else(|| {
        AfterburnerError::Engine(format!(
            "Ruby package {} has no {PRECOMPILED_WASM_MEMBER}; re-run `burn compile` to rebuild it",
            afb.qualified_name(),
        ))
    })?;

    let vm = EmbedderVm::new()?;
    let module = vm.compile(wasm_bytes, true, |_| Ok(()))?;

    let entry_rel = afb.manifest.package.entry.replace('\\', "/");
    let guest_script = format!("{GUEST_SRC_MOUNT}/{entry_rel}");
    let mut argv = vec![afb.qualified_name(), guest_script];
    argv.extend(args);
    let mut opts = WasiCommandOpts::new().args(argv).stdin(stdin);
    if let Some(bytes) = memory_bytes {
        opts = opts.max_memory_bytes(bytes as usize);
    }
    opts = manifold_to_wasi_opts(&manifold, opts);

    // Ruby's WASM port has a substantial startup cost; fall back to the same
    // fixed budget `cli::run::run_ruby_wasm_afb` uses when the caller does
    // not supply a tighter one.
    let fuel = fuel.or(Some(afterburner_wasi::ruby_runner::RUBY_FUEL));

    let raw = vm.run_command_bounded(&module, opts, fuel, None)?;
    Ok(finish(raw))
}

/// Ruby, source (no precompiled member): run on the bundled CRuby
/// interpreter via [`afterburner_wasi::ruby_runner::run_ruby_afb_with`], the
/// exact function `cli::run::run_ruby_afb` calls. See the module doc's
/// "known gaps" for what `request` cannot reach here.
fn run_ruby_source(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    use afterburner_wasi::ruby_runner::{RUBY_FUEL, resolve_ruby_runtime, run_ruby_afb_with};

    let entry_rel = &afb.manifest.package.entry;
    if !afb.source.contains_key(entry_rel) {
        return Err(AfterburnerError::Engine(format!(
            "package entry {entry_rel:?} (from afb.toml) is not present under source/ in {}",
            afb.qualified_name(),
        )));
    }

    let rt = resolve_ruby_runtime()?;

    let tmp_root = unique_scratch_dir("afb-run-rb-src");
    let _ = std::fs::remove_dir_all(&tmp_root);
    if let Err(e) = materialize_source(&tmp_root, &afb.source) {
        let _ = std::fs::remove_dir_all(&tmp_root);
        return Err(e);
    }

    let run_result = run_ruby_afb_with(&rt, &tmp_root, entry_rel, &afb.vendor);
    let _ = std::fs::remove_dir_all(&tmp_root);
    let _ = request; // stdin/fuel/memory_bytes/manifold: see module doc.

    match run_result {
        Ok(out) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Exited(out.exit_code),
            stdout: out.stdout,
            stderr: out.stderr,
            fuel_used: out.fuel_consumed,
        }),
        Err(AfterburnerError::FuelExhausted) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::OutOfFuel,
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: RUBY_FUEL,
        }),
        Err(AfterburnerError::Timeout) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Timeout,
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: RUBY_FUEL,
        }),
        Err(AfterburnerError::WasmTrap(msg)) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Trapped(msg),
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: 0,
        }),
        Err(other) => Err(other),
    }
}

/// Write every `source/<rel>` member under `root`, creating parent
/// directories as needed. Shared by [`run_ruby_source`].
fn materialize_source(root: &Path, source: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    for (rel, data) in source {
        let dest = root.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AfterburnerError::Engine(format!("creating {}: {e}", parent.display()))
            })?;
        }
        std::fs::write(&dest, data)
            .map_err(|e| AfterburnerError::Engine(format!("writing {}: {e}", dest.display())))?;
    }
    Ok(())
}

/// Python, source: run on the bundled CPython/Pyodide interpreter via
/// [`afterburner_wasi::pyodide_runner::run_pyodide_package_with`], the same
/// function `cli::run::run_python_afb` calls. See the module doc's "known
/// gaps" for what `request` cannot reach here, and why a bound firing always
/// classifies as `Trapped` rather than `OutOfFuel`.
fn run_python_source(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    use afterburner_wasi::pyodide_runner::{PyPackage, resolve_runtime, run_pyodide_package_with};

    let entry_source = afb
        .entry_source()
        .map_err(|e| AfterburnerError::Engine(format!("reading Python entry: {e}")))?;

    let vendor_pip_wheels: Vec<Vec<u8>> = afb
        .vendor
        .iter()
        .filter(|(k, _)| k.starts_with("vendor/pip/") && k.ends_with(".whl"))
        .map(|(_, v)| v.clone())
        .collect();

    const GUEST_PKG_ROOT: &str = "/pkg";
    let sys_path_dir = format!("{GUEST_PKG_ROOT}/source");
    let mut files = BTreeMap::new();
    for (rel, data) in &afb.source {
        files.insert(format!("{GUEST_PKG_ROOT}/{rel}"), data.clone());
    }
    let pkg = PyPackage {
        files,
        sys_path_dir,
        vendor_pip_wheels,
    };

    let rt = resolve_runtime()?;
    let _ = request; // stdin/fuel/memory_bytes/manifold: see module doc.

    match run_pyodide_package_with(&rt, entry_source, &pkg) {
        Ok(out) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Exited(out.exit_code),
            stdout: out.stdout,
            stderr: out.stderr,
            fuel_used: out.fuel_consumed,
        }),
        Err(e) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Trapped(e.to_string()),
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: 0,
        }),
    }
}

/// Python, compiled (self-contained `emscripten-pyodide` bundle): only
/// reachable with the `bin` feature also enabled. See the module doc for why.
#[cfg(feature = "bin")]
fn run_python_wasm(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    use crate::cli::compile::python_wasm::reconstruct_runtime_from_afb;
    use afterburner_wasi::pyodide_runner::{PyPackage, run_pyodide_package_with};

    let entry_source = afb
        .entry_source()
        .map_err(|e| AfterburnerError::Engine(format!("reading Python entry: {e}")))?;

    let tmp_root = unique_scratch_dir("afb-run-py-wasm");
    let (rt, pip_wheel_bytes) = reconstruct_runtime_from_afb(afb, &tmp_root)
        .map_err(|e| AfterburnerError::Engine(format!("reconstructing Python runtime: {e}")))?;

    const GUEST_PKG_ROOT: &str = "/pkg";
    let sys_path_dir = format!("{GUEST_PKG_ROOT}/source");
    let mut files = BTreeMap::new();
    for (rel, data) in &afb.source {
        files.insert(format!("{GUEST_PKG_ROOT}/{rel}"), data.clone());
    }
    let pkg = PyPackage {
        files,
        sys_path_dir,
        vendor_pip_wheels: pip_wheel_bytes,
    };

    let run_result = run_pyodide_package_with(&rt, entry_source, &pkg);
    let _ = std::fs::remove_dir_all(&tmp_root);
    let _ = request; // stdin/fuel/memory_bytes/manifold: see module doc.

    match run_result {
        Ok(out) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Exited(out.exit_code),
            stdout: out.stdout,
            stderr: out.stderr,
            fuel_used: out.fuel_consumed,
        }),
        Err(e) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Trapped(e.to_string()),
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: 0,
        }),
    }
}

/// Python, compiled: honest error when `bin` is off. See the module doc.
#[cfg(not(feature = "bin"))]
fn run_python_wasm(afb: &Afb, _request: AfbRunRequest) -> Result<AfbRunOutput> {
    Err(AfterburnerError::Engine(format!(
        "{} is a self-contained compiled Python bundle (runtime.target = {PYTHON_WASM_RUNTIME_TARGET:?}); \
         running it from a library caller requires the `bin` feature (rebuild with --features bin), \
         or use a source Python .afb instead",
        afb.qualified_name(),
    )))
}

#[cfg(test)]
mod tests;
