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
//!   on [`shared_epoch_vm`][afterburner_wasi::embedder_vm::shared_epoch_vm],
//!   with `stdin`, `fuel`, `memory_bytes`, `timeout`, and the manifold's
//!   `fs`/`env` grants fully wired through.
//! - Ruby, compiled (`[runtime] target = "wasm32-wasip1"`, produced by
//!   `burn compile` via wasi-vfs): the same WASI-command path as above, with
//!   the guest script path convention `cli::compile::ruby_wasm` documents.
//! - Python, source and Python, compiled (`[runtime] target =
//!   "emscripten-pyodide"`, a self-contained bundle): both run through
//!   [`afterburner_wasi::pyodide_runner::run_pyodide_package_bounded`], with
//!   `stdin`, `fuel`, `memory_bytes`, and the manifold's `env` and
//!   read-write `fs` grants wired through (see the module doc there for
//!   exactly how - the same staged-file technique the stdout/stderr capture
//!   already uses, in the read direction, for stdin). Reconstructing the
//!   compiled bundle's runtime
//!   ([`afterburner_wasi::pyodide_runner::reconstruct_runtime_from_afb`])
//!   lives in `afterburner-wasi` now, not behind the `bin` feature, so both
//!   shapes are reachable under `afb-run` alone - no second implementation,
//!   the function that used to live behind `bin` moved rather than being
//!   copied.
//! - Ruby, source (no precompiled member): the bundled CRuby interpreter via
//!   [`afterburner_wasi::ruby_runner::run_ruby_afb_with`], the exact function
//!   `cli::run::run_ruby_afb` calls - no second way to run Ruby source was
//!   invented here. Unlike Python, this path was not wired with bounds this
//!   round (see "known gaps" below): it refuses instead.
//!
//! ## Known gaps (honest, not hidden)
//!
//! `AfbRunRequest`'s bounds are fully enforced for the compiled-WASM,
//! compiled-Ruby, Python-source, and Python-compiled families - every field:
//! `stdin`, `fuel`, `memory_bytes`, the manifold's `env`, and (compiled-WASM
//! / compiled-Ruby only) `timeout` and the manifold's read-only `fs`. A
//! request for a bound a path does not enforce is refused outright
//! ([`AfterburnerError::Engine`], naming the language and the missing
//! bound(s)) rather than silently running with less containment than asked
//! for - see [`refuse_unsupported`].
//!
//! What is refused, and why:
//!
//! - Every family refuses `manifold.fs = FsAccess::ReadOnly(_)` when it can
//!   only offer read-write (Python) or does not offer extra `fs` grants at
//!   all (Ruby-source): granting read-write when the caller asked for
//!   read-only would widen the ceiling, which is never acceptable, so the
//!   narrower grant is refused rather than silently broadened.
//! - Python (both shapes) refuses `timeout`: `pyodide_runner`'s engine does
//!   not run with wasmtime epoch interruption enabled, so there is no
//!   mechanism to enforce a wall-clock deadline there today - see
//!   `pyodide_runner`'s own module doc for why threading that through is a
//!   separate, larger change than the fuel/memory/stdin/env wiring this
//!   round did.
//! - Python (both shapes): `fuel` and `memory_bytes` ARE enforced - the
//!   guest genuinely cannot exceed either - but the *outcome* does not
//!   always say which one fired. `memory_bytes` does: a denied
//!   `memory.grow` sets `PyodideRunOutput::memory_limit_hit`, which
//!   [`finish_pyodide`] reads and reports as `OutOfMemory`. `fuel` does
//!   not: `pyodide_runner`'s trap handling formats the underlying error
//!   with `{e}` (anyhow's top-level message only; the `Trap::OutOfFuel`
//!   cause needs `.chain()`, which nothing here calls), so a fuel-exhausted
//!   run comes back as `Trapped` with a message that does not name fuel,
//!   and `fuel_used` stays `0` rather than the budget spent. Real
//!   containment, imprecise reporting - not a safety gap, a diagnostics one.
//! - Ruby-source refuses `stdin`, `fuel`, `memory_bytes`, and any non-sealed
//!   `manifold.fs`/`manifold.env`: `ruby_runner`'s package runner was not
//!   extended with the equivalent of `pyodide_runner::PyodideRunBounds` this
//!   round (the coordinator's own call: "not offering it is fine" for this
//!   one path). Ruby-source still gets typed bound classification
//!   (`OutOfFuel` / `Timeout`) when its own fixed `RUBY_FUEL` budget or a
//!   real trap fires, because `ruby_runner` already routes through
//!   `EmbedderVm::run_command_with_host`, which classifies traps before this
//!   module ever sees them - that part was never a gap.
//!
//! `vertexia:` Ruby-source's gap (no bound wiring, refuses instead) is a
//! deliberate scope cut, not silently dropped work; upgrade path is an
//! additive `RubyRunBounds`-shaped parameter on `ruby_runner::run_ruby_pkg`,
//! mirroring `pyodide_runner::PyodideRunBounds` exactly.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use afterburner_afb::Afb;
use afterburner_core::{AfterburnerError, EnvAccess, FsAccess, Manifold, Result};
use afterburner_wasi::embedder_vm::{BoundedCommandOutput, CommandOutcome, WasiCommandOpts};

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
    /// Wall-clock deadline for the whole run, enforced by wasmtime epoch
    /// interruption (see
    /// [`shared_epoch_vm`][afterburner_wasi::embedder_vm::shared_epoch_vm]):
    /// a real preemption bound, not a "stop waiting for it" one - the guest
    /// is actually interrupted, and nothing keeps running in the
    /// background after this call returns [`AfbRunOutcome::Timeout`]. No
    /// thread is spawned per call; the deadline is a value set on the
    /// `Store`, checked by a single process-wide ticker thread that already
    /// runs for the life of the process.
    ///
    /// Granularity is one epoch tick
    /// ([`EPOCH_TICK_PERIOD_MS`][afterburner_wasi::embedder_vm::EPOCH_TICK_PERIOD_MS],
    /// 10 ms today): a shorter request rounds up to it, and a guest can run
    /// up to one tick past the deadline before the interruption is
    /// observed (epoch checks happen at safepoints the compiler inserts,
    /// not on every instruction) - this is not millisecond-precise, only
    /// millisecond-bounded.
    ///
    /// Only enforced for the compiled-WASM and compiled-Ruby families
    /// (both run through [`EmbedderVm`][afterburner_wasi::embedder_vm::EmbedderVm]).
    /// Ruby-source, Python-source, and compiled Python cannot honor a
    /// timeout today (their runners build their own engine without epoch
    /// interruption) and refuse rather than silently ignore it - see the
    /// module doc's "known gaps".
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
    dispatch(&parsed, request)
}

/// Language dispatch, mirroring `cli::run::run_afb` exactly.
fn dispatch(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    let runtime_target = afb.manifest.runtime.target.as_deref().unwrap_or("");
    if runtime_target == afterburner_wasi::pyodide_runner::RUNTIME_TARGET {
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
        timeout,
    } = request;

    let wasm_bytes = afb.precompiled.get(PRECOMPILED_WASM_MEMBER).ok_or_else(|| {
        AfterburnerError::Engine(format!(
            "{} has no {PRECOMPILED_WASM_MEMBER}; run `burn compile` to produce a native WASM package",
            afb.qualified_name(),
        ))
    })?;

    // The shared, epoch-interruption-enabled `EmbedderVm` (one engine, one
    // ticker thread, for the life of the process - see `shared_epoch_vm`'s
    // own doc): `timeout` is a real wall-clock bound only when the module
    // that runs it was compiled against that engine.
    let vm = afterburner_wasi::embedder_vm::shared_epoch_vm()?;
    let module = vm.compile(wasm_bytes, true, |_| Ok(()))?;

    let mut argv = vec![afb.qualified_name()];
    argv.extend(args);
    let mut opts = WasiCommandOpts::new().args(argv).stdin(stdin);
    if let Some(bytes) = memory_bytes {
        opts = opts.max_memory_bytes(bytes as usize);
    }
    opts = manifold_to_wasi_opts(&manifold, opts);

    let raw = vm.run_command_bounded(&module, opts, fuel, None, timeout)?;
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
        timeout,
    } = request;

    let wasm_bytes = afb.precompiled.get(PRECOMPILED_WASM_MEMBER).ok_or_else(|| {
        AfterburnerError::Engine(format!(
            "Ruby package {} has no {PRECOMPILED_WASM_MEMBER}; re-run `burn compile` to rebuild it",
            afb.qualified_name(),
        ))
    })?;

    let vm = afterburner_wasi::embedder_vm::shared_epoch_vm()?;
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

    let raw = vm.run_command_bounded(&module, opts, fuel, None, timeout)?;
    Ok(finish(raw))
}

/// Which of `AfbRunRequest`'s bound axes a dispatch path actually enforces.
/// `args` is not a bound (no security/resource meaning) and is never
/// checked. `manifold_fs_ro` and `manifold_fs_rw` are separate: granting
/// read-write when the caller asked for read-only would widen the ceiling,
/// so a path that can only offer read-write must refuse a
/// `FsAccess::ReadOnly` request even when it can honor `FsAccess::ReadWrite`.
#[derive(Default)]
struct SupportedBounds {
    stdin: bool,
    fuel: bool,
    memory_bytes: bool,
    manifold_fs_ro: bool,
    manifold_fs_rw: bool,
    manifold_env: bool,
    timeout: bool,
}

/// Refuse `request` outright if it asks for a bound `language`'s dispatch
/// path does not enforce, rather than silently running with less
/// containment than the caller asked for. `request.fuel`/`memory_bytes`
/// being `None`, `request.stdin` being empty, `request.manifold` being
/// sealed, and `request.timeout` being `None` never trigger a refusal - not
/// asking for a bound is always fine; asking for one and not getting it
/// silently is not.
fn refuse_unsupported(
    language: &str,
    request: &AfbRunRequest,
    supported: SupportedBounds,
) -> Result<()> {
    let mut missing: Vec<&str> = Vec::new();
    if !request.stdin.is_empty() && !supported.stdin {
        missing.push("stdin");
    }
    if request.fuel.is_some() && !supported.fuel {
        missing.push("fuel");
    }
    if request.memory_bytes.is_some() && !supported.memory_bytes {
        missing.push("memory_bytes");
    }
    match &request.manifold.fs {
        FsAccess::None => {}
        FsAccess::ReadOnly(_) if !supported.manifold_fs_ro => {
            missing.push("manifold.fs (read-only)");
        }
        FsAccess::ReadWrite(_) if !supported.manifold_fs_rw => {
            missing.push("manifold.fs (read-write)");
        }
        _ => {}
    }
    if !matches!(request.manifold.env, EnvAccess::None) && !supported.manifold_env {
        missing.push("manifold.env");
    }
    if request.timeout.is_some() && !supported.timeout {
        missing.push("timeout");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(AfterburnerError::Engine(format!(
            "{language}: {} not enforced for this package's run path; refusing rather than \
             running with {} silently ignored",
            missing.join(", "),
            if missing.len() == 1 { "it" } else { "them" },
        )))
    }
}

/// Ruby, source (no precompiled member): run on the bundled CRuby
/// interpreter via [`afterburner_wasi::ruby_runner::run_ruby_afb_with`], the
/// exact function `cli::run::run_ruby_afb` calls. See the module doc's
/// "known gaps" for why every bound is refused here.
fn run_ruby_source(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    use afterburner_wasi::ruby_runner::{RUBY_FUEL, resolve_ruby_runtime, run_ruby_afb_with};

    refuse_unsupported("Ruby (source)", &request, SupportedBounds::default())?;

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

/// Validate `request` against what a Python run (source or compiled - both
/// call this) can enforce, then translate it into the
/// [`PyodideRunBounds`][afterburner_wasi::pyodide_runner::PyodideRunBounds]
/// `pyodide_runner`'s bounded package runner takes. `FsAccess::ReadOnly` is
/// refused (`rw_preopens` is read-write only - honoring a read-only request
/// by granting read-write would silently widen it) and `timeout` is refused
/// (`pyodide_runner`'s engine runs without epoch interruption - see the
/// module doc's "known gaps").
fn python_bounds(
    language: &str,
    request: AfbRunRequest,
) -> Result<afterburner_wasi::pyodide_runner::PyodideRunBounds> {
    refuse_unsupported(
        language,
        &request,
        SupportedBounds {
            stdin: true,
            fuel: true,
            memory_bytes: true,
            manifold_fs_ro: false,
            manifold_fs_rw: true,
            manifold_env: true,
            timeout: false,
        },
    )?;

    let AfbRunRequest {
        stdin,
        args: _,
        manifold,
        fuel,
        memory_bytes,
        timeout: _,
    } = request;

    let rw_preopens = match manifold.fs {
        FsAccess::ReadWrite(paths) => paths
            .into_iter()
            .map(|p| {
                let guest = p.to_string_lossy().into_owned();
                (p, guest)
            })
            .collect(),
        _ => Vec::new(),
    };
    let env = match manifold.env {
        EnvAccess::AllowList(keys) => keys
            .into_iter()
            .filter_map(|k| std::env::var(&k).ok().map(|v| (k, v)))
            .collect(),
        EnvAccess::Full => std::env::vars().collect(),
        EnvAccess::None => Vec::new(),
    };

    Ok(afterburner_wasi::pyodide_runner::PyodideRunBounds {
        stdin: if stdin.is_empty() { None } else { Some(stdin) },
        fuel,
        max_memory_bytes: memory_bytes.map(|b| b as usize),
        env,
        rw_preopens,
    })
}

/// Classify a [`PyodideRunOutput`][afterburner_wasi::pyodide_runner::PyodideRunOutput]
/// into an [`AfbRunOutput`]. `memory_limit_hit` takes precedence over the
/// exit code for the same reason [`finish`] gives it precedence for the
/// WASI-command families: the caller asked for a memory ceiling, and it
/// firing is the more actionable fact even when the guest went on to exit
/// cleanly.
fn finish_pyodide(out: afterburner_wasi::pyodide_runner::PyodideRunOutput) -> AfbRunOutput {
    let outcome = if out.memory_limit_hit {
        AfbRunOutcome::OutOfMemory
    } else {
        AfbRunOutcome::Exited(out.exit_code)
    };
    AfbRunOutput {
        outcome,
        stdout: out.stdout,
        stderr: out.stderr,
        fuel_used: out.fuel_consumed,
    }
}

/// Python, source: run on the bundled CPython/Pyodide interpreter via
/// [`afterburner_wasi::pyodide_runner::run_pyodide_package_bounded`], the
/// bounded sibling of the function `cli::run::run_python_afb` calls. A trap
/// (including hitting a caller-supplied `fuel` ceiling) always classifies as
/// `Trapped` rather than `OutOfFuel` - see the module doc's "known gaps" for
/// why.
fn run_python_source(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    use afterburner_wasi::pyodide_runner::{
        PyPackage, resolve_runtime, run_pyodide_package_bounded,
    };

    let bounds = python_bounds("Python (source)", request)?;

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

    match run_pyodide_package_bounded(&rt, entry_source, &pkg, bounds) {
        Ok(out) => Ok(finish_pyodide(out)),
        Err(e) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Trapped(e.to_string()),
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: 0,
        }),
    }
}

/// Python, compiled (self-contained `emscripten-pyodide` bundle): reachable
/// under `afb-run` alone - reconstructing the bundle's runtime
/// ([`reconstruct_runtime_from_afb`][afterburner_wasi::pyodide_runner::reconstruct_runtime_from_afb])
/// lives in `afterburner-wasi` now, not behind the `bin` feature. Same
/// bound handling as [`run_python_source`] (both call [`python_bounds`] /
/// [`finish_pyodide`]) - the only difference is where the interpreter and
/// stdlib bytes come from.
fn run_python_wasm(afb: &Afb, request: AfbRunRequest) -> Result<AfbRunOutput> {
    use afterburner_wasi::pyodide_runner::{
        PyPackage, reconstruct_runtime_from_afb, run_pyodide_package_bounded,
    };

    let bounds = python_bounds("Python (compiled)", request)?;

    let entry_source = afb
        .entry_source()
        .map_err(|e| AfterburnerError::Engine(format!("reading Python entry: {e}")))?;

    let tmp_root = unique_scratch_dir("afb-run-py-wasm");
    let (rt, pip_wheel_bytes) = reconstruct_runtime_from_afb(afb, &tmp_root)?;

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

    let run_result = run_pyodide_package_bounded(&rt, entry_source, &pkg, bounds);
    let _ = std::fs::remove_dir_all(&tmp_root);

    match run_result {
        Ok(out) => Ok(finish_pyodide(out)),
        Err(e) => Ok(AfbRunOutput {
            outcome: AfbRunOutcome::Trapped(e.to_string()),
            stdout: Vec::new(),
            stderr: Vec::new(),
            fuel_used: 0,
        }),
    }
}

#[cfg(test)]
mod tests;
