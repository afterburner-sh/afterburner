// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Clap-derived CLI schema — the structure that `clap::Parser::parse`
//! fills from `std::env::args`.

use crate::Mode;
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "burn",
    version,
    about = "Sandboxed JavaScript runtime",
    long_about = "Execute JavaScript in the Afterburner sandbox. \
                  Reads .js files, evaluates inline code, pipes UDFs through stdin."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Cmd>,

    /// Positional fallback — when no subcommand is given but a path is,
    /// this is treated as `burn run <path>`. Matches the user expectation
    /// of `burn ./script.js` working with zero ceremony.
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Eval inline source (when not using a subcommand).
    #[arg(short = 'e', long = "eval", value_name = "CODE", global = true)]
    pub eval_code: Option<String>,

    /// Engine mode (`adaptive`, `wasm`, `native`). Default: adaptive.
    #[arg(long, value_name = "MODE", global = true)]
    pub mode: Option<String>,

    /// Per-call fuel budget (backend-specific instruction count).
    #[arg(long, value_name = "N", global = true)]
    pub fuel: Option<u64>,

    /// Per-call linear memory cap (bytes).
    #[arg(long, value_name = "BYTES", global = true)]
    pub memory: Option<usize>,

    /// Per-call wall-clock cap (milliseconds).
    #[arg(long = "timeout", value_name = "MS", global = true)]
    pub timeout_ms: Option<u64>,

    /// Grant outbound HTTP access. Values: `*` = any host;
    /// `api.example.com,*.trusted.io` = comma-separated allow-list with
    /// optional wildcard subdomains. Without this flag all HTTP is
    /// denied (`PermissionDenied`).
    #[arg(long = "allow-net", value_name = "HOSTS", global = true)]
    pub allow_net: Option<String>,

    /// Grant read+write filesystem access. Values: `*` = entire FS;
    /// `/var/data,/tmp/workspace` = comma-separated root allow-list.
    #[arg(long = "allow-fs", value_name = "PATHS", global = true)]
    pub allow_fs: Option<String>,

    /// Grant env-var read access. Values: `*` = all env; `HOME,PATH` =
    /// comma-separated name allow-list.
    #[arg(long = "allow-env", value_name = "VARS", global = true)]
    pub allow_env: Option<String>,

    /// Shortcut: grant all capabilities (net, fs, env). Use with care.
    #[arg(long = "allow-all", short = 'A', global = true)]
    pub allow_all: bool,

    /// Seal the sandbox (empty capabilities) — flip the CLI's open-by-default.
    /// Combine with `--allow-*` flags to hand-pick grants.
    #[arg(long = "sandbox", global = true)]
    pub sandbox: bool,

    /// Suppress the first-run open-capabilities banner and other
    /// non-essential stderr notices. `BURN_QUIET=1` in the environment
    /// has the same effect.
    #[arg(long = "quiet", short = 'q', global = true)]
    pub quiet: bool,

    /// Re-run the script when its file (or any local `require()` it
    /// pulls in) changes on disk. Mirrors `node --watch`. Off by
    /// default; pair with file-watching dev workflows.
    #[arg(long = "watch", global = true)]
    pub watch: bool,

    /// Load `KEY=VALUE` lines from a `.env`-style file into
    /// `process.env` before the script runs. Repeatable; later files
    /// override earlier keys. Mirrors `node --env-file=path`.
    #[arg(long = "env-file", value_name = "PATH", global = true)]
    pub env_file: Vec<PathBuf>,

    /// Preload a CommonJS module (or several, repeated) before the
    /// entry script. Mirrors `node --require=path`. Useful for
    /// instrumentation, sourcemap support, env shims.
    #[arg(long = "require", short = 'r', value_name = "MODULE", global = true)]
    pub require: Vec<String>,

    /// Preload an ES module (or several, repeated) before the entry
    /// script. Mirrors `node --import=path`. The module is lowered
    /// through the same TS-strip + ESM rewrite as user source.
    #[arg(long = "import", value_name = "MODULE", global = true)]
    pub import: Vec<String>,

    /// Enable the Permission Model (`process.permission.has(...)` /
    /// `get(...)`). Without `--permission`, `process.permission` is
    /// absent. Mirrors `node --permission`.
    #[arg(long = "permission", global = true)]
    pub permission: bool,

    /// Permission Model: read-only filesystem grant (host:path
    /// granularity). Same shape as `--allow-fs` but read-only.
    #[arg(long = "allow-fs-read", value_name = "PATHS", global = true)]
    pub allow_fs_read: Option<String>,

    /// Permission Model: write-only filesystem grant.
    #[arg(long = "allow-fs-write", value_name = "PATHS", global = true)]
    pub allow_fs_write: Option<String>,

    /// Permission Model: child-process grant. Required for
    /// `child_process.spawn`/`exec` under `--permission`.
    #[arg(long = "allow-child-process", global = true)]
    pub allow_child_process: bool,

    /// Permission Model: worker_threads grant. Required for `new
    /// Worker(...)` under `--permission`.
    #[arg(long = "allow-worker", global = true)]
    pub allow_worker: bool,

    /// **Internal — set only by `worker_threads`.** Marks this `burn`
    /// invocation as a worker child: read the init frame off stdin,
    /// expose `parentPort`, and pump frames over stdin/stdout per the
    /// daemon_workers protocol. Hidden from `--help` to discourage
    /// human use; running `burn --internal-worker foo.js` by hand
    /// without an init frame on stdin will hang.
    #[arg(long = "internal-worker", hide = true, global = true)]
    pub internal_worker: bool,

    /// **Internal — set only by `worker_threads`.** The monotonic
    /// `threadId` the parent assigned to this worker. Defaults to 0
    /// (which only the parent process sees) outside worker mode.
    #[arg(
        long = "worker-thread-id",
        value_name = "ID",
        hide = true,
        global = true
    )]
    pub worker_thread_id: Option<i32>,

    /// Positional arguments after the script path — passed through as
    /// `process.argv[2..]`. Only meaningful for the top-level
    /// `burn FILE arg1 arg2…` shape; each subcommand has its own
    /// `rest_args` when it accepts trailing args.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    pub rest_args: Vec<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Cmd {
    /// Execute a JavaScript file.
    Run {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Arguments passed through as `process.argv[2..]`.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        rest_args: Vec<String>,
    },
    /// Evaluate an inline JavaScript snippet.
    Eval {
        #[arg(value_name = "CODE")]
        code: String,
        /// Arguments passed through as `process.argv[2..]`.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        rest_args: Vec<String>,
    },
    /// UDF mode — reads JSON from stdin, feeds as `data` to the script,
    /// writes the script's return value as JSON to stdout.
    Thrust {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Parse + compile a script without executing it. Exit code 0 on
    /// success, 1 on syntax or semantic errors.
    Check {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Measure throughput + p50/p99 latency by running the script N
    /// times. Reports to stderr; script output is suppressed.
    Bench {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Total iterations to submit.
        #[arg(long, default_value_t = 10_000)]
        iters: usize,
        /// Worker count for the threaded path. `0` (the default)
        /// resolves to `BURN_SHARDS` if set, else
        /// `available_parallelism()`. `1` forces single-threaded
        /// (BurnCache, no ThrustEngine). `≥2` engages
        /// ThrustEngine with that many workers.
        #[arg(long, default_value_t = 0)]
        workers: usize,
    },
    /// Interactive REPL. Each line becomes a fresh script (no state
    /// shared across lines — matches the fresh-per-call invariant).
    Repl,
    /// Print the build version + enabled features.
    Version,
}

pub fn parse_mode(s: &str) -> Result<Mode> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "native" => Mode::Native,
        #[cfg(feature = "wasm")]
        "wasm" => Mode::Wasm,
        #[cfg(feature = "adaptive")]
        "adaptive" => Mode::Adaptive,
        other => anyhow::bail!("unknown --mode '{other}'; expected one of: native, wasm, adaptive"),
    })
}
