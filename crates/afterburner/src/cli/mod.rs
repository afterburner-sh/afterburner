// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Command-line dispatcher for the `burn` binary.
//!
//! Thin top-level: parse args, match on subcommand, delegate to one of
//! the per-subcommand files in this directory. Everything is gated
//! behind the `bin` cargo feature.
//!
//! Public surface exists so integration tests under `afterburner/tests/`
//! can exercise the flag-to-[`Manifold`] translation without spawning
//! the binary.

mod args;
mod banner;
mod bench;
mod build;
mod check;
mod daemon;
mod manifold;
mod passthrough;
mod registry;
mod repl;
mod run;
mod script;
mod shim;
mod style;
mod thrust;
mod version;
mod worker;

use anyhow::Result;
use clap::Parser;

pub use args::{Cli, Cmd, parse_mode};
pub use build::build_afterburner;
pub use manifold::{build_manifold, has_wildcard, is_implicit_open, parse_allow_list};

/// Entry point. `main()` in the `burn` binary delegates here.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    dispatch(cli)
}

/// Print a top-level error in the brand's alert color (honors NO_COLOR /
/// non-tty). Called by the `burn` binary entrypoint.
pub fn report_error(e: &anyhow::Error) {
    eprintln!("{} {:#}", style::error_prefix(), e);
}

fn dispatch(mut cli: Cli) -> Result<()> {
    let cmd = match cli.command.take() {
        Some(c) => c,
        None => {
            // pass-through targets (`burn node foo.js`, `burn
            // npm install`, …). Must run before the positional-file
            // fallback so `burn node` isn't misinterpreted as "run a
            // file called node".
            //
            // Eval-mode caveat: in `-e CODE` invocations, clap binds
            // the first positional into `cli.file`. For arbitrary
            // names that happen to resolve on PATH we prefer "script
            // arg" (so `burn -e CODE hello` still works when `hello`
            // is `/usr/bin/hello`), but the hard-coded Node-ecosystem
            // names are an explicit user intent and still dispatch.
            if let Some(ref file) = cli.file {
                match passthrough::detect(file) {
                    passthrough::Detected::KnownTarget(target) => {
                        return passthrough::dispatch(&mut cli, &target);
                    }
                    passthrough::Detected::PathTarget(target) if cli.eval_code.is_none() => {
                        return passthrough::dispatch(&mut cli, &target);
                    }
                    passthrough::Detected::Unknown(name) if cli.eval_code.is_none() => {
                        // Q5-2: never let an exec proceed with a
                        // ghost binary; emit a clean typed error
                        // first.
                        anyhow::bail!("burn: unknown command '{name}'");
                    }
                    _ => {}
                }
            }

            if let Some(code) = cli.eval_code.clone() {
                // With `-e CODE arg1 arg2`, clap binds the *first*
                // positional to `cli.file` (its declared slot), and
                // the rest into `cli.rest_args`. For eval mode, that
                // first positional is actually a script arg — fold it
                // back into `rest_args` so `process.argv` matches the
                // user's intent.
                let mut rest = Vec::new();
                if let Some(f) = cli.file.take() {
                    rest.push(f.to_string_lossy().into_owned());
                }
                rest.extend(std::mem::take(&mut cli.rest_args));
                Cmd::Eval {
                    code,
                    rest_args: rest,
                }
            } else if let Some(file) = cli.file.clone() {
                Cmd::Run {
                    file,
                    rest_args: std::mem::take(&mut cli.rest_args),
                }
            } else {
                // Bare `burn` (no subcommand, file, or eval) drops into the REPL.
                Cmd::Repl
            }
        }
    };

    // Show the open-capabilities banner once per user for script-like
    // subcommands. `version` / `check` are metadata-only and don't
    // execute user code, so they don't warrant the warning.
    if matches!(
        cmd,
        Cmd::Run { .. } | Cmd::Eval { .. } | Cmd::Thrust { .. } | Cmd::Bench { .. } | Cmd::Repl
    ) {
        banner::maybe_show(&cli);
    }

    match cmd {
        Cmd::Run { file, rest_args } => run::run_file(&cli, &file, &rest_args),
        Cmd::Eval { code, rest_args } => run::run_source(&cli, &code, &rest_args),
        Cmd::Thrust { file } => thrust::thrust_from_stdin(&cli, &file),
        Cmd::Check { file } => check::check_file(&cli, &file),
        Cmd::Bench {
            file,
            iters,
            workers,
        } => bench::bench(&cli, &file, iters, workers),
        Cmd::Repl => repl::repl(&cli),
        Cmd::Version => version::print_version(),

        // ── registry + package management ──────────────────────────────────
        Cmd::Login { token, registry } => registry::login(token.as_deref(), registry.as_deref()),
        Cmd::Logout { registry } => registry::logout(registry.as_deref()),
        Cmd::Whoami { registry } => registry::whoami(registry.as_deref()),
        Cmd::New { spec, opts } => registry::new_package(&cli, &spec, &opts),
        Cmd::Init { path, opts } => registry::init_package(&cli, path.as_deref(), &opts),
        Cmd::Package { dir, out } => registry::package(dir.as_deref(), out.as_deref()),
        Cmd::Publish {
            afb,
            dir,
            registry: reg,
            token,
        } => registry::publish(
            afb.as_deref(),
            dir.as_deref(),
            reg.as_deref(),
            token.as_deref(),
        ),
        Cmd::Yank {
            pkg,
            undo,
            registry: reg,
            token,
        } => registry::yank(&pkg, undo, reg.as_deref(), token.as_deref()),
        Cmd::Install { pkg, registry: reg } => registry::install(&pkg, reg.as_deref()),
        Cmd::Search {
            query,
            registry: reg,
        } => registry::search(&query, reg.as_deref()),
        Cmd::Add {
            pkg,
            dir,
            registry: reg,
        } => registry::add(&pkg, dir.as_deref(), reg.as_deref()),
        Cmd::Info { pkg, registry: reg } => registry::info(&pkg, reg.as_deref()),
        Cmd::Owner {
            pkg,
            list,
            add,
            remove,
        } => registry::owner(pkg.as_deref(), list, add.as_deref(), remove.as_deref()),
    }
}
