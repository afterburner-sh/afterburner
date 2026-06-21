// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
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

mod agent;
mod args;
mod banner;
mod bench;
mod build;
mod check;
mod compile;
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
    // Hook hot path: assistants spawn `burn agent hook --host <h>` before
    // EVERY shell command they run - dispatch straight off argv so the
    // invocation pays for nothing but the verdict (no clap, no banner).
    {
        let argv: Vec<String> = std::env::args().collect();
        if argv.get(1).is_some_and(|a| a == "agent") && argv.get(2).is_some_and(|a| a == "hook") {
            let host = argv
                .iter()
                .position(|a| a == "--host")
                .and_then(|i| argv.get(i + 1))
                .map_or("", String::as_str);
            return agent::hook_entry(host);
        }
    }
    // Animated brand banner ahead of clap's top-level help.
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--help" | "-h" | "help")
    ) {
        style::banner(env!("CARGO_PKG_VERSION"));
    }
    let cli = Cli::parse();
    dispatch(cli)
}

/// Print a top-level error in the brand's alert color (honors NO_COLOR /
/// non-tty). Called by the `burn` binary entrypoint.
pub fn report_error(e: &anyhow::Error) {
    eprintln!(
        "{} {}",
        style::error_prefix(),
        style::humanize_error(&format!("{e:#}"))
    );
}

fn dispatch(mut cli: Cli) -> Result<()> {
    // Pass-through targets (`burn node foo.js`, `burn npm install`, …)
    // must be resolved before *any* subcommand dispatch.
    //
    // The first positional (`cli.file`) is the pass-through target. It
    // takes precedence even when clap also parsed a `cli.command`: that
    // happens whenever the target's own arguments collide with a burn
    // subcommand name - `burn npm install express` makes clap bind
    // `install` as `Cmd::Install`, `burn pnpm run dev` as `Cmd::Run`,
    // etc. Those tokens belong to npm/pnpm, not to burn, so a detected
    // pass-through target wins and the trailing args are recovered from
    // raw argv inside the pass-through path.
    //
    // Eval-mode caveat: in `-e CODE` invocations clap binds the first
    // positional into `cli.file`. For arbitrary names that happen to
    // resolve on PATH we prefer "script arg" (so `burn -e CODE hello`
    // still works when `hello` is `/usr/bin/hello`), but the hard-coded
    // Node-ecosystem names are explicit user intent and still dispatch.
    if let Some(ref file) = cli.file {
        match passthrough::detect(file) {
            passthrough::Detected::KnownTarget(target) => {
                return passthrough::dispatch(&mut cli, &target);
            }
            passthrough::Detected::PathTarget(target) if cli.eval_code.is_none() => {
                return passthrough::dispatch(&mut cli, &target);
            }
            passthrough::Detected::Unknown(name)
                if cli.eval_code.is_none() && cli.command.is_none() =>
            {
                // Q5-2: never let an exec proceed with a ghost binary;
                // emit a clean typed error first. Suppressed when clap
                // parsed a real subcommand (the positional was the
                // subcommand's own argument, not a ghost target).
                anyhow::bail!("burn: unknown command '{name}'");
            }
            _ => {}
        }
    }

    // A top-level positional FILE *plus* a parsed subcommand is clap
    // mis-binding the script's own arguments. `burn app.js install foo`
    // (or, via the PATH shim, npm's internal `node npm-cli.js install
    // foo` re-entering as `burn npm-cli.js install foo`) makes clap bind
    // `app.js` to `cli.file` and then steal `install`/`run`/`test`/… as
    // `cli.command` because those tokens collide with registry
    // subcommand names. The file is an explicit "run this script", so it
    // wins; the subcommand tokens are script argv recovered from raw
    // argv. Registry subcommands proper never carry a leading FILE
    // positional, so this only triggers on the mis-binding.
    //
    // Skipped under `-e CODE`: there the positional + trailing tokens are
    // *eval* script args (handled below by folding `cli.file` back into
    // `rest_args`), not a file to run.
    if cli.command.is_some()
        && cli.eval_code.is_none()
        && let Some(file) = cli.file.clone()
    {
        let rest_args = run::script_args_from_argv(&file);
        banner::maybe_show(&cli);
        return run::run_file(&cli, &file, &rest_args);
    }

    // `-e CODE` is an explicit eval flag and always wins, even when a
    // trailing script arg collided with a subcommand name and clap bound
    // it as `cli.command` (`burn -e CODE install foo`). The positional +
    // trailing tokens are the eval script's argv; recover them from raw
    // argv when a hijacked command swallowed them.
    if let Some(code) = cli.eval_code.clone() {
        let rest = if cli.command.is_some() {
            // Hijacked: one or more eval script args collided with a
            // subcommand name, so clap pulled them out of `cli.file` /
            // `cli.rest_args` into `cli.command`. Recover the full
            // positional tail straight from raw argv.
            run::eval_args_from_argv(&code)
        } else {
            // Clean: clap bound the first positional to `cli.file` (its
            // declared slot) and the rest into `cli.rest_args`. Fold the
            // file back in so `process.argv` matches the user's intent.
            let mut rest = Vec::new();
            if let Some(f) = cli.file.take() {
                rest.push(f.to_string_lossy().into_owned());
            }
            rest.extend(std::mem::take(&mut cli.rest_args));
            rest
        };
        cli.file = None;
        cli.command = None;
        banner::maybe_show(&cli);
        return run::run_source(&cli, &code, &rest);
    }

    let cmd = match cli.command.take() {
        Some(c) => c,
        None => {
            if let Some(file) = cli.file.clone() {
                Cmd::Run {
                    file: Some(file),
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
        Cmd::Run { file, rest_args } => run::run_package_or_file(&cli, file.as_deref(), &rest_args),
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
        Cmd::Package {
            dir,
            out,
            compile,
            packages_dir,
        } => registry::package(
            dir.as_deref(),
            out.as_deref(),
            compile,
            packages_dir.as_deref(),
        ),
        Cmd::Compile {
            dir,
            out,
            packages_dir,
        } => compile::compile(dir.as_deref(), out.as_deref(), packages_dir.as_deref()),
        Cmd::Test { dir } => registry::test(&cli, dir.as_deref()),
        Cmd::Clean { dir, cache } => registry::clean(dir.as_deref(), cache),
        Cmd::Publish {
            afb,
            dir,
            registry: reg,
            token,
            compile,
            no_compile,
            packages_dir,
        } => registry::publish(
            afb.as_deref(),
            dir.as_deref(),
            reg.as_deref(),
            token.as_deref(),
            compile,
            no_compile,
            packages_dir.as_deref(),
        ),
        Cmd::Yank {
            pkg,
            undo,
            registry: reg,
            token,
        } => registry::yank(&pkg, undo, reg.as_deref(), token.as_deref()),
        Cmd::Install {
            pkg,
            registry: reg,
            jobs,
            locked,
        } => registry::install(pkg.as_deref(), reg.as_deref(), jobs, locked),
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

        // ── AI assistant integration ────────────────────────────────────────
        Cmd::Agent { action } => agent::dispatch(&action),
    }
}
