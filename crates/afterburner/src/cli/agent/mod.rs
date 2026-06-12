// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn agent` - wire AI coding assistants to run the JavaScript they
//! generate inside the burn sandbox.
//!
//! * `install` - pick assistants (arrow-key multi-select; detected ones
//!   pre-checked) and wire a pre-tool hook + an instruction block into each
//!   one's config. Idempotent; re-running repairs a stale binary path.
//! * `uninstall` - the exact inverse: remove the hook entries and the
//!   instruction blocks, leaving every config as it was.
//! * `status` - what's detected, wired, and current.
//! * `hook` - the non-interactive per-tool-call shim (see [`hook`]).
//!
//! The redirect itself rides on the pass-through dispatcher: the hook tells
//! the assistant to prefix the JS-executing command with `burn`, and
//! `burn node`/`burn npm`/`burn npx` already run those sandboxed.

mod classify;
mod context;
mod hook;
mod hosts;

use std::io::IsTerminal;

use anyhow::{Result, bail};

use super::args::AgentCmd;
use super::style;

/// Top-level `burn agent` dispatch.
///
/// # Errors
/// Surfaces I/O failures and invalid host names.
pub fn dispatch(cmd: &AgentCmd) -> Result<()> {
    match cmd {
        AgentCmd::Install {
            hosts,
            project,
            yes,
        } => install(hosts, !project, *yes),
        AgentCmd::Uninstall {
            hosts,
            all,
            project,
            yes,
        } => uninstall(hosts, *all, !project, *yes),
        AgentCmd::Status => status(),
        AgentCmd::Enable => set_disabled(false),
        AgentCmd::Disable => set_disabled(true),
        AgentCmd::Hook { host } => hook::run(host),
    }
}

/// Straight-off-argv entry for the hook hot path (see `cli::run`) - the
/// assistant spawns this before every shell command, so it must not pay
/// for clap or the banner.
pub fn hook_entry(host: &str) -> Result<()> {
    hook::run(host)
}

/// Flip the persistent kill switch (a flag file the hook stats on every
/// invocation). `disable` pauses the redirect everywhere WITHOUT touching
/// any assistant config; `enable` resumes it.
fn set_disabled(disabled: bool) -> Result<()> {
    let path = hook::disabled_path();
    if disabled {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, "disabled by `burn agent disable`\n")?;
        println!(
            "{}",
            style::warn(
                "sandbox redirect paused - hooks stay wired, everything is allowed through. Resume: burn agent enable"
            )
        );
    } else {
        match std::fs::remove_file(&path) {
            Ok(()) => println!("{}", style::ok("sandbox redirect active again.")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("{}", style::muted("already enabled - nothing to do."));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Validate `--host` values against the registry, with a helpful error.
fn validate_hosts(keys: &[String]) -> Result<Vec<&'static str>> {
    let mut out = Vec::new();
    for k in keys {
        match hosts::spec(k) {
            Some(h) => out.push(h.key),
            None => {
                let known: Vec<&str> = hosts::HOSTS.iter().map(|h| h.key).collect();
                bail!("unknown host '{k}'; expected one of: {}", known.join(", "));
            }
        }
    }
    Ok(out)
}

/// The arrow-key menu theme in the brand's flame palette. Mirrors the
/// crossterm styling rules in [`super::style`]: dialoguer's `console`
/// backend independently honours NO_COLOR / non-tty, so pipes stay clean.
fn menu_theme() -> dialoguer::theme::ColorfulTheme {
    use dialoguer::console::{Style, style};
    // 256-color approximations of the brand palette (style.rs uses RGB via
    // crossterm; console's 256-level keeps wide terminal compatibility):
    // 202 ≈ accent orange #ff6118, 220 ≈ gold #ffcf5e, 197 ≈ flame red.
    let orange = Style::new().color256(202).bold();
    dialoguer::theme::ColorfulTheme {
        prompt_prefix: style("🔥".to_string()),
        success_prefix: style("✓".to_string()).color256(220).bold(),
        active_item_prefix: style("❯ ".to_string()).color256(202).bold(),
        inactive_item_prefix: style("  ".to_string()),
        checked_item_prefix: style("[🔥]".to_string()).color256(220),
        unchecked_item_prefix: style("[  ]".to_string()).dim(),
        active_item_style: orange,
        ..dialoguer::theme::ColorfulTheme::default()
    }
}

/// Whether we can run an interactive picker.
fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Resolve which hosts to act on: explicit `--host` flags win; otherwise an
/// interactive multi-select (with `preselect`ed rows checked); otherwise -
/// non-tty or `--yes` - exactly the preselected set.
fn resolve_hosts(
    explicit: &[String],
    yes: bool,
    prompt: &str,
    preselect: impl Fn(&hosts::HostSpec) -> bool,
) -> Result<Vec<&'static str>> {
    if !explicit.is_empty() {
        return validate_hosts(explicit);
    }
    let detected: Vec<bool> = hosts::HOSTS.iter().map(&preselect).collect();
    if yes || !interactive() {
        let picked: Vec<&'static str> = hosts::HOSTS
            .iter()
            .zip(&detected)
            .filter(|(_, d)| **d)
            .map(|(h, _)| h.key)
            .collect();
        if picked.is_empty() {
            bail!(
                "no assistant detected; target one explicitly: burn agent install --host <{}>",
                hosts::HOSTS
                    .iter()
                    .map(|h| h.key)
                    .collect::<Vec<_>>()
                    .join("|")
            );
        }
        return Ok(picked);
    }
    let items: Vec<String> = hosts::HOSTS
        .iter()
        .zip(&detected)
        .map(|(h, d)| {
            if *d {
                format!("{}  (detected)", h.label)
            } else {
                format!("{}  (not detected - config will be created)", h.label)
            }
        })
        .collect();
    let picks = dialoguer::MultiSelect::with_theme(&menu_theme())
        .with_prompt(prompt)
        .items(&items)
        .defaults(&detected)
        .report(false)
        .interact_opt()?;
    let Some(picks) = picks else {
        bail!("cancelled - nothing changed");
    };
    if picks.is_empty() {
        bail!("nothing selected - nothing changed");
    }
    Ok(picks.into_iter().map(|i| hosts::HOSTS[i].key).collect())
}

/// `burn agent install` - wire hooks + instruction blocks.
fn install(explicit: &[String], user: bool, yes: bool) -> Result<()> {
    println!("{}", style::flame("burn agent"));
    println!(
        "{}",
        style::muted(
            "Route every JavaScript run through the sealed sandbox. Space toggles, Enter confirms."
        )
    );
    let picked = resolve_hosts(explicit, yes, "Wire which assistants?", |h| {
        hosts::is_installed(h)
    })?;
    let mut wired = Vec::new();
    for key in &picked {
        let label = hosts::spec(key).map_or(*key, |h| h.label);
        match hosts::wire_host(key, user) {
            Ok(msg) => {
                println!("  {}", paint_status(&msg));
                if let Some(ctx) = context::install_context(key, user)? {
                    println!("  {}", paint_status(&ctx));
                }
                wired.push(label);
            }
            Err(e) => println!("  {}", style::fail(&format!("{key}: {e}"))),
        }
    }
    if !wired.is_empty() {
        println!();
        println!(
            "{} now run JavaScript inside burn.",
            style::ok(&wired.join(", "))
        );
        println!(
            "{}",
            style::muted("Undo anytime: burn agent uninstall · one-off bypass: BURN_AGENT_HOOK=0")
        );
    }
    Ok(())
}

/// `burn agent uninstall` - remove hooks + instruction blocks.
fn uninstall(explicit: &[String], all: bool, user: bool, yes: bool) -> Result<()> {
    let picked = if all {
        hosts::HOSTS.iter().map(|h| h.key).collect()
    } else {
        resolve_hosts(explicit, yes, "Unwire which assistants?", |h| {
            hosts::status_host(h.key, user).wired
        })?
    };
    for key in &picked {
        match hosts::unwire_host(key, user) {
            Ok(msg) => {
                println!("  {}", paint_status(&msg));
                if let Some(ctx) = context::remove_context(key, user)? {
                    println!("  {}", paint_status(&ctx));
                }
            }
            Err(e) => println!("  {}", style::fail(&format!("{key}: {e}"))),
        }
    }
    println!();
    println!("{}", style::ok("sandbox routing removed."));
    Ok(())
}

/// `burn agent status` - inspect without touching.
fn status() -> Result<()> {
    println!("{}", style::flame("burn agent status"));
    if hook::disabled_path().exists() {
        println!(
            "  {}",
            style::warn("redirect DISABLED globally (burn agent enable to resume)")
        );
    }
    for h in hosts::HOSTS {
        let s = hosts::status_host(h.key, true);
        let detected = if s.detected {
            style::ok("detected")
        } else {
            style::muted("not found")
        };
        let wired = if s.stale {
            style::warn("wired (stale path - rerun: burn agent install)")
        } else if s.wired {
            style::ok("wired")
        } else {
            style::muted("not wired")
        };
        let ctx = if context::context_present(h.key, true) {
            style::ok("instructions")
        } else {
            style::muted("no instructions")
        };
        println!(
            "  {:<16} {detected}  ·  {wired}  ·  {ctx}",
            style::accent(h.label)
        );
    }
    Ok(())
}

/// Color a writer status line by its leading sigil (`+` wired, `-`
/// removed, `=` no-op, `!` attention).
fn paint_status(msg: &str) -> String {
    match msg.as_bytes().first() {
        Some(b'+') => style::ok(msg),
        Some(b'-') => style::gold(msg),
        Some(b'!') => style::warn(msg),
        _ => style::muted(msg),
    }
}
