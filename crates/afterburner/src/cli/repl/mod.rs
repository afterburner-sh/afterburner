// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn repl --lang <L>` - an interactive REPL for every supported language.
//!
//! One dispatcher, eight backends:
//!
//! * `js` / `javascript` - the JavaScript engine REPL ([`js`]). Each line is
//!   wrapped as a UDF and run; `var`/`let`/`const`/`function`/`class`
//!   declarations are replayed across lines so session state persists.
//! * `ts` / `typescript` - the same engine REPL with each line transpiled
//!   from TypeScript to JavaScript first (strip-types via oxc).
//! * `rust` / `go` / `c` / `cpp` - a compile-and-run-per-line REPL ([`compiled`],
//!   evcxr-style): the session's declarations are accumulated, the current
//!   line is wrapped in an entry point, the whole program is compiled to
//!   `wasm32-wasip1` via the existing compile drivers and run via the existing
//!   embedder. Honest about the per-line compile cost and the toolchain each
//!   language needs (a missing toolchain is a clear error, never a crash).
//! * `python` / `py` - a line REPL over the Pyodide runtime ([`python`]).
//! * `ruby` / `rb` - an honest pending state ([`ruby`]) until the ruby.wasm
//!   payload is bundled.
//!
//! Shared meta-commands (where the backend supports them): `:clear`/`:reset`
//! forget the session, `:help`/`:?` list commands, `:exit`/`:quit` leave.

mod compiled;
mod js;
mod python;
mod ruby;

use crate::cli::compile::lang::SourceLang;
use anyhow::Result;
use std::str::FromStr;

use super::args::Cli;

/// Entry point for `burn repl --lang <L>` (and bare `burn`, which routes here
/// with `lang = "js"`). Normalizes the language string and dispatches to the
/// matching backend. An unknown language is a clear error listing the
/// supported identifiers (via [`SourceLang::from_str`]).
pub fn repl(cli: &Cli, lang: &str) -> Result<()> {
    let lang = SourceLang::from_str(lang)?;
    match lang {
        SourceLang::Js => js::run(cli, false),
        SourceLang::Ts => js::run(cli, true),
        SourceLang::Rust | SourceLang::Go | SourceLang::C | SourceLang::Cpp => {
            compiled::run(cli, lang)
        }
        SourceLang::Python => python::run(cli),
        SourceLang::Ruby => ruby::run(),
    }
}

// ---- shared rustyline scaffolding -------------------------------------------

/// rustyline helper: colors the prompt via the Highlighter so rustyline still
/// measures width on the plain prompt (no `\x01`/`\x02` width markers). Shared
/// by every line-based REPL backend.
pub(super) struct ReplHelper;
impl rustyline::completion::Completer for ReplHelper {
    type Candidate = String;
}
impl rustyline::hint::Hinter for ReplHelper {
    type Hint = String;
}
impl rustyline::validate::Validator for ReplHelper {}
impl rustyline::highlight::Highlighter for ReplHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> std::borrow::Cow<'b, str> {
        match crate::cli::style::highlight_prompt(prompt) {
            Some(s) => std::borrow::Cow::Owned(s),
            None => std::borrow::Cow::Borrowed(prompt),
        }
    }
}
impl rustyline::Helper for ReplHelper {}

/// What a backend's per-line handler asks the shared loop to do next.
pub(super) enum Flow {
    /// Keep reading lines.
    Continue,
    /// Leave the REPL.
    Exit,
}

/// Run the shared rustyline read loop, handing each non-empty line to
/// `on_line`. The prompt is `{prompt}> `. Common concerns (history, the
/// editor, Ctrl-C / EOF exit, readline errors) live here so each backend only
/// implements its line handler. The banner is the caller's responsibility (it
/// is language-specific).
pub(super) fn read_loop<F>(prompt: &str, mut on_line: F) -> Result<()>
where
    F: FnMut(&str) -> Flow,
{
    use anyhow::Context;
    use rustyline::Editor;
    use rustyline::error::ReadlineError;
    use rustyline::history::FileHistory;

    let mut rl: Editor<ReplHelper, FileHistory> = Editor::new().context("rustyline init")?;
    rl.set_helper(Some(ReplHelper));
    let prompt = format!("{prompt}> ");
    loop {
        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);
                match on_line(trimmed) {
                    Flow::Continue => continue,
                    Flow::Exit => break,
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!(
                    "  {}",
                    crate::cli::style::fail(&format!("readline error: {e}"))
                );
                break;
            }
        }
    }
    Ok(())
}

/// Strip the engine's internal `compile failed:` prefix and humanize the rest,
/// for a clean one-line REPL error. Shared by the JS/TS backend.
pub(super) fn clean_repl_err(raw: &str) -> String {
    let s = crate::cli::style::humanize_error(raw);
    s.strip_prefix("compile failed: ").unwrap_or(&s).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_rejects_unknown_language() {
        // An unknown language is rejected at the `SourceLang::from_str` gate,
        // before any backend runs (so this never opens an interactive loop).
        use clap::Parser;
        let cli = Cli::parse_from(["burn"]);
        let err = repl(&cli, "haskell").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("haskell"), "must name the bad lang: {msg}");
    }

    #[test]
    fn clean_repl_err_strips_compile_prefix() {
        let out = clean_repl_err("compile failed: SyntaxError: bad");
        assert!(!out.starts_with("compile failed:"), "got: {out}");
        assert!(out.contains("SyntaxError"), "keeps the detail: {out}");
    }
}
