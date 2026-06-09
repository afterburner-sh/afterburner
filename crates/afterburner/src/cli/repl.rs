// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn repl` — interactive REPL.
//!
//! Meta-commands:
//!
//! * `:fuel N` — set the per-call fuel cap.
//! * `:mode native|wasm|adaptive` — rebuild the engine in a given mode.
//! * `:allow net=*`, `:allow fs=/tmp`, `:allow env=HOME` — grant
//!   capabilities on the live engine (rebuilds the manifold).
//! * `:help` — list commands. `:exit` / `:quit` — exit.
//!
//! Scripts run in UDF shape (`module.exports = () => ...` or plain
//! expressions — the latter are wrapped). No state shared across
//! lines; matches the fresh-per-call invariant.

use crate::Afterburner;
use anyhow::{Context, Result};
use serde_json::Value;

use super::args::Cli;
use super::build::build_afterburner;

// rustyline helper: colors the prompt via the Highlighter so rustyline still
// measures width on the plain prompt (no `\x01`/`\x02` width markers).
struct ReplHelper;
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
        match super::style::highlight_prompt(prompt) {
            Some(s) => std::borrow::Cow::Owned(s),
            None => std::borrow::Cow::Borrowed(prompt),
        }
    }
}
impl rustyline::Helper for ReplHelper {}

pub fn repl(cli: &Cli) -> Result<()> {
    use rustyline::Editor;
    use rustyline::error::ReadlineError;
    use rustyline::history::FileHistory;

    let mut rl: Editor<ReplHelper, FileHistory> = Editor::new().context("rustyline init")?;
    rl.set_helper(Some(ReplHelper));
    let mut live_cli = cli.clone();
    let mut ab = build_afterburner(&live_cli)?;

    super::style::repl_banner(env!("CARGO_PKG_VERSION"));
    loop {
        match rl.readline("burn> ") {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);

                if let Some(rest) = trimmed.strip_prefix(':') {
                    match dispatch_meta(rest, &mut live_cli, &mut ab) {
                        Ok(ReplAction::Continue) => continue,
                        Ok(ReplAction::Exit) => break,
                        Err(e) => {
                            eprintln!("  {}", super::style::fail(&e.to_string()));
                            continue;
                        }
                    }
                }

                // Evaluate as script. We wrap so a naked expression
                // gets its value back (not via module.exports).
                let wrapped = wrap_repl_line(trimmed);
                match ab
                    .register(&wrapped)
                    .and_then(|id| ab.run(&id, &Value::Null))
                {
                    Ok(v) => {
                        if !v.is_null() {
                            println!(
                                "{}",
                                super::style::value(&serde_json::to_string(&v).unwrap_or_default())
                            );
                        }
                    }
                    Err(e) => eprintln!("  {}", super::style::fail(&e.to_string())),
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("  {}", super::style::fail(&format!("readline error: {e}")));
                break;
            }
        }
    }
    Ok(())
}

enum ReplAction {
    Continue,
    Exit,
}

fn dispatch_meta(rest: &str, cli: &mut Cli, ab: &mut Afterburner) -> Result<ReplAction> {
    let (cmd, arg) = match rest.split_once(char::is_whitespace) {
        Some((c, a)) => (c, a.trim()),
        None => (rest, ""),
    };
    match cmd {
        "help" | "?" => {
            for (cmd, desc) in [
                (":fuel N", "set the per-call fuel cap"),
                (":mode native|wasm|adaptive", "rebuild the engine in a mode"),
                (":allow net=*|host,list", "grant outbound HTTP"),
                (":allow fs=*|/path,list", "grant filesystem access"),
                (":allow env=*|VAR,list", "grant env-var access"),
                (":exit | :quit", "leave the REPL"),
            ] {
                eprintln!(
                    "  {} {}",
                    super::style::accent(&format!("{cmd:<28}")),
                    super::style::muted(desc)
                );
            }
        }
        "fuel" => {
            let n: u64 = arg.parse().context("parse fuel")?;
            cli.fuel = Some(n);
            *ab = build_afterburner(cli)?;
            eprintln!("  {}", super::style::ok(&format!("fuel = {n}")));
        }
        "mode" => {
            cli.mode = Some(arg.to_string());
            *ab = build_afterburner(cli)?;
            eprintln!("  {}", super::style::ok(&format!("mode = {arg}")));
        }
        "allow" => {
            let (k, v) = arg.split_once('=').context(":allow expects key=value")?;
            match k.trim() {
                "net" => cli.allow_net = Some(v.to_string()),
                "fs" => cli.allow_fs = Some(v.to_string()),
                "env" => cli.allow_env = Some(v.to_string()),
                "all" => cli.allow_all = true,
                other => anyhow::bail!("unknown capability '{other}' (expected: net|fs|env|all)"),
            }
            *ab = build_afterburner(cli)?;
            eprintln!("  {}", super::style::ok(&format!("{k} = {v}")));
        }
        "exit" | "quit" => return Ok(ReplAction::Exit),
        other => anyhow::bail!("unknown command :{other} — try :help"),
    }
    Ok(ReplAction::Continue)
}

/// Wrap a raw REPL line into a module-exports shape so naked
/// expressions yield their value back to the user.
///
/// Two cases:
///
/// * **Expressions** (`1 + 1`, `Math.sqrt(16)`, `[1,2,3].map(x=>x*2)`):
///   wrapped as `module.exports = () => (LINE);` — the parens
///   force expression position, the arrow returns the value.
///
/// * **Statements** (`var a = 32;`, `let x = ...`, `function f(){}`,
///   `if (...) ...`, etc.): can't sit inside parens (syntax error).
///   Wrapped as a body block: `() => { LINE; return undefined; }`.
///   Statements don't have a value; user sees `undefined` in the
///   output (and any side effects on `globalThis` if relevant —
///   though state doesn't persist across lines per the
///   fresh-per-call invariant).
///
/// Detection is a static prefix check on the trimmed line. Covers
/// the practical REPL inputs; false positives (e.g., a bare
/// identifier `var` used as a variable name in some hypothetical
/// dialect) would only mis-classify, not crash.
pub(super) fn wrap_repl_line(line: &str) -> String {
    if line.contains("module.exports") {
        return line.to_string();
    }
    if is_statement(line) {
        format!("module.exports = () => {{ {line}; return undefined; }};\n")
    } else {
        format!("module.exports = () => ({line});\n")
    }
}

/// Heuristic: does this line look like a statement that can't be
/// wrapped in parens? Checks for the leading keyword. Multi-line
/// pasted statements are the common REPL case; one keyword is
/// enough to disambiguate.
fn is_statement(line: &str) -> bool {
    // Trim leading whitespace; the keyword has to be the very
    // first token.
    let trimmed = line.trim_start();
    const KEYWORDS: &[&str] = &[
        "var ",
        "var\t",
        "let ",
        "let\t",
        "const ",
        "const\t",
        "function ",
        "function\t",
        "function(",
        "class ",
        "class\t",
        "class{",
        "if ",
        "if(",
        "if\t",
        "for ",
        "for(",
        "for\t",
        "while ",
        "while(",
        "while\t",
        "do ",
        "do{",
        "do\t",
        "try ",
        "try{",
        "try\t",
        "switch ",
        "switch(",
        "switch\t",
        "return ",
        "return;",
        "return\t",
        "throw ",
        "throw\t",
        "break;",
        "break\n",
        "break\t",
        "continue;",
        "continue\n",
        "continue\t",
        "import ",
        "import\t",
        "export ",
        "export\t",
        "{", // bare block / object-literal-in-statement context
    ];
    KEYWORDS.iter().any(|k| trimmed.starts_with(k)) || trimmed == "break" || trimmed == "continue"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_expression_uses_parens() {
        assert!(wrap_repl_line("1 + 1").contains("(1 + 1)"));
        assert!(wrap_repl_line("Math.sqrt(16)").contains("(Math.sqrt(16))"));
    }

    #[test]
    fn wrap_var_statement_uses_block() {
        let w = wrap_repl_line("var a = 32;");
        assert!(w.contains("{ var a = 32;"));
        assert!(w.contains("return undefined"));
    }

    #[test]
    fn wrap_let_statement_uses_block() {
        let w = wrap_repl_line("let x = [1, 2, 3];");
        assert!(w.contains("{ let x = [1, 2, 3];"));
    }

    #[test]
    fn wrap_const_statement_uses_block() {
        let w = wrap_repl_line("const k = 42;");
        assert!(w.contains("{ const k = 42;"));
    }

    #[test]
    fn wrap_function_decl_uses_block() {
        let w = wrap_repl_line("function f() { return 1; }");
        assert!(w.contains("{ function f"));
    }

    #[test]
    fn wrap_if_statement_uses_block() {
        let w = wrap_repl_line("if (true) console.log('hi');");
        assert!(w.contains("{ if (true)"));
    }

    #[test]
    fn wrap_module_exports_passthrough() {
        let w = wrap_repl_line("module.exports = () => 42");
        assert_eq!(w, "module.exports = () => 42");
    }
}
