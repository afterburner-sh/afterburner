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
    // Accumulated declarations (var/let/const/function/class) so REPL state
    // persists across lines — the engine runs each line isolated.
    let mut decls: Vec<(String, String)> = Vec::new();

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
                    if matches!(rest.trim(), "clear" | "reset") {
                        decls.clear();
                        eprintln!("  {}", super::style::muted("session cleared"));
                        continue;
                    }
                    match dispatch_meta(rest, &mut live_cli, &mut ab) {
                        Ok(ReplAction::Continue) => continue,
                        Ok(ReplAction::Exit) => break,
                        Err(e) => {
                            eprintln!("  {}", super::style::fail(&clean_repl_err(&e.to_string())));
                            continue;
                        }
                    }
                }

                // Evaluate the line against the accumulated session so vars and
                // functions defined earlier are in scope.
                let wrapped = build_eval(&decls, trimmed);
                match ab
                    .register(&wrapped)
                    .and_then(|id| ab.run(&id, &Value::Null))
                {
                    Ok(v) => {
                        // A successful declaration joins the session (latest wins).
                        if let Some(name) = declared_name(trimmed) {
                            decls.retain(|(n, _)| n != &name);
                            decls.push((name, trimmed.to_string()));
                        }
                        if !v.is_null() {
                            println!(
                                "{}",
                                super::style::value(&serde_json::to_string(&v).unwrap_or_default())
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("  {}", super::style::fail(&clean_repl_err(&e.to_string())))
                    }
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

fn clean_repl_err(raw: &str) -> String {
    let s = super::style::humanize_error(raw);
    s.strip_prefix("compile failed: ").unwrap_or(&s).to_string()
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
                (":clear", "forget all session declarations"),
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

/// Build the eval wrapper for a REPL line, replaying the session's accumulated
/// declarations first so earlier state is in scope. Expressions are returned
/// (their value is shown); statements run for their effect.
fn build_eval(decls: &[(String, String)], line: &str) -> String {
    if line.contains("module.exports") {
        return format!("{line}\n");
    }
    let mut body = String::new();
    for (_, d) in decls {
        body.push_str(d);
        body.push('\n');
    }
    if is_statement(line) {
        body.push_str(line);
        body.push_str("\nreturn undefined;");
    } else {
        body.push_str("return (");
        body.push_str(line);
        body.push_str(");");
    }
    format!("module.exports = () => {{\n{body}\n}};\n")
}

/// The identifier a `var`/`let`/`const`/`function`/`class` line declares.
fn declared_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    for kw in [
        "async function ",
        "function*",
        "function ",
        "class ",
        "const ",
        "let ",
        "var ",
    ] {
        if let Some(rest) = t.strip_prefix(kw) {
            let name: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
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
    fn expression_is_returned() {
        assert!(build_eval(&[], "1 + 1").contains("return (1 + 1)"));
    }

    #[test]
    fn statement_runs_for_effect() {
        let w = build_eval(&[], "var a = 32;");
        assert!(w.contains("var a = 32;"));
        assert!(w.contains("return undefined"));
    }

    #[test]
    fn session_declarations_are_replayed() {
        let decls = vec![("a".to_string(), "var a = 3;".to_string())];
        let w = build_eval(&decls, "a");
        assert!(w.contains("var a = 3;"));
        assert!(w.contains("return (a)"));
    }

    #[test]
    fn module_exports_passes_through() {
        assert_eq!(
            build_eval(&[], "module.exports = () => 42"),
            "module.exports = () => 42\n"
        );
    }

    #[test]
    fn declared_name_extracts_identifier() {
        assert_eq!(declared_name("var a = 3;").as_deref(), Some("a"));
        assert_eq!(declared_name("let foo = 1").as_deref(), Some("foo"));
        assert_eq!(declared_name("const K = 2").as_deref(), Some("K"));
        assert_eq!(declared_name("function bar() {}").as_deref(), Some("bar"));
        assert_eq!(declared_name("class Widget {}").as_deref(), Some("Widget"));
        assert_eq!(declared_name("a + 1"), None);
        assert_eq!(declared_name("console.log(a)"), None);
    }
}
