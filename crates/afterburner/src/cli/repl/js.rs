// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The JavaScript / TypeScript REPL backend.
//!
//! Each line becomes a fresh script run through the engine. Session state
//! persists by replaying the accumulated `var`/`let`/`const`/`function`/`class`
//! declarations before the current line (the engine runs each line isolated).
//!
//! With `transpile_ts = true` (`burn repl --lang ts`) each line is stripped of
//! TypeScript types via oxc before it is run as JavaScript.
//!
//! Meta-commands:
//!
//! * `:fuel N` - set the per-call fuel cap.
//! * `:mode native|wasm|adaptive` - rebuild the engine in a given mode.
//! * `:allow net=*`, `:allow fs=/tmp`, `:allow env=HOME` - grant
//!   capabilities on the live engine (rebuilds the manifold).
//! * `:clear` / `:reset` - forget all session declarations.
//! * `:help` - list commands. `:exit` / `:quit` - exit.

use crate::Afterburner;
use crate::cli::build::build_afterburner;
use crate::cli::style;
use anyhow::{Context, Result};
use serde_json::Value;
use std::cell::RefCell;

use super::super::args::Cli;
use super::{Flow, clean_repl_err, read_loop};

/// Run the JS (or TS) engine REPL. `transpile_ts` strips TypeScript types from
/// each line before evaluation.
pub fn run(cli: &Cli, transpile_ts: bool) -> Result<()> {
    // The live engine and session state are owned here and mutated by the
    // per-line closure. `RefCell` because `read_loop` takes an `FnMut` that
    // borrows them across calls; this is single-threaded REPL state.
    let live_cli = RefCell::new(cli.clone());
    let ab = RefCell::new(build_afterburner(&live_cli.borrow())?);
    // Accumulated declarations (var/let/const/function/class) so REPL state
    // persists across lines - the engine runs each line isolated.
    let decls: RefCell<Vec<(String, String)>> = RefCell::new(Vec::new());

    let lang = if transpile_ts { "ts" } else { "js" };
    style::repl_banner_lang(env!("CARGO_PKG_VERSION"), lang);

    read_loop("burn", |trimmed| {
        if let Some(rest) = trimmed.strip_prefix(':') {
            if matches!(rest.trim(), "clear" | "reset") {
                decls.borrow_mut().clear();
                eprintln!("  {}", style::muted("session cleared"));
                return Flow::Continue;
            }
            match dispatch_meta(rest, &mut live_cli.borrow_mut(), &mut ab.borrow_mut()) {
                Ok(Flow::Exit) => return Flow::Exit,
                Ok(Flow::Continue) => return Flow::Continue,
                Err(e) => {
                    eprintln!("  {}", style::fail(&clean_repl_err(&e.to_string())));
                    return Flow::Continue;
                }
            }
        }

        // For TS, strip types from the raw line first so the engine sees plain
        // JS. A transpile error is reported and the line is dropped.
        let prepared = if transpile_ts {
            match transpile_ts_line(trimmed) {
                Ok(js) => {
                    // A line that is purely TypeScript types (an `interface` /
                    // `type` alias) strips to nothing: it is a no-op, not an
                    // empty expression. Acknowledge and move on.
                    if js.trim().is_empty() {
                        eprintln!("  {}", style::muted("(type-only; nothing to run)"));
                        return Flow::Continue;
                    }
                    js
                }
                Err(e) => {
                    eprintln!("  {}", style::fail(&clean_repl_err(&e.to_string())));
                    return Flow::Continue;
                }
            }
        } else {
            trimmed.to_string()
        };

        // Evaluate the line against the accumulated session so vars and
        // functions defined earlier are in scope.
        let wrapped = build_eval(&decls.borrow(), &prepared);
        let result = {
            let ab = ab.borrow();
            ab.register(&wrapped)
                .and_then(|id| ab.run(&id, &Value::Null))
        };
        match result {
            Ok(v) => {
                // A successful declaration joins the session (latest wins). We
                // record the prepared (post-TS-strip) text so replay is plain JS.
                if let Some(name) = declared_name(&prepared) {
                    let mut d = decls.borrow_mut();
                    d.retain(|(n, _)| n != &name);
                    d.push((name, prepared.trim().to_string()));
                }
                if !v.is_null() {
                    println!(
                        "{}",
                        style::value(&serde_json::to_string(&v).unwrap_or_default())
                    );
                }
            }
            Err(e) => eprintln!("  {}", style::fail(&clean_repl_err(&e.to_string()))),
        }
        Flow::Continue
    })
}

/// Strip TypeScript types from a single REPL line, returning plain JS.
///
/// The oxc transpiler operates on whole modules, so a bare expression like
/// `1 as number` is parsed as a statement (which is fine: we take the stripped
/// output). ESM lowering is applied too (a no-op for plain expressions).
#[cfg(feature = "ts")]
fn transpile_ts_line(line: &str) -> Result<String> {
    let path = std::path::Path::new("<repl>.ts");
    // No inline source map: the line is wrapped in an expression position where
    // a trailing `//# sourceMappingURL=` comment would break the wrap.
    crate::ts::transpile_no_source_map(line, path)
        .map(|js| js.trim_end().to_string())
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Without the `ts` feature, `--lang ts` cannot strip types: honest error.
#[cfg(not(feature = "ts"))]
fn transpile_ts_line(_line: &str) -> Result<String> {
    anyhow::bail!(
        "burn: TypeScript REPL requires the `ts` cargo feature \
         (rebuild with `cargo install afterburner --features ts`)"
    )
}

fn dispatch_meta(rest: &str, cli: &mut Cli, ab: &mut Afterburner) -> Result<Flow> {
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
                    style::accent(&format!("{cmd:<28}")),
                    style::muted(desc)
                );
            }
        }
        "fuel" => {
            let n: u64 = arg.parse().context("parse fuel")?;
            cli.fuel = Some(n);
            *ab = build_afterburner(cli)?;
            eprintln!("  {}", style::ok(&format!("fuel = {n}")));
        }
        "mode" => {
            cli.mode = Some(arg.to_string());
            *ab = build_afterburner(cli)?;
            eprintln!("  {}", style::ok(&format!("mode = {arg}")));
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
            eprintln!("  {}", style::ok(&format!("{k} = {v}")));
        }
        "exit" | "quit" => return Ok(Flow::Exit),
        other => anyhow::bail!("unknown command :{other}, try :help"),
    }
    Ok(Flow::Continue)
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
        // Strip a trailing semicolon so `1 + 1;` wraps as `return (1 + 1)`,
        // not `return (1 + 1;)` (a syntax error).
        let expr = line.trim_end().trim_end_matches(';').trim_end();
        body.push_str("return (");
        body.push_str(expr);
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
    fn trailing_semicolon_on_expression_is_stripped() {
        let w = build_eval(&[], "1 + 1;");
        assert!(w.contains("return (1 + 1)"));
        assert!(!w.contains("1 + 1;)"));
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

    #[cfg(feature = "ts")]
    #[test]
    fn ts_line_strips_type_annotations() {
        // `const x: number = 1` -> the `: number` annotation is removed.
        let js = transpile_ts_line("const x: number = 1").unwrap();
        assert!(js.contains("const x = 1"), "stripped TS types: {js}");
        assert!(!js.contains(": number"), "annotation gone: {js}");
    }

    #[cfg(feature = "ts")]
    #[test]
    fn ts_expression_with_cast_strips_to_plain_js() {
        // `1 as number` -> `1`.
        let js = transpile_ts_line("1 as number").unwrap();
        assert!(js.contains('1'), "keeps the value: {js}");
        assert!(!js.contains("as number"), "cast removed: {js}");
    }
}
