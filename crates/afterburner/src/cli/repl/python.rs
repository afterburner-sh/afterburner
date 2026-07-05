// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The Python REPL backend, over the Pyodide (CPython-WASI) runtime.
//!
//! The session boots + warms ONE CPython interpreter up front (via
//! [`WarmPyInterpreter`](afterburner_wasi::pyodide_runner::WarmPyInterpreter))
//! and runs every line on it through `PyRun_SimpleString` in a PERSISTENT
//! namespace. So assignments and `def`/`import` persist across lines for free
//! (they live in the interpreter), and each line costs ~ms instead of a fresh
//! ~490 ms CPython boot. No session replay, no output slicing: a line's stdout
//! is exactly that line's output. `:clear` drops the persistent namespace.
//!
//! A bare expression prints via an injected `print(repr(...))` wrapper
//! (mirroring the interactive interpreter echoing a value); a statement runs
//! as-is. A raised line routes its traceback to stderr and does not corrupt the
//! namespace (a failed statement simply leaves its binding unmade).
//!
//! Uses the self-contained Pyodide runtime by default (the bundle the build
//! script assembles), so the REPL needs no configuration; `BURN_PYTHON_RUNTIME`
//! still overrides it. When no runtime is available (no bundle and no override)
//! or the `wasm` feature is absent, the REPL prints a clear, actionable error
//! and returns - never a fake prompt.

use crate::cli::style;
use anyhow::Result;

use super::super::args::Cli;

/// Run the Python line REPL. Returns an actionable error (its message contains
/// "python runtime not found") when no runtime is available.
#[cfg(feature = "wasm")]
pub fn run(_cli: &Cli) -> Result<()> {
    use super::{Flow, read_loop};
    use afterburner_wasi::pyodide_runner::WarmPyInterpreter;
    use std::io::Write;

    style::repl_banner_lang(env!("CARGO_PKG_VERSION"), "python");
    eprintln!(
        "  {}",
        style::muted("warming a persistent CPython interpreter (state carries across lines)...")
    );
    // Boot + warm ONE interpreter for the whole session (#53): pay the ~490 ms
    // CPython bringup once here, then each line runs on it in ~ms. State lives in
    // the interpreter's persistent namespace, so there is no per-line boot and no
    // session replay - a name bound on one line is simply present on the next.
    let mut interp = WarmPyInterpreter::boot_resolved().map_err(|e| anyhow::anyhow!("{e}"))?;

    read_loop("py", move |trimmed| {
        if let Some(rest) = trimmed.strip_prefix(':') {
            match rest.trim() {
                "clear" | "reset" => {
                    let _ = interp.reset_persistent();
                    eprintln!("  {}", style::muted("session cleared"));
                }
                "help" | "?" => print_help(),
                "exit" | "quit" => return Flow::Exit,
                other => eprintln!(
                    "  {}",
                    style::fail(&format!("unknown command :{other}, try :help"))
                ),
            }
            return Flow::Continue;
        }

        // Run ONLY the current line on the warm interpreter, echoed to print its
        // value when it is a bare expression. No session accumulation, no output
        // slicing: the line's stdout IS the line's output.
        let is_expr = looks_like_expression(trimmed);
        let program = build_program(trimmed, is_expr);
        match interp.run_persistent(&program) {
            Ok(out) => {
                // A raised program routes its traceback to stderr (exit_code 0 on
                // the warm path); a clean run leaves stderr empty.
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.trim().is_empty() {
                    eprintln!("  {}", style::fail(&clean_py_err(&err)));
                } else {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    if !stdout.is_empty() {
                        print!("{stdout}");
                        let _ = std::io::stdout().flush();
                    }
                }
            }
            Err(e) => eprintln!("  {}", style::fail(&clean_py_err(&e.to_string()))),
        }
        Flow::Continue
    })
}

/// Python REPL when the `wasm` feature is absent: honest, actionable error.
#[cfg(not(feature = "wasm"))]
pub fn run(_cli: &Cli) -> Result<()> {
    let _ = style::muted("");
    anyhow::bail!("Python REPL requires the `wasm` cargo feature (rebuild with `--features wasm`).")
}

/// Build the program to run for one REPL line: the `line` itself, wrapped in
/// `print(repr(...))` when `echo` is true so a bare expression shows its value
/// (the interactive-interpreter feel); otherwise the line runs as-is. State
/// persists in the warm interpreter's namespace, so no prior lines are replayed.
fn build_program(line: &str, echo: bool) -> String {
    let line = line.trim();
    if line.is_empty() {
        return String::new();
    }
    if echo {
        // Echo the value like the interactive interpreter. `repr` so strings
        // show quoted; `None` (e.g. a bare `print(...)` call slipped through) is
        // suppressed to avoid a stray `None`.
        format!("__burn_v = ({line})\nif __burn_v is not None:\n    print(repr(__burn_v))\n")
    } else {
        format!("{line}\n")
    }
}

/// Heuristic: is this line a bare expression to be echoed, rather than a
/// statement run for effect? Mirrors the JS backend's split. Anything starting
/// with a binding/flow/definition keyword (or that is an assignment) is a
/// statement; everything else is treated as an expression.
fn looks_like_expression(line: &str) -> bool {
    let t = line.trim_start();
    if t.is_empty() {
        return false;
    }
    // Leading statement keywords (followed by a space, so `print(...)` - a
    // call, an expression - is NOT caught by `print`, and `import x` is).
    const STMT_KW: &[&str] = &[
        "import ",
        "from ",
        "def ",
        "class ",
        "if ",
        "elif ",
        "else",
        "for ",
        "while ",
        "with ",
        "try",
        "except",
        "finally",
        "return",
        "raise ",
        "pass",
        "break",
        "continue",
        "global ",
        "nonlocal ",
        "assert ",
        "del ",
        "yield",
        "async ",
        "await ",
        "@",
    ];
    if STMT_KW.iter().any(|kw| t.starts_with(kw)) {
        return false;
    }
    // An assignment (`x = ...`, `x += ...`) is a statement, but `==`/`!=`/`<=`/
    // `>=` are comparison expressions. Detect a top-level single `=` that is
    // not part of a comparison operator.
    if is_top_level_assignment(t) {
        return false;
    }
    true
}

/// Detect a top-level assignment: a `=` (or augmented `+=`, `-=`, ...) that is
/// not a `==`/`!=`/`<=`/`>=` comparison and is not nested in brackets. Good
/// enough for the REPL's one-line inputs; bracket-nesting guards against
/// `f(a=1)` (a call, an expression).
fn is_top_level_assignment(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'=' if depth == 0 => {
                let prev = if i > 0 { bytes[i - 1] } else { b' ' };
                let next = if i + 1 < bytes.len() {
                    bytes[i + 1]
                } else {
                    b' '
                };
                // `==` is comparison; `!=`,`<=`,`>=` end in `=` with a relational
                // char before. An augmented op (`+=` etc.) ends in `=` too and IS
                // an assignment, so only exclude the comparison forms.
                let is_comparison = next == b'=' || matches!(prev, b'=' | b'!' | b'<' | b'>');
                if !is_comparison {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Strip CPython's leading `Traceback (most recent call last):` framing into a
/// compact one-line error for the REPL (the final exception line is the useful
/// part).
#[cfg(feature = "wasm")]
fn clean_py_err(raw: &str) -> String {
    let trimmed = raw.trim();
    // The last non-empty line of a traceback is the exception type + message.
    trimmed
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

#[cfg(feature = "wasm")]
fn print_help() {
    for (cmd, desc) in [
        (":clear", "forget the session"),
        (":help", "show commands"),
        (":exit | :quit", "leave the REPL"),
    ] {
        eprintln!(
            "  {} {}",
            style::accent(&format!("{cmd:<16}")),
            style::muted(desc)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expression_is_wrapped_to_echo_its_value() {
        let p = build_program("1 + 1", true);
        assert!(p.contains("__burn_v = (1 + 1)"), "got: {p}");
        assert!(p.contains("print(repr(__burn_v))"), "echoes value: {p}");
    }

    #[test]
    fn assignment_is_a_statement_not_echoed() {
        let p = build_program("x = 5", false);
        assert!(p.contains("x = 5"), "got: {p}");
        assert!(!p.contains("__burn_v"), "assignment is not echoed: {p}");
    }

    #[test]
    fn empty_line_yields_empty_program() {
        assert!(build_program("", false).is_empty());
        assert!(build_program("   ", true).is_empty());
    }

    #[test]
    fn def_is_a_statement() {
        assert!(!looks_like_expression("def f(): return 1"));
        assert!(!looks_like_expression("import os"));
        assert!(!looks_like_expression("from os import path"));
        assert!(!looks_like_expression("for i in range(3): pass"));
    }

    #[test]
    fn call_and_arithmetic_are_expressions() {
        assert!(looks_like_expression("print('hi')"));
        assert!(looks_like_expression("len([1,2,3])"));
        assert!(looks_like_expression("2 ** 10"));
        assert!(looks_like_expression("x == 5"));
        assert!(looks_like_expression("x <= 5"));
    }

    #[test]
    fn keyword_arg_call_is_expression_not_assignment() {
        // `f(a=1)` is a call (expression), not a top-level assignment.
        assert!(!is_top_level_assignment("f(a=1)"));
        assert!(looks_like_expression("sorted([3,1], key=abs)"));
    }

    #[test]
    fn augmented_assignment_is_statement() {
        assert!(is_top_level_assignment("x += 1"));
        assert!(!looks_like_expression("x += 1"));
    }

    #[test]
    fn comparison_is_not_assignment() {
        assert!(!is_top_level_assignment("a == b"));
        assert!(!is_top_level_assignment("a != b"));
        assert!(!is_top_level_assignment("a >= b"));
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn clean_py_err_keeps_the_exception_line() {
        let raw = "Traceback (most recent call last):\n  File \"<stdin>\"\nNameError: name 'z' is not defined";
        assert_eq!(clean_py_err(raw), "NameError: name 'z' is not defined");
    }
}
