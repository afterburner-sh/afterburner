// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The Python REPL backend, over the Pyodide (CPython-WASI) runtime.
//!
//! The runtime runs `python -c <source>` on a freshly booted CPython per call
//! and does not carry interpreter state across boots. To present a stateful
//! REPL on top of that, the session accumulates the lines entered so far and
//! re-runs the whole accumulated program each line. Because each step extends
//! the program by exactly the new line, the prior run's stdout is a prefix of
//! the new run's stdout, so only the new suffix is shown.
//!
//! That makes assignments and `def`/`import` persist across lines for free.
//! A bare expression prints via an injected `print(repr(...))` wrapper
//! (mirroring the interactive interpreter echoing a value); because that echo
//! adds bytes the next baseline must not count, an echoed expression runs the
//! committed program a second time to re-measure the baseline. The per-line
//! cost is therefore one CPython boot for a statement, two when echoing a value.
//!
//! Limitation (honest): the committed lines are replayed each line, so a line
//! whose output is non-deterministic across runs (unseeded `random`, a clock
//! read, network) can mis-slice the shown suffix. Pure compute - the REPL's
//! common case - is exact.
//!
//! Requires `BURN_PYTHON_RUNTIME=<dir>` (containing `pyodide-exnref.wasm` and
//! `python_stdlib.zip`). When unset or the `wasm` feature is absent, the REPL
//! prints a clear, actionable error and returns - never a fake prompt.

use crate::cli::style;
use anyhow::Result;

use super::super::args::Cli;

/// The substring an integration test can match to LOUD-SKIP honestly when the
/// Python runtime is not configured (never a silent green).
pub const PY_RUNTIME_MISSING_MARKER: &str = "python runtime not found";

/// Run the Python line REPL. Returns an actionable error (carrying
/// [`PY_RUNTIME_MISSING_MARKER`]) when the runtime is unavailable.
#[cfg(feature = "wasm")]
pub fn run(_cli: &Cli) -> Result<()> {
    use super::{Flow, read_loop};
    use std::cell::RefCell;

    let runtime = locate_runtime()?;
    style::repl_banner_lang(env!("CARGO_PKG_VERSION"), "python");
    eprintln!(
        "  {}",
        style::muted(
            "each line re-runs the session (one CPython boot per line; two when echoing a value)"
        )
    );

    // The committed session lines (each replayed as a plain statement so its
    // side effects persist), and the byte length of the stdout the committed
    // plain program produces. That plain output is a strict prefix of any
    // display run (which only appends the current line on top), so the new
    // line's output is the suffix past `baseline`.
    let session: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let baseline: RefCell<usize> = RefCell::new(0);

    read_loop("py", |trimmed| {
        if let Some(rest) = trimmed.strip_prefix(':') {
            match rest.trim() {
                "clear" | "reset" => {
                    session.borrow_mut().clear();
                    *baseline.borrow_mut() = 0;
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

        let is_expr = looks_like_expression(trimmed);
        // Display program: committed lines (plain) + the current line, echoed
        // when it is a bare expression so its value shows.
        let display = build_program(&session.borrow(), trimmed, is_expr);
        let prev = *baseline.borrow();
        match run_program(&runtime, &display) {
            Ok(stdout) => {
                let suffix = if stdout.len() >= prev {
                    &stdout[prev..]
                } else {
                    // Non-monotonic (a non-deterministic replayed line): show the
                    // whole output rather than panic-slicing.
                    &stdout[..]
                };
                if !suffix.is_empty() {
                    print!("{suffix}");
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                // Commit the line and advance the baseline to the committed
                // PLAIN output. For a statement the display program already is
                // the plain program, so reuse its length (no extra boot); for an
                // echoed expression, run the plain program once to measure it
                // (the echo's repr output must not poison the next baseline).
                session.borrow_mut().push(trimmed.to_string());
                let new_baseline = if is_expr {
                    let plain = build_program(&session.borrow(), "", false);
                    run_program(&runtime, &plain)
                        .map(|s| s.len())
                        .unwrap_or(stdout.len())
                } else {
                    stdout.len()
                };
                *baseline.borrow_mut() = new_baseline;
            }
            Err(e) => {
                // A failed line does NOT join the session (so the next line is
                // not poisoned by a broken statement). The baseline is unchanged.
                eprintln!("  {}", style::fail(&clean_py_err(&e.to_string())));
            }
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

/// A located Python runtime: the absolute paths to the two artifacts the
/// embedder needs.
#[cfg(feature = "wasm")]
struct Runtime {
    wasm_path: String,
    stdlib_path: String,
}

/// Locate the Pyodide runtime from `BURN_PYTHON_RUNTIME`, verifying the wasm
/// payload exists. Returns an error carrying [`PY_RUNTIME_MISSING_MARKER`] when
/// the variable is unset or the file is absent.
#[cfg(feature = "wasm")]
fn locate_runtime() -> Result<Runtime> {
    let dir = std::env::var("BURN_PYTHON_RUNTIME").map_err(|_| {
        anyhow::anyhow!(
            "{PY_RUNTIME_MISSING_MARKER}; set BURN_PYTHON_RUNTIME=<dir> where <dir> \
             contains pyodide-exnref.wasm and python_stdlib.zip"
        )
    })?;
    let wasm_path = format!("{dir}/pyodide-exnref.wasm");
    let stdlib_path = format!("{dir}/python_stdlib.zip");
    if !std::path::Path::new(&wasm_path).exists() {
        anyhow::bail!(
            "{PY_RUNTIME_MISSING_MARKER}; {wasm_path} does not exist. \
             Set BURN_PYTHON_RUNTIME to a directory containing pyodide-exnref.wasm \
             and python_stdlib.zip"
        );
    }
    Ok(Runtime {
        wasm_path,
        stdlib_path,
    })
}

/// Run an accumulated Python program and return its stdout as a String.
#[cfg(feature = "wasm")]
fn run_program(rt: &Runtime, program: &str) -> Result<String> {
    use afterburner_wasi::pyodide_runner::run_pyodide_source;
    let out = run_pyodide_source(&rt.wasm_path, &rt.stdlib_path, program)
        .map_err(|e| anyhow::anyhow!("python runtime error: {e}"))?;
    // A non-zero exit means the program raised; surface its stderr-shaped
    // output (CPython writes tracebacks to stdout under `-c` here) as an error.
    if out.exit_code != 0 {
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        anyhow::bail!("{}", text.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Build the program to run: the committed session lines (each as a plain
/// statement so its side effects persist), then the current `line`. When
/// `echo` is true the current line is wrapped in `print(repr(...))` so its
/// value shows (the interactive-interpreter feel); otherwise it runs as-is.
///
/// An empty `line` builds the committed-plain program (no current line), used
/// to measure the baseline output after an echoed expression is committed.
fn build_program(session: &[String], line: &str, echo: bool) -> String {
    let mut out = String::new();
    for prior in session {
        out.push_str(prior);
        out.push('\n');
    }
    let line = line.trim();
    if line.is_empty() {
        return out;
    }
    if echo {
        // Echo the value like the interactive interpreter. `repr` so strings
        // show quoted; `None` (e.g. a bare `print(...)` call slipped through)
        // is suppressed to avoid a stray `None`.
        out.push_str("__burn_v = (");
        out.push_str(line);
        out.push_str(")\nif __burn_v is not None:\n    print(repr(__burn_v))\n");
    } else {
        out.push_str(line);
        out.push('\n');
    }
    out
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
        let p = build_program(&[], "1 + 1", true);
        assert!(p.contains("__burn_v = (1 + 1)"), "got: {p}");
        assert!(p.contains("print(repr(__burn_v))"), "echoes value: {p}");
    }

    #[test]
    fn assignment_is_a_statement_not_echoed() {
        let p = build_program(&[], "x = 5", false);
        assert!(p.contains("x = 5"), "got: {p}");
        assert!(!p.contains("__burn_v"), "assignment is not echoed: {p}");
    }

    #[test]
    fn empty_current_line_yields_committed_plain_program() {
        // Baseline measurement: prior lines only, no echo wrapper, no new line.
        let session = vec!["x = 1".to_string(), "print(x)".to_string()];
        let p = build_program(&session, "", false);
        assert!(p.contains("x = 1"), "prior assignment present: {p}");
        assert!(p.contains("print(x)"), "prior call present: {p}");
        assert!(!p.contains("__burn_v"), "no echo wrapper: {p}");
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

    #[test]
    fn prior_session_lines_precede_the_current_line() {
        let session = vec!["x = 10".to_string()];
        let p = build_program(&session, "x * 2", true);
        let x_at = p.find("x = 10").expect("session line present");
        let expr_at = p.find("x * 2").expect("current line present");
        assert!(x_at < expr_at, "session replays before the line: {p}");
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn clean_py_err_keeps_the_exception_line() {
        let raw = "Traceback (most recent call last):\n  File \"<stdin>\"\nNameError: name 'z' is not defined";
        assert_eq!(clean_py_err(raw), "NameError: name 'z' is not defined");
    }
}
