// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The Ruby REPL backend, over the bundled ruby.wasm (CRuby-WASI) runtime.
//!
//! The runtime runs `ruby -e <source>` on a freshly booted CRuby per call and
//! does not carry interpreter state across boots. To present a stateful REPL on
//! top of that, the session accumulates the lines entered so far and re-runs
//! the whole accumulated program each line. Because each step extends the
//! program by exactly the new line, the prior run's stdout is a prefix of the
//! new run's stdout, so only the new suffix is shown.
//!
//! That makes assignments and `def`/`require` persist across lines for free.
//! Unlike Python, every Ruby construct is an expression, so the REPL uniformly
//! echoes the current line's value via `p (...)` (Ruby's `inspect`), matching
//! IRB's `=> value` feel: `x = 5` echoes `5`, `def f; end` echoes `:f`, a bare
//! `puts` (which returns `nil`) echoes nothing extra because the echo is
//! suppressed for `nil`. Because that echo adds bytes the next baseline must
//! not count, an echoed line runs the committed program a second time to
//! re-measure the baseline. The per-line cost is therefore one CRuby boot for a
//! value-less line, two when echoing a value.
//!
//! Limitation (honest): the committed lines are replayed each line, so a line
//! whose output is non-deterministic across runs (a clock read, `rand` without
//! a seed) can mis-slice the shown suffix. Pure compute - the REPL's common
//! case - is exact.
//!
//! Uses the self-contained ruby.wasm runtime by default (the bundle the build
//! script assembles), so the REPL needs no configuration; `BURN_RUBY_RUNTIME`
//! still overrides it. When no runtime is available (no bundle and no override)
//! or the `wasm` feature is absent, the REPL prints a clear, actionable error
//! and returns - never a fake prompt.

use anyhow::Result;

use crate::cli::style;

/// Run the Ruby line REPL. Returns an actionable error (its message contains
/// "ruby runtime not found", the substring the integration test matches to
/// LOUD-SKIP honestly when no runtime was assembled - never a silent green)
/// when no runtime is available.
#[cfg(feature = "wasm")]
pub fn run() -> Result<()> {
    use super::{Flow, read_loop};
    use std::cell::RefCell;

    let runtime = afterburner_wasi::ruby_runner::resolve_ruby_runtime()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    style::repl_banner_lang(env!("CARGO_PKG_VERSION"), "ruby");
    eprintln!(
        "  {}",
        style::muted(
            "each line re-runs the session (one CRuby boot per line; two when echoing a value)"
        )
    );

    // The committed session lines (each replayed as a plain statement so its
    // side effects persist), and the byte length of the stdout the committed
    // plain program produces. That plain output is a strict prefix of any
    // display run (which only appends the current line on top), so the new
    // line's output is the suffix past `baseline`.
    let session: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let baseline: RefCell<usize> = RefCell::new(0);

    read_loop("rb", |trimmed| {
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

        // Display program: committed lines (plain) + the current line, echoed so
        // its value shows (IRB-style). Every Ruby construct is an expression, so
        // the echo is uniform (no statement-vs-expression heuristic needed).
        let display = build_program(&session.borrow(), trimmed, true);
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
                // PLAIN output (no echo wrapper), so the echo's bytes do not
                // poison the next line's baseline. Always one extra boot since
                // every committed line is echoed.
                session.borrow_mut().push(trimmed.to_string());
                let plain = build_program(&session.borrow(), "", false);
                let new_baseline = run_program(&runtime, &plain)
                    .map(|s| s.len())
                    .unwrap_or(stdout.len());
                *baseline.borrow_mut() = new_baseline;
            }
            Err(e) => {
                // A failed line does NOT join the session (so the next line is
                // not poisoned by a broken statement). The baseline is unchanged.
                eprintln!("  {}", style::fail(&clean_rb_err(&e.to_string())));
            }
        }
        Flow::Continue
    })
}

/// Ruby REPL when the `wasm` feature is absent: honest, actionable error.
#[cfg(not(feature = "wasm"))]
pub fn run() -> Result<()> {
    let _ = style::muted("");
    anyhow::bail!("Ruby REPL requires the `wasm` cargo feature (rebuild with `--features wasm`).")
}

/// Run an accumulated Ruby program and return its stdout as a String.
#[cfg(feature = "wasm")]
fn run_program(rt: &afterburner_wasi::ruby_runner::RubyRuntime, program: &str) -> Result<String> {
    use afterburner_wasi::ruby_runner::run_ruby_with;
    let out = run_ruby_with(rt, program).map_err(|e| anyhow::anyhow!("ruby runtime error: {e}"))?;
    // A non-zero exit means the program raised; surface CRuby's stderr (the
    // exception / syntax error) as the REPL error line, falling back to stdout
    // if stderr is empty.
    if out.exit_code != 0 {
        let err = String::from_utf8_lossy(&out.stderr);
        let text = if err.trim().is_empty() {
            String::from_utf8_lossy(&out.stdout).into_owned()
        } else {
            err.into_owned()
        };
        anyhow::bail!("{}", text.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Build the program to run: the committed session lines (each as a plain
/// statement so its side effects persist), then the current `line`. When
/// `echo` is true the current line is wrapped so its value is printed via
/// `p` (Ruby's `inspect`, the IRB `=> value` feel); `nil` is suppressed so a
/// bare `puts` does not echo a stray `nil`.
///
/// An empty `line` builds the committed-plain program (no current line), used
/// to measure the baseline output after an echoed line is committed.
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
        // Echo the value like IRB. `__burn_v = (<line>)` captures the value;
        // `p __burn_v unless __burn_v.nil?` inspects it unless it is nil (a
        // bare `puts`/`print` returns nil, so it does not double-print).
        out.push_str("__burn_v = (");
        out.push_str(line);
        out.push_str(")\np(__burn_v) unless __burn_v.nil?\n");
    } else {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Strip CRuby's `-e:LINE: ` location prefix and the trailing exception-class
/// framing into a compact one-line error for the REPL. CRuby writes errors as
/// `-e:1:in '<main>': undefined ... (NameError)`; the useful part is the
/// message, so we keep the last non-empty line and drop the `-e:N:` prefix.
#[cfg(feature = "wasm")]
fn clean_rb_err(raw: &str) -> String {
    let trimmed = raw.trim();
    let last = trimmed
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or(trimmed)
        .trim();
    // Drop a leading `-e:<n>:` (and `-e:<n>:in '...':`) source locator.
    let after_loc = last
        .strip_prefix("-e:")
        .and_then(|s| s.split_once(": ").map(|(_, rest)| rest))
        .unwrap_or(last);
    after_loc.trim().to_string()
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
    fn line_is_wrapped_to_echo_its_value() {
        let p = build_program(&[], "1 + 1", true);
        assert!(p.contains("__burn_v = (1 + 1)"), "got: {p}");
        assert!(
            p.contains("p(__burn_v) unless __burn_v.nil?"),
            "echoes: {p}"
        );
    }

    #[test]
    fn plain_line_is_not_echoed() {
        let p = build_program(&[], "x = 5", false);
        assert!(p.contains("x = 5"), "got: {p}");
        assert!(!p.contains("__burn_v"), "plain build has no echo: {p}");
    }

    #[test]
    fn empty_current_line_yields_committed_plain_program() {
        let session = vec!["x = 1".to_string(), "puts x".to_string()];
        let p = build_program(&session, "", false);
        assert!(p.contains("x = 1"), "prior assignment present: {p}");
        assert!(p.contains("puts x"), "prior call present: {p}");
        assert!(!p.contains("__burn_v"), "no echo wrapper: {p}");
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
    fn clean_rb_err_keeps_the_message_and_drops_the_locator() {
        let raw = "-e:1:in '<main>': undefined local variable or method 'z' (NameError)";
        let cleaned = clean_rb_err(raw);
        assert!(
            cleaned.contains("undefined local variable"),
            "keeps the message: {cleaned}"
        );
        assert!(
            !cleaned.starts_with("-e:"),
            "drops the -e: locator: {cleaned}"
        );
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn clean_rb_err_handles_a_plain_message() {
        // A message without the `-e:N:` prefix passes through (last line kept).
        let raw = "some error\nSyntaxError: unexpected end";
        assert_eq!(clean_rb_err(raw), "SyntaxError: unexpected end");
    }
}
