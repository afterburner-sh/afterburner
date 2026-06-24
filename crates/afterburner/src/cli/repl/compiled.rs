// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! The compile-and-run REPL backend for the native languages (Rust, Go, C,
//! C++) - an evcxr-style loop.
//!
//! There is no source interpreter for these languages, so each line is run by
//! compiling a whole program. The session is split into two accumulators:
//!
//! * **items** - top-level declarations (`use`/`fn`/`struct`/`impl` in Rust,
//!   imports and top-level `func`/`type`/`var` in Go, `#include`/functions in
//!   C/C++). Kept at module scope, never re-printed.
//! * **body** - statements run inside the entry point (`main`). Replayed in
//!   order each line so earlier side effects and bindings are in scope.
//!
//! A bare expression on the current line is echoed where the language has a
//! generic print (Rust: `println!("{:?}", _)`, Go: `fmt.Printf("%v\n", _)`);
//! C and C++ have no generic value print, so there an expression is run as a
//! statement and the user prints explicitly (`printf` / `std::cout`). This is
//! the honest limit, stated in the banner.
//!
//! Each line recompiles the whole program (the honest, unavoidable cost of a
//! compiled REPL - announced in the banner). The compile uses the EXISTING
//! single-file drivers ([`compile_single_file`]); nothing is reimplemented
//! here. A missing toolchain (no `cargo`/`go`, no `wasm32-wasip1` target, no
//! wasi-sdk) is a clear, actionable error, never a crash. Because the body is
//! append-only, the prior run's stdout is a prefix of the new run's, so only
//! the new suffix is shown.

use crate::cli::compile::lang::SourceLang;
use crate::cli::style;
use anyhow::Result;

use super::super::args::Cli;

/// Run the compiled REPL for `lang` (one of Rust / Go / C / C++).
#[cfg(feature = "wasm")]
pub fn run(_cli: &Cli, lang: SourceLang) -> Result<()> {
    use super::{Flow, read_loop};
    use std::cell::RefCell;

    let spec = LangSpec::of(lang)?;
    style::repl_banner_lang(env!("CARGO_PKG_VERSION"), spec.short);
    eprintln!(
        "  {}",
        style::muted("each line recompiles the whole program (compiled-REPL cost)")
    );
    if !spec.echoes_expressions {
        eprintln!(
            "  {}",
            style::muted(&format!(
                "{}: expressions are not auto-printed; print explicitly",
                spec.short
            ))
        );
    }

    let session = RefCell::new(Session::default());
    let last_out_len = RefCell::new(0usize);

    read_loop(spec.short, |trimmed| {
        if let Some(rest) = trimmed.strip_prefix(':') {
            match rest.trim() {
                "clear" | "reset" => {
                    *session.borrow_mut() = Session::default();
                    *last_out_len.borrow_mut() = 0;
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

        // Classify and tentatively fold the line into the session, render the
        // full program, and compile+run it.
        let kind = spec.classify(trimmed);

        // Some item lines produce no output and do not compile in isolation
        // (a Go `import` is "imported and not used" until a later line uses
        // it). Commit them without a compile; they take effect on first use.
        if spec.defer_compile(trimmed) {
            session.borrow_mut().commit(trimmed.to_string(), kind);
            eprintln!("  {}", style::muted("(recorded; takes effect on next use)"));
            return Flow::Continue;
        }

        let program = spec.render(&session.borrow(), trimmed, kind);
        match compile_and_run(&spec, &program) {
            Ok(stdout) => {
                let prev = *last_out_len.borrow();
                // The retained program (items + body) deterministically produces
                // the first `prev` bytes; everything after is this line's new
                // output (a statement's prints, or an expression's echo).
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
                // The line compiled and ran: commit it to the session. Only a
                // RETAINED line (item/stmt) advances the output baseline; an
                // expression is echo-only, so the next program reverts to the
                // current retained output and the baseline must stay at `prev`.
                session.borrow_mut().commit(trimmed.to_string(), kind);
                if kind != LineKind::Expr {
                    *last_out_len.borrow_mut() = stdout.len();
                }
            }
            Err(e) => {
                // A failed line does not join the session. The baseline output
                // length is unchanged (the last good program still defines it).
                eprintln!("  {}", style::fail(&e.to_string()));
            }
        }
        Flow::Continue
    })
}

/// Compiled REPL when the `wasm` feature is absent: honest error.
#[cfg(not(feature = "wasm"))]
pub fn run(_cli: &Cli, _lang: SourceLang) -> Result<()> {
    let _ = style::muted("");
    anyhow::bail!(
        "the compiled-language REPL requires the `wasm` cargo feature \
         (rebuild with `--features wasm`)."
    )
}

/// Compile the rendered program to `wasm32-wasip1` via the existing single-file
/// driver and run it through the embedder, returning captured stdout.
///
/// Toolchain-absence errors from the driver are passed through verbatim (they
/// already carry the actionable remediation, e.g. `rustup target add
/// wasm32-wasip1` or "wasi-sdk not found").
#[cfg(feature = "wasm")]
fn compile_and_run(spec: &LangSpec, program: &str) -> Result<String> {
    use crate::cli::compile::lang::compile_single_file;
    use afterburner_wasi::embedder_vm::{EmbedderVm, WasiCommandOpts};
    use anyhow::Context;

    // Write the program to a uniquely-named temp file with the right extension
    // so the driver picks the right language, then clean it up.
    let path = std::env::temp_dir().join(format!(
        "burn-repl-{}-{}.{}",
        spec.short,
        next_unique(),
        spec.ext
    ));
    std::fs::write(&path, program).with_context(|| format!("writing {}", path.display()))?;

    let wasm_bytes = compile_single_file(&path);
    let _ = std::fs::remove_file(&path);
    let wasm_bytes = wasm_bytes?;

    let vm = EmbedderVm::new().context("creating EmbedderVm")?;
    let module = vm
        .compile(&wasm_bytes, true, |_| Ok(()))
        .context("compiling WASM module")?;
    let opts = WasiCommandOpts::new().args(["burn-repl"]);
    let out = vm
        .run_command(&module, opts, None)
        .context("running WASM command")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A process-unique counter so concurrent or rapid temp files never collide.
#[cfg(feature = "wasm")]
fn next_unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let seq = N.fetch_add(1, Ordering::Relaxed);
    // Mix in the pid so two processes' temp files do not collide either.
    ((std::process::id() as u64) << 24) ^ seq
}

// ---- session model ----------------------------------------------------------

/// How a REPL line participates in the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind {
    /// A top-level declaration kept at module scope (e.g. `fn`, `use`,
    /// `#include`, Go `import`).
    Item,
    /// A statement run inside the entry point, replayed each line.
    Stmt,
    /// A bare expression echoed via the language's generic print (or, where
    /// there is none, run as a statement).
    Expr,
}

/// The accumulated REPL session: module-scope items and entry-body statements.
#[derive(Default)]
struct Session {
    items: Vec<String>,
    body: Vec<String>,
}

impl Session {
    /// Fold a successfully-run line into the session by its kind. Expressions
    /// are not retained in the body (they only echo a value; retaining them
    /// would re-print every prior expression each line).
    fn commit(&mut self, line: String, kind: LineKind) {
        match kind {
            LineKind::Item => self.items.push(line),
            LineKind::Stmt => self.body.push(line),
            LineKind::Expr => { /* echo-only; not retained */ }
        }
    }
}

// ---- per-language program rendering -----------------------------------------

/// Per-language knobs for the compiled REPL: the source extension, the short
/// id, whether bare expressions can be auto-echoed, and the language-specific
/// classify/render hooks.
struct LangSpec {
    lang: SourceLang,
    short: &'static str,
    ext: &'static str,
    echoes_expressions: bool,
}

impl LangSpec {
    fn of(lang: SourceLang) -> Result<Self> {
        Ok(match lang {
            SourceLang::Rust => Self {
                lang,
                short: "rust",
                ext: "rs",
                echoes_expressions: true,
            },
            SourceLang::Go => Self {
                lang,
                short: "go",
                ext: "go",
                echoes_expressions: true,
            },
            SourceLang::C => Self {
                lang,
                short: "c",
                ext: "c",
                echoes_expressions: false,
            },
            SourceLang::Cpp => Self {
                lang,
                short: "cpp",
                ext: "cpp",
                echoes_expressions: false,
            },
            other => anyhow::bail!("compiled REPL does not handle {other:?} (bug)"),
        })
    }

    /// Whether this line should be recorded into the session WITHOUT an
    /// immediate compile (it has no output and would not compile in isolation).
    /// Only Go `import` lines qualify: Go rejects an imported-and-unused
    /// package, so the import is deferred until a later line references it.
    fn defer_compile(&self, line: &str) -> bool {
        matches!(self.lang, SourceLang::Go) && line.trim().starts_with("import ")
    }

    /// Classify a line as item / statement / expression for this language.
    fn classify(&self, line: &str) -> LineKind {
        match self.lang {
            SourceLang::Rust => classify_rust(line),
            SourceLang::Go => classify_go(line),
            SourceLang::C | SourceLang::Cpp => classify_c(line, self.echoes_expressions),
            _ => LineKind::Stmt,
        }
    }

    /// Render the full source program for a new `line` of the given `kind`,
    /// given the prior `session`.
    fn render(&self, session: &Session, line: &str, kind: LineKind) -> String {
        match self.lang {
            SourceLang::Rust => render_rust(session, line, kind),
            SourceLang::Go => render_go(session, line, kind),
            SourceLang::C => render_c(session, line, kind, false),
            SourceLang::Cpp => render_c(session, line, kind, true),
            _ => String::new(),
        }
    }
}

// -- Rust --

/// Classify a Rust REPL line. Items are the keyword-led top-level declarations;
/// a trailing `;` (or a leading statement keyword like `let`) marks a statement;
/// everything else is an expression to echo.
fn classify_rust(line: &str) -> LineKind {
    let t = line.trim();
    const ITEM_KW: &[&str] = &[
        "use ",
        "fn ",
        "struct ",
        "enum ",
        "trait ",
        "impl ",
        "mod ",
        "const ",
        "static ",
        "type ",
        "pub ",
        "macro_rules!",
        "#[",
        "extern ",
        "union ",
    ];
    if ITEM_KW.iter().any(|kw| t.starts_with(kw)) {
        return LineKind::Item;
    }
    if t.starts_with("let ") || t.ends_with(';') || t.ends_with('}') {
        return LineKind::Stmt;
    }
    LineKind::Expr
}

fn render_rust(session: &Session, line: &str, kind: LineKind) -> String {
    // Replayed bindings are "unused", defined-but-not-yet-called fns are "dead
    // code": expected in a REPL. Silence the lints at the source so rustc's
    // warning chatter does not leak into the session output (real errors still
    // surface and fail the compile).
    let mut out = String::from("#![allow(warnings)]\n");
    for item in &session.items {
        out.push_str(item);
        out.push('\n');
    }
    if kind == LineKind::Item {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("fn main() {\n");
    for stmt in &session.body {
        out.push_str("    ");
        out.push_str(stmt);
        out.push('\n');
    }
    match kind {
        LineKind::Stmt => {
            out.push_str("    ");
            out.push_str(line);
            out.push('\n');
        }
        LineKind::Expr => {
            // Echo via Debug so most values print without a Display bound.
            out.push_str("    println!(\"{:?}\", {");
            out.push_str(line.trim().trim_end_matches(';'));
            out.push_str("});\n");
        }
        LineKind::Item => {}
    }
    out.push_str("}\n");
    out
}

// -- Go --

/// Classify a Go REPL line. `import`/`func`/`type`/top-level `var`/`const` are
/// items; a `:=` short-var-decl, a trailing `;`/`}`, or a statement-shaped call
/// (`fmt.Print*`, `print`/`println`, which return values that cannot be echoed)
/// is a statement; the rest is an expression.
fn classify_go(line: &str) -> LineKind {
    let t = line.trim();
    const ITEM_KW: &[&str] = &["import ", "import(", "func ", "type ", "var ", "const "];
    if ITEM_KW.iter().any(|kw| t.starts_with(kw)) {
        return LineKind::Item;
    }
    // Calls whose result must not be wrapped in `fmt.Printf("%v\n", ...)`:
    // `fmt.Print*` return `(int, error)` (a multi-value context error), and
    // the builtins `print`/`println` return nothing.
    const STMT_CALL: &[&str] = &["fmt.Print", "println(", "print(", "panic(", "log."];
    if STMT_CALL.iter().any(|p| t.starts_with(p)) {
        return LineKind::Stmt;
    }
    if t.contains(":=") || t.ends_with(';') || t.ends_with('}') {
        return LineKind::Stmt;
    }
    LineKind::Expr
}

/// Collect the names introduced by a Go `name := ...` (or `a, b := ...`)
/// short-variable-declaration line. Used to emit `_ = name` so Go's
/// "declared and not used" never fires on a replayed REPL binding.
fn go_short_var_names(line: &str) -> Vec<String> {
    let t = line.trim();
    let Some(idx) = t.find(":=") else {
        return Vec::new();
    };
    t[..idx]
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty() && *n != "_")
        // A valid Go identifier (best-effort: starts with a letter/underscore).
        .filter(|n| {
            n.chars()
                .next()
                .is_some_and(|c| c.is_alphabetic() || c == '_')
                && n.chars().all(|c| c.is_alphanumeric() || c == '_')
        })
        .map(str::to_string)
        .collect()
}

fn render_go(session: &Session, line: &str, kind: LineKind) -> String {
    // All item lines: the session's, plus the current line when it is an item.
    // `String` (not `&str`) so the quoted-import slice has no borrow trouble.
    let mut imports: Vec<String> = Vec::new();
    let mut other_items: Vec<String> = Vec::new();
    let all_items = session
        .items
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(line).filter(|_| kind == LineKind::Item));
    for s in all_items {
        let st = s.trim();
        if let Some(path) = st.strip_prefix("import ") {
            // `import "fmt"` -> the quoted path (everything from the first `"`).
            if let Some(idx) = path.find('"') {
                imports.push(path[idx..].to_string());
                continue;
            }
        }
        other_items.push(s.to_string());
    }

    let mut out = String::from("package main\n\n");
    // fmt is always imported so expression echo (`fmt.Printf`) and the common
    // case work; duplicate user `import "fmt"` is de-duplicated below.
    out.push_str("import (\n\t\"fmt\"\n");
    for imp in &imports {
        let p = imp.trim();
        if p != "\"fmt\"" {
            out.push('\t');
            out.push_str(p);
            out.push('\n');
        }
    }
    out.push_str(")\n\n");
    // `_ = fmt.Sprint` keeps fmt "used" even if no statement references it.
    out.push_str("var _ = fmt.Sprint\n\n");
    for it in &other_items {
        out.push_str(it.trim());
        out.push('\n');
    }
    out.push_str("\nfunc main() {\n");
    // Names declared with `:=` in the body, so we can mark them used (Go errors
    // on an unused variable). The current line's names are included when it is a
    // statement that joins the body.
    let mut declared: Vec<String> = Vec::new();
    for stmt in &session.body {
        out.push('\t');
        out.push_str(stmt.trim());
        out.push('\n');
        declared.extend(go_short_var_names(stmt));
    }
    match kind {
        LineKind::Stmt => {
            out.push('\t');
            out.push_str(line.trim());
            out.push('\n');
            declared.extend(go_short_var_names(line));
        }
        LineKind::Expr => {
            out.push_str("\tfmt.Printf(\"%v\\n\", ");
            out.push_str(line.trim());
            out.push_str(")\n");
        }
        LineKind::Item => {}
    }
    // `_ = name` for every `:=`-declared name keeps Go from rejecting a binding
    // that is only used by a later line. Harmless when the name is also used.
    for name in &declared {
        out.push_str("\t_ = ");
        out.push_str(name);
        out.push('\n');
    }
    out.push_str("}\n");
    out
}

// -- C / C++ --

/// Classify a C/C++ REPL line. `#include`/`#define`/preprocessor and lines that
/// look like a top-level function or struct definition are items; everything
/// else is a statement (C/C++ have no generic expression echo, so even a bare
/// expression is run as a statement: `echo_expr` is false for these).
fn classify_c(line: &str, _echo_expr: bool) -> LineKind {
    let t = line.trim();
    if t.starts_with('#') {
        return LineKind::Item;
    }
    // A top-level definition ending in `{` or `}` (a function/struct body) is an
    // item; a `struct`/`typedef`/`enum` declaration likewise.
    const ITEM_KW: &[&str] = &["typedef ", "struct ", "enum ", "union "];
    if (t.ends_with('{') || t.ends_with('}'))
        && !t.starts_with("for")
        && !t.starts_with("while")
        && !t.starts_with("if")
        && !t.starts_with('}')
    {
        return LineKind::Item;
    }
    if ITEM_KW.iter().any(|kw| t.starts_with(kw)) {
        return LineKind::Item;
    }
    LineKind::Stmt
}

fn render_c(session: &Session, line: &str, kind: LineKind, is_cpp: bool) -> String {
    let mut out = String::new();
    // Default headers so the common case works without ceremony.
    if is_cpp {
        out.push_str("#include <cstdio>\n#include <iostream>\n");
    } else {
        out.push_str("#include <stdio.h>\n#include <stdlib.h>\n");
    }
    for item in &session.items {
        out.push_str(item);
        out.push('\n');
    }
    if kind == LineKind::Item {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("int main(void) {\n");
    for stmt in &session.body {
        out.push_str("    ");
        out.push_str(stmt);
        out.push('\n');
    }
    if kind == LineKind::Stmt || kind == LineKind::Expr {
        out.push_str("    ");
        out.push_str(line.trim());
        // Add a trailing semicolon if the user omitted it on a bare expression.
        if !line.trim().ends_with(';') && !line.trim().ends_with('}') {
            out.push(';');
        }
        out.push('\n');
    }
    out.push_str("    return 0;\n}\n");
    out
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

    fn sess(items: &[&str], body: &[&str]) -> Session {
        Session {
            items: items.iter().map(|s| s.to_string()).collect(),
            body: body.iter().map(|s| s.to_string()).collect(),
        }
    }

    // -- Rust --

    #[test]
    fn rust_classify() {
        assert_eq!(classify_rust("fn add(a: i32) -> i32 { a }"), LineKind::Item);
        assert_eq!(classify_rust("use std::fmt;"), LineKind::Item);
        assert_eq!(classify_rust("struct P { x: i32 }"), LineKind::Item);
        assert_eq!(classify_rust("let x = 5;"), LineKind::Stmt);
        assert_eq!(classify_rust("println!(\"hi\");"), LineKind::Stmt);
        assert_eq!(classify_rust("1 + 1"), LineKind::Expr);
        assert_eq!(classify_rust("add(2, 3)"), LineKind::Expr);
    }

    #[test]
    fn rust_renders_expression_echo_with_debug() {
        let p = render_rust(&Session::default(), "1 + 2", LineKind::Expr);
        assert!(p.contains("fn main()"), "has entry: {p}");
        assert!(
            p.contains("println!(\"{:?}\", {1 + 2})"),
            "echoes via Debug: {p}"
        );
    }

    #[test]
    fn rust_item_goes_to_module_scope_not_main() {
        let p = render_rust(&Session::default(), "fn f() -> i32 { 7 }", LineKind::Item);
        let item_at = p.find("fn f()").unwrap();
        let main_at = p.find("fn main()").unwrap();
        assert!(item_at < main_at, "item before main: {p}");
    }

    #[test]
    fn rust_replays_body_statements_in_main() {
        let s = sess(&[], &["let x = 10;"]);
        let p = render_rust(&s, "x + 1", LineKind::Expr);
        let let_at = p.find("let x = 10;").unwrap();
        let echo_at = p.find("{x + 1}").unwrap();
        assert!(let_at < echo_at, "prior let replays before echo: {p}");
    }

    // -- Go --

    #[test]
    fn go_classify() {
        assert_eq!(classify_go("import \"fmt\""), LineKind::Item);
        assert_eq!(
            classify_go("func add(a int) int { return a }"),
            LineKind::Item
        );
        assert_eq!(classify_go("type P struct{ X int }"), LineKind::Item);
        assert_eq!(classify_go("x := 5"), LineKind::Stmt);
        assert_eq!(classify_go("1 + 1"), LineKind::Expr);
    }

    #[test]
    fn go_always_imports_fmt_and_dedups_user_fmt() {
        let s = sess(&["import \"fmt\""], &[]);
        let p = render_go(&s, "2 * 21", LineKind::Expr);
        // Exactly one `"fmt"` in the import block.
        assert_eq!(p.matches("\"fmt\"").count(), 1, "fmt de-duplicated: {p}");
        assert!(p.contains("fmt.Printf(\"%v\\n\", 2 * 21)"), "echo: {p}");
    }

    #[test]
    fn go_user_import_is_added_to_block() {
        let s = sess(&["import \"strings\""], &[]);
        let p = render_go(&s, "strings.ToUpper(\"hi\")", LineKind::Expr);
        assert!(p.contains("\"strings\""), "user import present: {p}");
        assert!(p.contains("\"fmt\""), "fmt still present: {p}");
    }

    #[test]
    fn go_print_call_is_statement_not_echoed_expression() {
        // `fmt.Println(...)` returns (int, error): must be a statement, not
        // wrapped in `fmt.Printf("%v\n", ...)` (a multi-value-context error).
        assert_eq!(classify_go("fmt.Println(\"hi\")"), LineKind::Stmt);
        assert_eq!(classify_go("println(42)"), LineKind::Stmt);
        let p = render_go(&Session::default(), "fmt.Println(\"hi\")", LineKind::Stmt);
        assert!(
            p.contains("fmt.Println(\"hi\")"),
            "runs as a statement: {p}"
        );
        assert!(!p.contains("Printf(\"%v"), "not echo-wrapped: {p}");
    }

    #[test]
    fn go_short_var_names_are_marked_used() {
        // A `x := 21` body line must get a `_ = x` so Go does not reject it as
        // an unused variable when a later line uses it.
        let s = sess(&[], &["x := 21"]);
        let p = render_go(&s, "x * 2", LineKind::Expr);
        assert!(p.contains("x := 21"), "binding present: {p}");
        assert!(p.contains("_ = x"), "binding marked used: {p}");
        assert!(p.contains("fmt.Printf(\"%v\\n\", x * 2)"), "echo: {p}");
    }

    #[test]
    fn go_short_var_names_extraction() {
        assert_eq!(go_short_var_names("x := 5"), vec!["x"]);
        assert_eq!(go_short_var_names("a, b := f()"), vec!["a", "b"]);
        assert_eq!(go_short_var_names("_, e := f()"), vec!["e"]);
        assert!(go_short_var_names("x = 5").is_empty(), "= is not :=");
        assert!(go_short_var_names("fmt.Println(x)").is_empty());
    }

    #[test]
    fn go_func_item_is_outside_main() {
        let p = render_go(
            &Session::default(),
            "func sq(n int) int { return n * n }",
            LineKind::Item,
        );
        let f_at = p.find("func sq").unwrap();
        let main_at = p.find("func main()").unwrap();
        assert!(f_at < main_at, "func item before main: {p}");
    }

    // -- C / C++ --

    #[test]
    fn c_classify() {
        assert_eq!(classify_c("#include <math.h>", false), LineKind::Item);
        assert_eq!(
            classify_c("int sq(int n) { return n*n; }", false),
            LineKind::Item
        );
        assert_eq!(classify_c("printf(\"%d\\n\", 5);", false), LineKind::Stmt);
        assert_eq!(classify_c("int x = 3;", false), LineKind::Stmt);
        // Control-flow ending in `{` is a statement, not an item.
        assert_eq!(classify_c("for (int i=0;i<3;i++) {", false), LineKind::Stmt);
    }

    #[test]
    fn c_default_headers_present() {
        let p = render_c(
            &Session::default(),
            "printf(\"hi\\n\");",
            LineKind::Stmt,
            false,
        );
        assert!(p.contains("#include <stdio.h>"), "stdio: {p}");
        assert!(p.contains("int main(void)"), "entry: {p}");
        assert!(p.contains("printf(\"hi\\n\");"), "stmt: {p}");
    }

    #[test]
    fn cpp_default_headers_present() {
        let p = render_c(
            &Session::default(),
            "std::cout << 5 << std::endl;",
            LineKind::Stmt,
            true,
        );
        assert!(p.contains("#include <iostream>"), "iostream: {p}");
        assert!(p.contains("std::cout << 5"), "stmt: {p}");
    }

    #[test]
    fn c_bare_expression_gets_a_semicolon() {
        // C/C++ run an "expression" as a statement; a missing `;` is added.
        let p = render_c(&Session::default(), "puts(\"x\")", LineKind::Stmt, false);
        assert!(p.contains("puts(\"x\");"), "semicolon added: {p}");
    }

    #[test]
    fn c_function_item_is_outside_main() {
        let p = render_c(
            &Session::default(),
            "int sq(int n) { return n*n; }",
            LineKind::Item,
            false,
        );
        let f_at = p.find("int sq").unwrap();
        let main_at = p.find("int main").unwrap();
        assert!(f_at < main_at, "function item before main: {p}");
    }

    // -- session model --

    #[test]
    fn commit_routes_by_kind_and_expr_is_not_retained() {
        let mut s = Session::default();
        s.commit("use std::fmt;".to_string(), LineKind::Item);
        s.commit("let x = 1;".to_string(), LineKind::Stmt);
        s.commit("x + 1".to_string(), LineKind::Expr);
        assert_eq!(s.items.len(), 1, "item retained");
        assert_eq!(s.body.len(), 1, "stmt retained");
        // The expression is echo-only and must NOT be in the body.
        assert!(
            !s.body.iter().any(|l| l.contains("x + 1")),
            "expression not retained in body: {:?}",
            s.body
        );
    }

    #[test]
    fn langspec_known_languages_resolve() {
        assert_eq!(LangSpec::of(SourceLang::Rust).unwrap().short, "rust");
        assert_eq!(LangSpec::of(SourceLang::Go).unwrap().short, "go");
        assert_eq!(LangSpec::of(SourceLang::C).unwrap().short, "c");
        assert_eq!(LangSpec::of(SourceLang::Cpp).unwrap().short, "cpp");
        assert!(LangSpec::of(SourceLang::Rust).unwrap().echoes_expressions);
        assert!(!LangSpec::of(SourceLang::C).unwrap().echoes_expressions);
    }

    #[test]
    fn langspec_rejects_non_compiled_language() {
        assert!(LangSpec::of(SourceLang::Js).is_err());
        assert!(LangSpec::of(SourceLang::Python).is_err());
    }

    #[test]
    fn go_import_line_defers_compile_others_do_not() {
        let go = LangSpec::of(SourceLang::Go).unwrap();
        assert!(go.defer_compile("import \"strings\""), "go import defers");
        assert!(!go.defer_compile("x := 5"), "go stmt does not defer");
        // Rust `use` does NOT defer (Rust tolerates an unused import as a
        // warning, which `#![allow(warnings)]` silences - it still compiles).
        let rust = LangSpec::of(SourceLang::Rust).unwrap();
        assert!(!rust.defer_compile("use std::fmt;"), "rust use compiles");
    }
}
