// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Shell-command classifier for the assistant hook - decides whether a
//! command would execute code *outside* the sandbox and, when it would,
//! builds the exact corrected command the assistant should run instead
//! (usually the same command with the executing segment prefixed by
//! `burn`, which the pass-through dispatcher in
//! [`super::super::passthrough`] turns into a sandboxed run).
//!
//! Pure string work - no I/O, no engine init - so the hook adds
//! microseconds, not milliseconds, to every tool call. The tokenizer is a
//! lightweight quote-aware splitter, NOT a full shell grammar; the
//! fallback heuristic at the end keeps exotic constructions redirecting
//! (a false positive costs the assistant one retry; a false negative
//! silently runs unsandboxed code, which is the failure mode we refuse).

/// What the classifier decided about one whole command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not code execution (or already sandboxed) - let the host proceed.
    Allow,
    /// Code would run outside the sandbox: deny and hand back `corrected`.
    Redirect {
        /// The ready-to-run replacement command.
        corrected: String,
        /// The human/agent-facing explanation embedding `corrected`.
        reason: String,
    },
}

/// What one pipeline segment contributes to the verdict.
enum SegAction {
    /// Nothing to do for this segment.
    None,
    /// Insert `burn ` at this byte offset (start of the runtime token).
    Prefix(usize),
    /// Replace this byte range (a `sh -c` payload) with a rewritten string.
    Splice(std::ops::Range<usize>, String),
    /// No mechanical rewrite exists (stdin scripts, deno): suggest this
    /// replacement command instead.
    Suggest(String),
}

/// One shell token: its unquoted text and the byte span of its raw form
/// (quotes included) in the original command string.
struct Tok {
    text: String,
    start: usize,
    end: usize,
    quoted: bool,
}

/// Classify a full command line.
pub fn classify(command: &str) -> Verdict {
    let mut prefixes: Vec<usize> = Vec::new();
    let mut splices: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    let mut suggestion: Option<String> = None;

    for (seg_start, seg) in segments(command) {
        match classify_segment(seg, seg_start) {
            SegAction::None => {}
            SegAction::Prefix(at) => prefixes.push(at),
            SegAction::Splice(range, with) => splices.push((range, with)),
            SegAction::Suggest(s) => suggestion = Some(s),
        }
    }

    if prefixes.is_empty() && splices.is_empty() && suggestion.is_none() {
        return Verdict::Allow;
    }

    // Apply mechanical rewrites back-to-front so earlier offsets stay valid.
    let corrected = if !prefixes.is_empty() || !splices.is_empty() {
        let mut out = command.to_string();
        let mut edits: Vec<(usize, usize, String)> = prefixes
            .iter()
            .map(|&at| (at, at, "burn --sandbox ".to_string()))
            .chain(splices.iter().map(|(r, w)| (r.start, r.end, w.clone())))
            .collect();
        edits.sort_by_key(|e| std::cmp::Reverse(e.0));
        for (start, end, with) in edits {
            out.replace_range(start..end, &with);
        }
        out
    } else {
        // Suggestion-only (stdin scripts / deno): the suggestion IS the
        // corrected command.
        suggestion.clone().unwrap_or_default()
    };

    let reason = format!(
        "Code must run SEALED in the burn sandbox: no network, no \
         filesystem, no env access by default. Conform the code to those \
         constraints, then re-run exactly: `{corrected}` . Only when a \
         capability is genuinely required, grant it narrowly after the \
         sandbox flag (e.g. `burn --sandbox --allow-net=api.example.com \
         node app.js`); never --allow-all. Inline JS: `burn --sandbox \
         -e '<code>'`."
    );
    Verdict::Redirect { corrected, reason }
}

/// Split a command line into pipeline/sequence segments at top-level
/// (outside quotes) `&&`, `||`, `|`, `;`, and newlines. Returns each
/// segment's text plus its byte offset in the original string.
fn segments(command: &str) -> Vec<(usize, &str)> {
    let bytes = command.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == b'\\' && q == b'"' {
                    i += 1; // skip escaped char inside double quotes
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                b'\'' | b'"' => quote = Some(c),
                b'\\' => i += 1,
                b'&' | b'|' if i + 1 < bytes.len() && bytes[i + 1] == c => {
                    out.push((start, &command[start..i]));
                    i += 1;
                    start = i + 1;
                }
                b'|' | b';' | b'\n' => {
                    out.push((start, &command[start..i]));
                    start = i + 1;
                }
                _ => {}
            },
        }
        i += 1;
    }
    out.push((start, &command[start..]));
    out
}

/// Quote-aware tokenizer for one segment. `base` is the segment's byte
/// offset in the full command, so token spans index the original string.
fn tokenize(seg: &str, base: usize) -> Vec<Tok> {
    let bytes = seg.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        let mut text = String::new();
        let mut quoted = false;
        while i < bytes.len() && !(bytes[i] as char).is_whitespace() {
            match bytes[i] {
                b'\'' => {
                    quoted = true;
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\'' {
                        text.push(bytes[i] as char);
                        i += 1;
                    }
                    i += 1; // closing quote (or end)
                }
                b'"' => {
                    quoted = true;
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 1;
                        }
                        text.push(bytes[i] as char);
                        i += 1;
                    }
                    i += 1;
                }
                b'\\' if i + 1 < bytes.len() => {
                    text.push(bytes[i + 1] as char);
                    i += 2;
                }
                c => {
                    text.push(c as char);
                    i += 1;
                }
            }
        }
        toks.push(Tok {
            text,
            start: base + start,
            end: base + i,
            quoted,
        });
    }
    toks
}

/// Basename of a command token (strips directories and a `.exe` suffix),
/// lowercased for matching.
fn basename(tok: &str) -> String {
    let name = tok.rsplit(['/', '\\']).next().unwrap_or(tok);
    name.strip_suffix(".exe")
        .unwrap_or(name)
        .to_ascii_lowercase()
}

/// Whether a token is a `VAR=value` environment assignment.
fn is_env_assignment(tok: &str) -> bool {
    let Some(eq) = tok.find('=') else {
        return false;
    };
    let name = &tok[..eq];
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.chars().next().unwrap_or('0').is_ascii_digit()
}

/// Whether every argument is a harmless metadata flag (`--version` etc.).
fn only_metadata_flags(args: &[&Tok]) -> bool {
    !args.is_empty()
        && args
            .iter()
            .all(|t| matches!(t.text.as_str(), "--version" | "-v" | "--help" | "-h"))
}

/// First argument that names a file/script: not a flag, not a shell
/// redirection, not quoted-empty.
fn first_file_arg<'a>(args: &'a [&'a Tok]) -> Option<&'a Tok> {
    let mut skip_next = false;
    for t in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let s = t.text.as_str();
        if !t.quoted && (s.starts_with('<') || s.starts_with('>')) {
            continue;
        }
        if s.starts_with('-') {
            // Flags that consume a value would otherwise donate it as a
            // phantom "file". Covers node (-e/--eval/-p/--print/-r/--require)
            // and python/ruby (-c/-e/--eval/-m).
            if matches!(
                s,
                "-e" | "--eval" | "-p" | "--print" | "-r" | "--require" | "-c" | "-m"
            ) {
                skip_next = true;
            }
            continue;
        }
        return Some(t);
    }
    None
}

/// Package-manager subcommands that only manage dependencies/metadata and
/// never execute project JavaScript.
const PM_SAFE: &[&str] = &[
    "install",
    "i",
    "ci",
    "add",
    "a",
    "remove",
    "rm",
    "uninstall",
    "un",
    "update",
    "up",
    "upgrade",
    "audit",
    "info",
    "view",
    "show",
    "ls",
    "list",
    "ll",
    "la",
    "link",
    "unlink",
    "config",
    "get",
    "set",
    "cache",
    "store",
    "why",
    "licenses",
    "outdated",
    "prune",
    "dedupe",
    "ping",
    "whoami",
    "login",
    "logout",
    "adduser",
    "owner",
    "search",
    "pack",
    "publish",
    "unpublish",
    "version",
    "pkg",
    "import",
    "policies",
    "fund",
    "doctor",
    "completion",
    "help",
    "--version",
    "-v",
    "--help",
    "-h",
    "setup",
    "approve-builds",
];

/// Shell wrappers we skip over to find the real command underneath.
fn skip_wrappers(toks: &[Tok]) -> &[Tok] {
    let mut rest = toks;
    loop {
        // Leading VAR=value assignments.
        while let Some(first) = rest.first() {
            if !first.quoted && is_env_assignment(&first.text) {
                rest = &rest[1..];
            } else {
                break;
            }
        }
        let Some(first) = rest.first() else {
            return rest;
        };
        match basename(&first.text).as_str() {
            "env" => {
                // `env [-i] [VAR=val …] cmd` - drop env, its flags, and
                // assignments (the loop re-strips assignments).
                rest = &rest[1..];
                while let Some(t) = rest.first() {
                    if t.text.starts_with('-') {
                        rest = &rest[1..];
                    } else {
                        break;
                    }
                }
            }
            "time" | "nice" | "command" | "exec" => rest = &rest[1..],
            "timeout" => {
                // `timeout [flags] DURATION cmd` - drop timeout, flags, and
                // the duration token.
                rest = &rest[1..];
                while let Some(t) = rest.first() {
                    if t.text.starts_with('-') {
                        rest = &rest[1..];
                    } else {
                        break;
                    }
                }
                if !rest.is_empty() {
                    rest = &rest[1..];
                }
            }
            _ => return rest,
        }
    }
}

/// Classify one pipeline segment.
fn classify_segment(seg: &str, base: usize) -> SegAction {
    let toks = tokenize(seg, base);
    let rest = skip_wrappers(&toks);
    let Some(head) = rest.first() else {
        return SegAction::None;
    };
    let name = basename(&head.text);
    let args: Vec<&Tok> = rest[1..].iter().collect();
    let sub = args
        .iter()
        .find(|t| !t.text.starts_with('-'))
        .map(|t| t.text.as_str());

    // Anything already routed through burn is sandboxed - never loop.
    if name == "burn" {
        return SegAction::None;
    }
    // Direct node_modules/.bin tool invocations are node programs.
    if head.text.contains("node_modules/.bin/") || head.text.contains("node_modules\\.bin\\") {
        return SegAction::Prefix(head.start);
    }

    match name.as_str() {
        "node" | "nodejs" => {
            if only_metadata_flags(&args) {
                return SegAction::None;
            }
            let has_inline = args
                .iter()
                .any(|t| matches!(t.text.as_str(), "-e" | "--eval" | "-p" | "--print"));
            if has_inline || first_file_arg(&args).is_some() {
                // `burn node …` handles both file and inline forms.
                SegAction::Prefix(head.start)
            } else {
                // Bare node = REPL or a stdin-piped/heredoc script; there is
                // no mechanical rewrite (`burn node` needs a file or -e).
                SegAction::Suggest(
                    "burn --sandbox -e '<code>'  (or save the script to a file and run: burn <file>)"
                        .to_string(),
                )
            }
        }
        "npx" | "pnpx" | "bunx" => {
            if only_metadata_flags(&args) || args.is_empty() {
                SegAction::None
            } else {
                SegAction::Prefix(head.start)
            }
        }
        "npm" | "pnpm" | "yarn" | "bun" => {
            match sub {
                // Bare `yarn` / `pnpm` / `npm` (= install) and dependency
                // management never run project code.
                None => SegAction::None,
                Some(s) if PM_SAFE.contains(&s) => {
                    // …except `bun <file>`: bun runs files directly and a
                    // file named like a subcommand is impossible here.
                    SegAction::None
                }
                // Everything else executes JS: run/test/start/exec/dlx/x,
                // a yarn/pnpm script shorthand, or a file (bun app.ts).
                Some(_) => SegAction::Prefix(head.start),
            }
        }
        "deno" => match sub {
            Some("run" | "serve" | "task" | "test" | "bench" | "eval" | "repl") => {
                // deno is not a pass-through target (it never spawns node,
                // so the PATH shim can't capture it): synthesize the native
                // burn form instead of prefixing.
                if sub == Some("eval") {
                    SegAction::Suggest("burn --sandbox -e '<code>'".to_string())
                } else {
                    let after_sub: Vec<&Tok> = args
                        .iter()
                        .skip_while(|t| t.text != sub.unwrap_or_default())
                        .skip(1)
                        .copied()
                        .collect();
                    match first_file_arg(&after_sub) {
                        Some(f) => SegAction::Suggest(format!("burn --sandbox run {}", f.text)),
                        None => SegAction::Suggest("burn --sandbox run <file>".to_string()),
                    }
                }
            }
            _ => SegAction::None,
        },
        // ── interpreted: python / ruby ───────────────────────────────────
        //
        // `burn python x.py` / `burn python3 x.py` / `burn ruby x.rb`
        // are now first-class in-process dispatch (passthrough.rs), so a
        // plain prefix suffices. Bare interpreters (REPL) get a suggestion;
        // metadata flags are allowed.
        n if matches!(n, "python" | "ruby") || n.starts_with("python3") || n == "python3" => {
            if only_metadata_flags(&args) {
                return SegAction::None;
            }
            let has_inline = args
                .iter()
                .any(|t| matches!(t.text.as_str(), "-c" | "-e" | "--eval" | "-m"));
            if has_inline || first_file_arg(&args).is_some() {
                SegAction::Prefix(head.start)
            } else {
                let ext = if n == "ruby" { "rb" } else { "py" };
                SegAction::Suggest(format!(
                    "burn --sandbox {n} <file.{ext}>  (save the code to a file and run: burn <file.{ext}>)"
                ))
            }
        }
        // ── compiled: go run, cargo run, rustc, gcc/g++/clang ───────────
        //
        // Only the RUN forms are intercepted; pure build/metadata steps
        // (`go build`, `cargo build`, `gcc -c`, `--version`) are allowed.
        // A false-allow on a build is fine; a false-deny on a build is not.
        "go" => match sub {
            Some("run") => {
                // `go run x.go` -> suggest `burn x.go`
                let after_run: Vec<&Tok> = args
                    .iter()
                    .skip_while(|t| t.text != "run")
                    .skip(1)
                    .copied()
                    .collect();
                match first_file_arg(&after_run) {
                    Some(f) => SegAction::Suggest(format!("burn {}", f.text)),
                    None => SegAction::Suggest("burn <file.go>".to_string()),
                }
            }
            _ => SegAction::None, // go build, go test metadata, etc.
        },
        "cargo" => match sub {
            Some("run") => SegAction::Suggest("burn --sandbox run".to_string()),
            _ => SegAction::None, // cargo build, cargo test, cargo check, etc.
        },
        "rustc" => {
            if only_metadata_flags(&args) {
                return SegAction::None;
            }
            match first_file_arg(&args) {
                Some(f) => SegAction::Suggest(format!("burn {}", f.text)),
                None => SegAction::Suggest("burn <file.rs>".to_string()),
            }
        }
        "gcc" | "cc" | "g++" | "c++" | "clang" | "clang++" => {
            // Allow pure compilation (-c/-S/-E) and metadata (--version/-v).
            let compile_only = args
                .iter()
                .any(|t| matches!(t.text.as_str(), "-c" | "-S" | "-E"));
            if compile_only || only_metadata_flags(&args) {
                return SegAction::None;
            }
            // A run form (producing an executable) - suggest the burn form.
            match first_file_arg(&args) {
                Some(f) => SegAction::Suggest(format!("burn {}", f.text)),
                None => SegAction::Suggest("burn <source>".to_string()),
            }
        }
        "tsx" | "ts-node" | "ts-node-esm" | "jest" | "vitest" | "mocha" => {
            // Node-backed runners: the PATH shim re-enters burn for their
            // internal `node` spawns, so a plain prefix sandboxes them.
            SegAction::Prefix(head.start)
        }
        "sh" | "bash" | "zsh" | "dash" => {
            // `sh -c '<payload>'` - classify the payload and splice the
            // rewritten payload back into the same quotes.
            let mut want_payload = false;
            for t in &args {
                if want_payload {
                    if let Verdict::Redirect { corrected, .. } = classify(&t.text) {
                        // Only splice when the rewrite is mechanical (the
                        // corrected text still contains the payload shape).
                        let span = span_inside_quotes(t);
                        return SegAction::Splice(span, corrected);
                    }
                    return SegAction::None;
                }
                if !t.text.starts_with('-') {
                    break; // a script file, not -c
                }
                if t.text.contains('c') {
                    want_payload = true;
                }
            }
            SegAction::None
        }
        "xargs" | "find" | "parallel" => {
            // The runtime appears as a later argument (`xargs node`,
            // `find … -exec node {} ;`). No clean mechanical rewrite.
            let runtime = args.iter().any(|t| {
                if t.quoted {
                    return false;
                }
                let b = basename(&t.text);
                matches!(
                    b.as_str(),
                    "node"
                        | "nodejs"
                        | "npx"
                        | "tsx"
                        | "ts-node"
                        | "bunx"
                        | "pnpx"
                        | "python"
                        | "python3"
                        | "ruby"
                        | "rustc"
                        | "gcc"
                        | "g++"
                        | "clang"
                        | "clang++"
                ) || b.starts_with("python3")
            });
            if runtime {
                SegAction::Suggest(
                    "burn --sandbox <file>  (run each source file through burn)".to_string(),
                )
            } else {
                SegAction::None
            }
        }
        _ => SegAction::None,
    }
}

/// The byte span of a token's *content* - inside its surrounding quotes
/// when present, so a splice preserves the original quoting.
fn span_inside_quotes(t: &Tok) -> std::ops::Range<usize> {
    if t.quoted && t.end - t.start >= 2 {
        (t.start + 1)..(t.end - 1)
    } else {
        t.start..t.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corrected(cmd: &str) -> String {
        match classify(cmd) {
            Verdict::Redirect { corrected, .. } => corrected,
            Verdict::Allow => panic!("expected redirect for: {cmd}"),
        }
    }

    fn allowed(cmd: &str) -> bool {
        classify(cmd) == Verdict::Allow
    }

    // ── direct node ─────────────────────────────────────────────────────

    #[test]
    fn node_file_is_prefixed() {
        assert_eq!(corrected("node script.js"), "burn --sandbox node script.js");
        assert_eq!(
            corrected("node ./dist/app.js --port 3000"),
            "burn --sandbox node ./dist/app.js --port 3000"
        );
    }

    #[test]
    fn node_inline_eval_is_prefixed() {
        assert_eq!(
            corrected("node -e 'console.log(1+1)'"),
            "burn --sandbox node -e 'console.log(1+1)'"
        );
        assert_eq!(
            corrected("node -p process.version"),
            "burn --sandbox node -p process.version"
        );
        assert_eq!(
            corrected("node --eval \"1+1\""),
            "burn --sandbox node --eval \"1+1\""
        );
    }

    #[test]
    fn node_metadata_flags_are_allowed() {
        assert!(allowed("node --version"));
        assert!(allowed("node -v"));
        assert!(allowed("node --help"));
    }

    #[test]
    fn path_qualified_node_is_prefixed() {
        assert_eq!(
            corrected("/usr/bin/node app.js"),
            "burn --sandbox /usr/bin/node app.js"
        );
        assert_eq!(
            corrected("~/.nvm/versions/node/v22.0.0/bin/node app.js"),
            "burn --sandbox ~/.nvm/versions/node/v22.0.0/bin/node app.js"
        );
    }

    #[test]
    fn bare_node_stdin_gets_a_suggestion() {
        // `echo code | node`, `node <<EOF` - no mechanical rewrite exists.
        match classify("echo 'console.log(1)' | node") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn --sandbox -e")),
            Verdict::Allow => panic!("stdin node must redirect"),
        }
        match classify("node <<'EOF'\nconsole.log(1)\nEOF") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("heredoc node must redirect"),
        }
    }

    // ── wrappers + env prefixes ─────────────────────────────────────────

    #[test]
    fn env_assignment_prefix_is_skipped() {
        assert_eq!(
            corrected("NODE_ENV=production node server.js"),
            "NODE_ENV=production burn --sandbox node server.js"
        );
    }

    #[test]
    fn wrapper_commands_are_skipped() {
        assert_eq!(
            corrected("time node bench.js"),
            "time burn --sandbox node bench.js"
        );
        assert_eq!(
            corrected("timeout 30 node slow.js"),
            "timeout 30 burn --sandbox node slow.js"
        );
        assert_eq!(
            corrected("env -i node app.js"),
            "env -i burn --sandbox node app.js"
        );
    }

    // ── package managers ────────────────────────────────────────────────

    #[test]
    fn npm_script_execution_is_prefixed() {
        assert_eq!(corrected("npm test"), "burn --sandbox npm test");
        assert_eq!(corrected("npm run build"), "burn --sandbox npm run build");
        assert_eq!(corrected("npm start"), "burn --sandbox npm start");
        assert_eq!(corrected("pnpm run dev"), "burn --sandbox pnpm run dev");
        assert_eq!(corrected("yarn build"), "burn --sandbox yarn build"); // script shorthand
        assert_eq!(
            corrected("bun run index.ts"),
            "burn --sandbox bun run index.ts"
        );
        assert_eq!(corrected("bun app.ts"), "burn --sandbox bun app.ts");
    }

    #[test]
    fn dependency_management_is_allowed() {
        assert!(allowed("npm install"));
        assert!(allowed("npm install express"));
        assert!(allowed("npm ci"));
        assert!(allowed("pnpm add -D typescript"));
        assert!(allowed("yarn"));
        assert!(allowed("yarn add react"));
        assert!(allowed("bun install"));
        assert!(allowed("npm audit"));
        assert!(allowed("npm config get registry"));
        assert!(allowed("npm --version"));
    }

    #[test]
    fn npx_always_executes() {
        assert_eq!(
            corrected("npx tsx main.ts"),
            "burn --sandbox npx tsx main.ts"
        );
        assert_eq!(
            corrected("npx create-react-app my-app"),
            "burn --sandbox npx create-react-app my-app"
        );
        assert_eq!(corrected("bunx vitest"), "burn --sandbox bunx vitest");
        assert!(allowed("npx --version"));
    }

    // ── ts runners + test runners ───────────────────────────────────────

    #[test]
    fn ts_runners_are_prefixed() {
        assert_eq!(
            corrected("tsx watch src/main.ts"),
            "burn --sandbox tsx watch src/main.ts"
        );
        assert_eq!(
            corrected("ts-node script.ts"),
            "burn --sandbox ts-node script.ts"
        );
    }

    #[test]
    fn test_runners_are_prefixed() {
        assert_eq!(
            corrected("jest --coverage"),
            "burn --sandbox jest --coverage"
        );
        assert_eq!(corrected("vitest run"), "burn --sandbox vitest run");
        assert_eq!(
            corrected("./node_modules/.bin/mocha test/"),
            "burn --sandbox ./node_modules/.bin/mocha test/"
        );
    }

    // ── deno (not a pass-through target) ────────────────────────────────

    #[test]
    fn deno_gets_native_burn_forms() {
        assert_eq!(
            corrected("deno run --allow-net server.ts"),
            "burn --sandbox run server.ts"
        );
        match classify("deno eval 'console.log(1)'") {
            Verdict::Redirect { corrected, .. } => {
                assert!(corrected.starts_with("burn --sandbox -e"))
            }
            Verdict::Allow => panic!(),
        }
        assert!(allowed("deno fmt"));
        assert!(allowed("deno --version"));
    }

    // ── compound commands ───────────────────────────────────────────────

    #[test]
    fn compound_segments_rewrite_only_the_js_parts() {
        assert_eq!(
            corrected("cd app && node build.js && echo done"),
            "cd app && burn --sandbox node build.js && echo done"
        );
        assert_eq!(
            corrected("npm install && npm test"),
            "npm install && burn --sandbox npm test"
        );
        assert_eq!(
            corrected("node a.js; node b.js"),
            "burn --sandbox node a.js; burn --sandbox node b.js"
        );
    }

    #[test]
    fn sh_dash_c_payload_is_rewritten_in_place() {
        assert_eq!(
            corrected("sh -c 'node x.js'"),
            "sh -c 'burn --sandbox node x.js'"
        );
        assert_eq!(
            corrected("bash -lc \"npm test\""),
            "bash -lc \"burn --sandbox npm test\""
        );
    }

    #[test]
    fn xargs_and_find_exec_get_a_suggestion() {
        match classify("ls *.js | xargs node") {
            Verdict::Redirect { .. } => {}
            Verdict::Allow => panic!("xargs node must redirect"),
        }
        match classify("find . -name '*.js' -exec node {} \\;") {
            Verdict::Redirect { .. } => {}
            Verdict::Allow => panic!("find -exec node must redirect"),
        }
    }

    // ── non-JS and already-sandboxed commands stay untouched ────────────

    #[test]
    fn unrelated_commands_are_allowed() {
        assert!(allowed("ls -la"));
        assert!(allowed("git status"));
        assert!(allowed("echo 'use node for this'")); // quoted mention, no exec
        assert!(allowed("cat node.txt"));
        assert!(allowed("grep -r node_modules src/"));
        assert!(allowed("rm -rf node_modules"));
    }

    #[test]
    fn burn_prefixed_commands_never_loop() {
        assert!(allowed("burn node app.js"));
        assert!(allowed("burn npm test"));
        assert!(allowed("burn -e 'console.log(1)'"));
        assert!(allowed("cd app && burn node build.js"));
    }

    #[test]
    fn reason_embeds_the_corrected_command() {
        match classify("node app.js") {
            Verdict::Redirect { reason, corrected } => {
                assert!(reason.contains(&corrected));
                assert!(reason.contains("burn"));
            }
            Verdict::Allow => panic!(),
        }
    }

    // ── python / ruby interpreted languages ─────────────────────────────

    #[test]
    fn python_file_is_prefixed() {
        assert_eq!(
            corrected("python script.py"),
            "burn --sandbox python script.py"
        );
        assert_eq!(
            corrected("python3 script.py"),
            "burn --sandbox python3 script.py"
        );
        assert_eq!(
            corrected("python3.12 app.py"),
            "burn --sandbox python3.12 app.py"
        );
    }

    #[test]
    fn ruby_file_is_prefixed() {
        assert_eq!(corrected("ruby script.rb"), "burn --sandbox ruby script.rb");
        assert_eq!(
            corrected("ruby ./app.rb --port 3000"),
            "burn --sandbox ruby ./app.rb --port 3000"
        );
    }

    #[test]
    fn python_inline_is_prefixed() {
        // -c/-e with an inline payload: still prefixed (burn python handles it)
        assert_eq!(
            corrected("python -c 'print(1)'"),
            "burn --sandbox python -c 'print(1)'"
        );
    }

    #[test]
    fn python_metadata_flags_are_allowed() {
        assert!(allowed("python --version"));
        assert!(allowed("python3 --version"));
        assert!(allowed("ruby --version"));
        assert!(allowed("python -h"));
        assert!(allowed("ruby -h"));
    }

    #[test]
    fn bare_python_gets_a_suggestion() {
        match classify("python") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("bare python must redirect"),
        }
        match classify("ruby") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("bare ruby must redirect"),
        }
    }

    // ── compiled languages ───────────────────────────────────────────────

    #[test]
    fn go_run_gets_a_suggestion() {
        match classify("go run main.go") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("go run must redirect"),
        }
    }

    #[test]
    fn go_build_is_allowed() {
        assert!(allowed("go build ./..."));
        assert!(allowed("go build -o out main.go"));
        assert!(allowed("go test ./..."));
        assert!(allowed("go --version"));
    }

    #[test]
    fn cargo_run_gets_a_suggestion() {
        match classify("cargo run") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("cargo run must redirect"),
        }
        match classify("cargo run -- --port 8080") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("cargo run with args must redirect"),
        }
    }

    #[test]
    fn cargo_build_and_test_are_allowed() {
        assert!(allowed("cargo build"));
        assert!(allowed("cargo build --release"));
        assert!(allowed("cargo test"));
        assert!(allowed("cargo check"));
        assert!(allowed("cargo clippy"));
        assert!(allowed("cargo fmt"));
    }

    #[test]
    fn rustc_run_gets_a_suggestion() {
        match classify("rustc main.rs") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("rustc must redirect"),
        }
    }

    #[test]
    fn rustc_metadata_is_allowed() {
        assert!(allowed("rustc --version"));
        assert!(allowed("rustc -v"));
    }

    #[test]
    fn gcc_link_gets_a_suggestion() {
        match classify("gcc main.c -o main") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("gcc linking must redirect"),
        }
        match classify("g++ main.cpp -o main") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("g++ linking must redirect"),
        }
        match classify("clang main.c -o main") {
            Verdict::Redirect { corrected, .. } => assert!(corrected.contains("burn")),
            Verdict::Allow => panic!("clang linking must redirect"),
        }
    }

    #[test]
    fn gcc_compile_only_is_allowed() {
        assert!(allowed("gcc -c main.c"));
        assert!(allowed("g++ -c main.cpp -o main.o"));
        assert!(allowed("clang -S main.c"));
        assert!(allowed("gcc --version"));
    }
}
