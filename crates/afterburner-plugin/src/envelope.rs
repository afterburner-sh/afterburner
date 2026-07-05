// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! JS source envelopes. Each user source is wrapped to:
//!
//! 1. Load input into a local `__ab_data`.
//! 2. Install a `module` / `exports` pair plus the plenum `require`.
//! 3. Invoke the user function and `JSON.stringify` the result to stdout.
//! 4. If the result is a Promise, `await` it (Javy's event-loop drain
//!    surfaces unhandled rejections as module-evaluation errors).

use alloc::format;
use alloc::string::{String, ToString};

/// Normalise a leading hashbang/BOM and bare dynamic `import(...)`
/// expressions so the source parses *and runs* cleanly under QuickJS,
/// which (a) rejects `#!` (it tokenises `#` as the start of a private
/// name and chokes on `!`) and (b) has no registered module loader so
/// `import('foo')` throws "could not load module" at runtime.
///
/// Node performs the shebang fix-up at module-load time; the dynamic
/// import is rewritten to `globalThis.__ab_dyn_import(...)` so it
/// resolves through our CJS require resolver. Hashbang replacement is
/// length-preserving (`#!` → `//`) so error line/column numbers still
/// line up with the user's file.
fn normalize_leading_hashbang(source: &str) -> String {
    let stripped = source.strip_prefix('\u{feff}').unwrap_or(source);
    let after = if let Some(rest) = stripped.strip_prefix("#!") {
        let mut out = String::with_capacity(stripped.len());
        out.push_str("//");
        out.push_str(rest);
        out
    } else if stripped.len() == source.len() {
        source.to_string()
    } else {
        stripped.to_string()
    };
    rewrite_dynamic_imports(&after)
}

/// Rewrite bare `import(spec)` expressions to a require-based shim.
/// Pattern: any non-identifier char (or BOL) followed by `import`
/// followed by optional whitespace + `(`. Excludes `import.meta`,
/// member access on an identifier called `import`, and identifier-
/// prefixed forms like `oimport(`. Strings / comments containing the
/// literal token are a known false positive but vanishingly rare in
/// real code; the alternative (registering a real QuickJS module
/// loader through the wasm guest) is much larger surface for the same
/// outcome.
fn rewrite_dynamic_imports(source: &str) -> String {
    if !source.contains("import") {
        return source.to_string();
    }
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len() + 32);
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'i'
            && i + 6 <= bytes.len()
            && &bytes[i..i + 6] == b"import"
            && (i == 0 || !is_ident_char(bytes[i - 1]))
        {
            // Skip whitespace after `import`.
            let mut j = i + 6;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                // Emit `globalThis.__ab_dyn_import(require, ` (with the
                // trailing `(` consumed) and skip past the original `(`.
                out.push_str("globalThis.__ab_dyn_import");
                // Preserve any whitespace between `import` and `(`.
                out.push_str(&source[i + 6..j]);
                out.push_str("(require,");
                i = j + 1;
                continue;
            }
        }
        // Copy one UTF-8 char.
        let ch_len = source[i..]
            .chars()
            .next()
            .map(|c| c.len_utf8())
            .unwrap_or(1);
        out.push_str(&source[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Envelope for the legacy mode: user source is compiled and run
/// together, with the input literal inlined into the JS text.
pub fn wrap_user_source(user: &str, input_json: &str) -> String {
    let user = normalize_leading_hashbang(user);
    let input_lit = js_string_literal(input_json);
    format!(
        r#"
        function __ab_write_stdout(s) {{
            Javy.IO.writeSync(1, new TextEncoder().encode(s));
        }}
        const __ab_data = JSON.parse({input_lit});
        const __ab_module = {{ exports: undefined }};
        // #57: inline the user source as an IIFE so it compiles into the
        // envelope bytecode ONCE at ignite, instead of re-parsing it via
        // `new Function(<source string>)` on every warm thrust (~150us). Same
        // module/exports/require param scoping as before; matches the native
        // tier's compiled-once entry (#24).
        (function (module, exports, require) {{
            {user}
        }})(__ab_module, __ab_module.exports, globalThis.require);
        const __ab_fn = __ab_module.exports;
        const __ab_maybe = (typeof __ab_fn === 'function') ? __ab_fn(__ab_data) : __ab_fn;
        const __ab_result = (__ab_maybe !== null && typeof __ab_maybe === 'object' && typeof __ab_maybe.then === 'function')
            ? await __ab_maybe
            : __ab_maybe;
        __ab_write_stdout(JSON.stringify(__ab_result === undefined ? null : __ab_result));
        "#
    )
}

/// Bytecode-cache variant of [`wrap_user_source`]. The compiled
/// bytecode is *input-agnostic* - it pulls the per-call input directly
/// from the host via the `__AB_GET_INPUT_VALUE__` global installed in
/// `globals::install`. Identical Promise / await semantics to the
/// inlined-input version above; the only difference is the input
/// source. Skipping the per-call preamble compile cuts ~150 µs from
/// the hot path.
///
/// One bytecode serves both input framings: the getter returns a JS
/// string under JSON framing (parsed here with QuickJS's native
/// `JSON.parse`) and a `Uint8Array` under raw framing (handed to the
/// module as-is - no string materialization, no parse). The branch is
/// a single `typeof` per invocation; raw framing can never produce a
/// string, so the dispatch is unambiguous.
///
/// The same bytecode also serves both **output** framings, branching
/// on the module's return value: a `Uint8Array` / `ArrayBuffer`
/// result crosses the boundary as raw bytes through
/// `__AB_RAW_OUTPUT__` (→ the `host_raw_output` import →
/// `OutputValue::Bytes` host-side) with no `JSON.stringify`, no
/// string materialization, and no stdout framing; every other value
/// keeps the JSON-over-stdout contract. The two `instanceof` checks
/// are O(1) per invocation. (The legacy [`wrap_user_source`] envelope
/// keeps JSON-only output: its host path predates - and never reads -
/// the raw-output slot.)
pub fn wrap_user_source_with_input_global(user: &str) -> String {
    let user = normalize_leading_hashbang(user);
    format!(
        r#"
        function __ab_write_stdout(s) {{
            Javy.IO.writeSync(1, new TextEncoder().encode(s));
        }}
        const __ab_input = __AB_GET_INPUT_VALUE__();
        const __ab_data = (typeof __ab_input === 'string') ? JSON.parse(__ab_input) : __ab_input;
        const __ab_module = {{ exports: undefined }};
        // #57: inline user source (compiled once at ignite) instead of
        // re-parsing via `new Function(<source>)` every warm thrust (~150us).
        (function (module, exports, require) {{
            {user}
        }})(__ab_module, __ab_module.exports, globalThis.require);
        const __ab_fn = __ab_module.exports;
        const __ab_maybe = (typeof __ab_fn === 'function') ? __ab_fn(__ab_data) : __ab_fn;
        const __ab_result = (__ab_maybe !== null && typeof __ab_maybe === 'object' && typeof __ab_maybe.then === 'function')
            ? await __ab_maybe
            : __ab_maybe;
        const __ab_out = (__ab_result === undefined) ? null : __ab_result;
        if (__ab_out instanceof Uint8Array) {{
            __AB_RAW_OUTPUT__(__ab_out);
        }} else if (__ab_out instanceof ArrayBuffer) {{
            __AB_RAW_OUTPUT__(new Uint8Array(__ab_out));
        }} else {{
            __ab_write_stdout(JSON.stringify(__ab_out));
        }}
        "#
    )
}

/// Columnar-invoke wrapper. Phase 1 of the UDF-perf push - identical
/// shape to [`wrap_user_source_with_input_global`] except the result
/// dispatch goes through the JS-side `__ab_columnar_dispatch` helper
/// (installed at modify_runtime time by
/// `globals::columnar::install_dispatcher_js`) instead of via
/// `__AB_GET_INPUT_VALUE__` + `JSON.parse` / `JSON.stringify` to
/// stdout.
///
/// Synchronous in Phase 1 - the dispatcher throws a clean error if
/// the user UDF returns a Promise. Async columnar UDFs land in
/// Phase 1.5+. The vast majority of analytical columnar UDFs are
/// pure compute and sync, so this is the right default.
pub fn wrap_user_source_columnar(user: &str) -> String {
    let user = normalize_leading_hashbang(user);
    format!(
        r#"
        const __ab_module = {{ exports: undefined }};
        // #57: inline user source (compiled once at ignite) instead of
        // re-parsing via `new Function(<source>)` every warm thrust (~150us).
        (function (module, exports, require) {{
            {user}
        }})(__ab_module, __ab_module.exports, globalThis.require);
        __ab_columnar_dispatch(__ab_module.exports);
        "#
    )
}

/// Envelope for script mode. The user source runs as top-level code
/// inside a Node-style CommonJS wrapper (`module` / `exports` /
/// `require` bound as parameters). Unlike the UDF wrappers above, we
/// do **not** call `module.exports(input)` afterward - script mode
/// runs whatever the user wrote top-level and exits when that
/// finishes. Stdout comes from `console.log` (plenum's console
/// polyfill), not from `JSON.stringify(result)`.
///
/// `argv_json` / `env_json` must be valid JSON literals (array and
/// object respectively) - they are inlined into the JS text verbatim
/// and become `process.argv` / `process.env`. The process polyfill
/// was bootstrapped at Wizer-preinit time with empty argv/env, so we
/// also mutate the live `globalThis.process` here to refresh those
/// fields per invocation.
///
/// `cwd_json` is a JSON string literal (including quotes). It becomes
/// `globalThis.__host_cwd` so `process.cwd()` + the B6 `require()`
/// resolver have a working baseline for path-relative lookups when
/// the entry script is eval'd (`[eval]` has no dirname of its own).
///
/// Top-level `await` inside user source resolves through Javy's
/// event-loop drain: the outer wrapper itself is compiled as an ES
/// module, so a rejecting Promise surfaces as a module-evaluation
/// error that `invoke` returns as `Err` - exactly how we want script
/// errors to flow back to the host as a WASM trap.
///
/// **Exported promises are awaited.** A script whose final
/// `module.exports` is a thenable (`module.exports =
/// someAsyncMain()`) gets that value awaited after the top-level code
/// finishes: a rejection surfaces exactly like a top-level `throw` -
/// the error message + stack reach stderr and the process exits
/// nonzero (exit code 1, Node's convention for an unhandled
/// error/rejection). A resolved exported promise changes nothing -
/// the value is discarded and the script exits 0. Without this await,
/// a rejected exported promise would vanish: the assignment itself is
/// synchronous, nothing ever observed the rejection, and the run
/// exited 0 with no output.
pub fn wrap_script_source(user: &str, argv_json: &str, env_json: &str, cwd_json: &str) -> String {
    let user = normalize_leading_hashbang(user);
    let user_lit = js_string_literal(&user);
    // The user wrapper is an `AsyncFunction` so top-level `await`
    // inside the user's source compiles. The plain `Function`
    // constructor creates a sync function body; an `await` inside
    // would parse as the identifier "await" and trip a "expecting ';'"
    // SyntaxError. With AsyncFunction the body parses as an async
    // function, await is legal, and the function returns a Promise we
    // can `await` from the outer wrapper.
    format!(
        r#"
        globalThis.__ab_argv = {argv_json};
        globalThis.__host_env = {env_json};
        globalThis.__host_cwd = {cwd_json};
        if (globalThis.process) {{
            globalThis.process.argv = globalThis.__ab_argv;
            globalThis.process.env  = globalThis.__host_env;
        }}
        // rebase the require resolver on the freshly-set cwd so
        // `require('./foo')` in an eval script lands in the user's
        // invocation directory.
        if (typeof globalThis.__plenum_refresh_entry_require === 'function') {{
            globalThis.__plenum_refresh_entry_require();
        }}
        // Derive __filename / __dirname from the entry-script path
        // baked into argv[1]. The user script frequently relies on
        // these (Node 21+ `import.meta.dirname` lowers to __dirname),
        // so make them first-class locals in the entry wrapper just
        // like require.js does for require()'d modules.
        const __ab_entry = (globalThis.__ab_argv && globalThis.__ab_argv[1]) || '';
        const __ab_filename = (function() {{
            if (!__ab_entry || __ab_entry === '[eval]') return globalThis.__host_cwd || '/';
            if (__ab_entry[0] === '/' || /^[A-Za-z]:[\\/]/.test(__ab_entry)) return __ab_entry;
            var cwd = globalThis.__host_cwd || '/';
            var sep = (cwd[cwd.length - 1] === '/' ? '' : '/');
            return cwd + sep + __ab_entry;
        }})();
        const __ab_dirname = (function() {{
            var f = __ab_filename;
            var i = f.lastIndexOf('/');
            if (i < 0) i = f.lastIndexOf('\\');
            return i <= 0 ? '/' : f.slice(0, i);
        }})();
        const __ab_AsyncFunction = (async function () {{}}).constructor;
        const __ab_module = {{ exports: {{}} }};
        const __ab_user = new __ab_AsyncFunction(
            'module', 'exports', 'require', '__filename', '__dirname', {user_lit}
        );
        await __ab_user(
            __ab_module, __ab_module.exports, globalThis.require,
            __ab_filename, __ab_dirname
        );
        // Await an exported thenable so its rejection cannot vanish:
        // `module.exports = Promise.reject(e)` must fail the run the
        // same way a top-level `throw e` does (message + stack on
        // stderr, exit code 1). A resolved value is discarded -
        // script-mode output stays console-only.
        const __ab_exported = __ab_module.exports;
        if (__ab_exported !== null
            && (typeof __ab_exported === 'object' || typeof __ab_exported === 'function')
            && typeof __ab_exported.then === 'function') {{
            await __ab_exported;
        }}
        "#
    )
}

pub fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
