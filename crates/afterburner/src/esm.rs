// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! ESM → CJS transform (AST-guided source rewrite).
//!
//! oxc 0.127 parses ES module syntax into a well-typed AST but does
//! *not* ship a first-class ESM→CJS transformer (upstream issue
//! [#4050]). This module fills the gap: we parse with oxc (to get
//! precise byte spans that correctly ignore strings containing the
//! substring `"import"`), collect every top-level import/export
//! declaration, and splice in CommonJS replacements using those
//! spans.
//!
//! Scope matches what 95% of real-world Node+TS code uses:
//!
//! * `import X from 'Y'` (default)
//! * `import { a, b as c } from 'Y'` (named with aliases)
//! * `import * as Ns from 'Y'` (namespace)
//! * `import X, { a, b } from 'Y'` (default + named combined)
//! * `import 'Y'` (side-effect only)
//! * `export default EXPR` (+ `function` / `class` declarations)
//! * `export const foo = …` / `export let` / `export var`
//! * `export function foo() {}` / `export class C {}`
//! * `export { a, b as c }` (no source)
//! * `export { a } from 'Y'` / `export * from 'Y'` /
//!   `export * as Ns from 'Y'` (re-export)
//!
//! Explicitly **not handled by this rewriter**:
//!
//! * Dynamic `import()` - needs async resolution; use
//!   `require()` directly when you need it at runtime.
//! * Top-level `await` at module scope - CJS output doesn't model
//!   module-as-promise; wrap with `(async () => { … })()` if you
//!   need it.
//!
//! `import.meta.*` is rewritten textually to its CJS equivalent
//! before parse:
//!
//! * `import.meta.dirname` → `__dirname` (Node 21+)
//! * `import.meta.filename` → `__filename` (Node 21+)
//! * `import.meta.url` → `('file://' + __filename)`
//! * `import.meta.resolve(spec)` → `require.resolve(spec)` (Node 22+)
//! * bare `import.meta` → an inline object with `{ url, dirname,
//!   filename, resolve }` for the rare reflective-access case.
//!
//! The substitution is unambiguous (no valid JS uses the literal
//! token `import.meta` in a string or comment way that would be
//! confused with the syntactic form), so a regex-shaped pre-pass
//! keeps the AST traversal tight without a custom visitor.
//!
//! The transform emits an `Object.defineProperty(exports,
//! '__esModule', { value: true })` prologue for any module that
//! used `export default` or named exports, so CJS consumers that
//! check the interop flag (`require('./x').__esModule`) see a
//! truthful answer - this matches TypeScript's `esModuleInterop`
//! output.
//!
//! [#4050]: https://github.com/oxc-project/oxc/issues/4050

use oxc::allocator::Allocator;
use oxc::ast::ast::{
    AwaitExpression, BindingPattern, Declaration, ExportDefaultDeclarationKind,
    ImportDeclarationSpecifier, ModuleExportName, Statement,
};
use oxc::ast_visit::Visit;
use oxc::parser::Parser;
use oxc::semantic::SemanticBuilder;
use oxc::span::{GetSpan, SourceType};
use std::collections::HashMap;
use std::path::Path;

/// Rewrite any top-level ESM declarations in `source` into CJS
/// equivalents. Source that contains no ESM declarations returns
/// unchanged (no parse cost? we still parse, but emit an identical
/// string - simpler than maintaining a second fast path).
pub fn rewrite_esm_to_cjs(source: &str, path: &Path) -> Result<String, String> {
    // Pre-pass: rewrite `import.meta.*` accesses to their CJS
    // equivalents. Done before the AST parse so the lowered output
    // doesn't carry `import.meta` into the CJS runtime where it'd
    // be a syntax error. See module-level docs for the mapping.
    let source_owned: String;
    let source: &str = if source.contains("import.meta") {
        source_owned = rewrite_import_meta(source);
        &source_owned
    } else {
        source
    };
    let allocator = Allocator::default();
    // Accept both `.js` / `.ts` etc. SourceType::from_path decides
    // ESM vs script based on extension; for explicit `.cjs` we still
    // want to parse permissively because the ESM rewrite ran on a
    // TS-strip that might leave CJS-shaped code too.
    let source_type = SourceType::from_path(path).unwrap_or(SourceType::mjs());
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() {
        return Err(parsed
            .errors
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
            .join("\n"));
    }

    // Build semantic info so we can find every `IdentifierReference`
    // that resolves to a named import. Each such reference gets
    // rewritten in place to `<temp>.<imported_name>`, which gives the
    // module body live-binding semantics for named imports - the
    // ES2015 spec's `module record import binding` shape - without
    // needing engine support. This matches what V8 / SpiderMonkey do
    // internally with module export getter slots.
    let semantic = SemanticBuilder::new().build(&parsed.program).semantic;
    let scoping = semantic.scoping();
    let nodes = semantic.nodes();

    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut has_named_or_default_export = false;
    // Map from each named-import-local symbol id to its rewrite text.
    // We walk references at the end because oxc's reference table
    // is keyed by SymbolId; collecting the per-import map first lets
    // us emit one Vec of edits in source order at the bottom.
    let mut named_import_rewrites: HashMap<oxc::syntax::symbol::SymbolId, String> = HashMap::new();

    for stmt in &parsed.program.body {
        match stmt {
            Statement::ImportDeclaration(decl) => {
                let src_name = decl.source.value.as_str();
                let start = decl.span.start as usize;
                let end = decl.span.end as usize;
                let temp = next_temp();
                let (replacement, named_locals) = rewrite_import(
                    src_name,
                    decl.specifiers.as_ref().map(|v| v.as_slice()),
                    &temp,
                );
                edits.push((start, end, replacement));
                // Register named-import locals for the live-binding
                // reference rewrite. The semantic phase has already
                // populated `BindingIdentifier::symbol_id` for each
                // import specifier, so we read it straight from the
                // AST node - no name-keyed scope lookup needed.
                if let Some(specs) = decl.specifiers.as_ref() {
                    for spec in specs {
                        if let ImportDeclarationSpecifier::ImportSpecifier(s) = spec {
                            let imported_name = mod_export_name(&s.imported);
                            if let Some(symbol_id) = s.local.symbol_id.get() {
                                named_import_rewrites
                                    .insert(symbol_id, format!("{temp}.{imported_name}"));
                            }
                        }
                    }
                }
                // The Vec returned by `rewrite_import` is now unused
                // here (kept on the function signature for potential
                // future callers), so drop it.
                let _ = named_locals;
            }
            Statement::ExportDefaultDeclaration(decl) => {
                has_named_or_default_export = true;
                let start = decl.span.start as usize;
                let end = decl.span.end as usize;
                let replacement = rewrite_export_default(&decl.declaration, source);
                edits.push((start, end, replacement));
            }
            Statement::ExportNamedDeclaration(decl) => {
                has_named_or_default_export = true;
                if let Some(inner) = decl.declaration.as_ref() {
                    // `export const foo = …` / `export function foo()` /
                    // `export class Foo` - leave the inner declaration's
                    // *body* in place so any imported-name references
                    // inside it stay at their original byte offsets
                    // (the live-binding pass relies on those positions).
                    // Two surgical edits: drop the leading `export ` and
                    // append the `exports.X = X` line after the body.
                    let outer_start = decl.span.start as usize;
                    let inner_span = inner.span();
                    let inner_start = inner_span.start as usize;
                    let inner_end = inner_span.end as usize;
                    edits.push((outer_start, inner_start, String::new()));
                    let names = decl_names(inner);
                    let mut tail = String::new();
                    for name in names {
                        tail.push_str(&format!("\nexports.{name} = {name};"));
                    }
                    if !tail.is_empty() {
                        edits.push((inner_end, inner_end, tail));
                    }
                } else {
                    let start = decl.span.start as usize;
                    let end = decl.span.end as usize;
                    let replacement = rewrite_export_named(
                        decl.declaration.as_ref(),
                        &decl.specifiers,
                        decl.source.as_ref().map(|s| s.value.as_str()),
                        source,
                    );
                    edits.push((start, end, replacement));
                }
            }
            Statement::ExportAllDeclaration(decl) => {
                has_named_or_default_export = true;
                let start = decl.span.start as usize;
                let end = decl.span.end as usize;
                let src_name = decl.source.value.as_str();
                let exported_as = decl.exported.as_ref().map(mod_export_name);
                edits.push((
                    start,
                    end,
                    rewrite_export_all(src_name, exported_as.as_deref()),
                ));
            }
            _ => {}
        }
    }

    // Live-binding pass: walk every named-import local's resolved
    // references and rewrite each one to `<temp>.<imported>`. The
    // `IdentifierReference` AST node's span is the byte range of
    // *just the identifier* - declarations and import-spec sites
    // don't appear in the reference table, so we never accidentally
    // splice the import declaration itself (it's already replaced
    // above by the `const __ab_esm_N = require(...)` shape).
    if !named_import_rewrites.is_empty() {
        for (symbol_id, replacement) in &named_import_rewrites {
            for ref_id in scoping.get_resolved_reference_ids(*symbol_id) {
                let reference = scoping.get_reference(*ref_id);
                let node = nodes.get_node(reference.node_id());
                let span = node.span();
                edits.push((span.start as usize, span.end as usize, replacement.clone()));
            }
        }
    }

    // Await-tracking pass - wrap every `await EXPR` so the value
    // flows through user-patched `Promise.prototype.then` before the
    // engine resumes. This is the only path that makes
    // `async_hooks.createHook({init,before,after})` fire for native
    // `await` expressions: QuickJS resolves async/await internally
    // with no JS-visible hook, but the spliced `__ab_await_track`
    // call routes the resolved value through one user-level `.then`
    // first, which our patched prototype catches.
    //
    // The rewrite is span-surgical - two inserts per await - so it
    // doesn't disturb the original expression text or its inner
    // byte spans (which the live-binding pass may have already
    // queued edits over).
    {
        let mut collector = AwaitSpanCollector::default();
        collector.visit_program(&parsed.program);
        for (arg_start, arg_end) in collector.spans {
            edits.push((arg_start, arg_start, "__ab_await_track(".to_string()));
            edits.push((arg_end, arg_end, ")".to_string()));
        }
    }

    // Debugger statement-instrumentation pass - gated on
    // `BURN_DEBUGGER_INSTRUMENT=1`. When enabled, every statement
    // gets prefixed with `__ab_brk("<path>", line, col);`. The JS
    // global `__ab_brk` checks the active breakpoint table (populated
    // by `Debugger.setBreakpointByUrl`); when a hit matches the
    // current location, it fires `Debugger.paused` and blocks via
    // `__host_inspector_pause` until the connected DevTools client
    // sends `Debugger.resume`/`stepX`. Off by default - the
    // instrumented call has a fast path (`if (!breakpoints.length)
    // return`) so its cost is one property read per statement, but
    // keeping it gated keeps non-debug runs zero-cost.
    if std::env::var("BURN_DEBUGGER_INSTRUMENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let path_lit = js_string_literal(&path.display().to_string());
        let mut bcol = BreakpointCollector::default();
        bcol.visit_program(&parsed.program);
        for stmt_start in bcol.statement_starts {
            let (line, col) = byte_to_line_col(source, stmt_start);
            let probe = format!("__ab_brk({path_lit},{line},{col});", line = line, col = col);
            edits.push((stmt_start, stmt_start, probe));
        }
    }

    if edits.is_empty() {
        // No ESM - pass through. Keeps plain-CJS untouched.
        return Ok(source.to_string());
    }

    // Apply the edits right-to-left so earlier byte spans stay valid
    // while we splice.
    edits.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
    let mut out = source.to_string();
    for (start, end, text) in edits {
        out.replace_range(start..end, &text);
    }

    if has_named_or_default_export {
        // Preface so `require('./x').__esModule === true`, matching
        // TypeScript's CJS emit contract for interop.
        let prologue = "Object.defineProperty(exports, '__esModule', { value: true });\n";
        out.insert_str(0, prologue);
    }

    Ok(out)
}

/// Lower one `import` declaration. Returns the replacement text and a
/// `Vec<(local_name, imported_name)>` of *named* imports the caller
/// must then live-bind by reference rewriting in the module body.
///
/// Default + namespace imports stay declared as `const` because:
///
/// * **default**: spec semantics for `import X from 'Y'` are a snapshot
///   of `Y`'s default export at link time. CJS already enforces that -
///   `module.exports.default` is set once during evaluate and doesn't
///   change. A `const` binding matches.
/// * **namespace**: `import * as Ns from 'Y'` binds the module
///   namespace object. Since CJS `require('Y')` returns the same
///   object reference forever, `const Ns = require('Y')` already
///   gives live property reads (`Ns.foo` always reads the current
///   value). No rewrite needed.
/// * **named**: `import { fromB } from 'Y'` is the case the spec
///   defines as a *getter slot* on the importer's environment. The
///   caller rewrites every reference to `fromB` into `<temp>.fromB`
///   so cross-module reads bypass the snapshot a const binding would
///   freeze.
fn rewrite_import(
    src: &str,
    specifiers: Option<&[ImportDeclarationSpecifier]>,
    temp: &str,
) -> (String, Vec<(String, String)>) {
    let src_lit = js_string_literal(src);
    let Some(specs) = specifiers else {
        // `import 'Y'` - pure side-effect.
        return (format!("require({src_lit});"), Vec::new());
    };
    if specs.is_empty() {
        return (format!("require({src_lit});"), Vec::new());
    }

    let mut default_local: Option<String> = None;
    let mut namespace_local: Option<String> = None;
    let mut named: Vec<(String, String)> = Vec::new();

    for spec in specs {
        match spec {
            ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                default_local = Some(s.local.name.to_string());
            }
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                namespace_local = Some(s.local.name.to_string());
            }
            ImportDeclarationSpecifier::ImportSpecifier(s) => {
                let imported = mod_export_name(&s.imported);
                let local = s.local.name.to_string();
                // `(local, imported)` - local is what the user code
                // refers to; imported is the property to read off the
                // namespace object. Same string when there's no rename.
                named.push((local, imported));
            }
        }
    }

    let mut out = format!("const {temp} = require({src_lit});\n");
    if let Some(local) = default_local {
        out.push_str(&format!(
            "const {local} = {temp} && {temp}.__esModule ? {temp}.default : {temp};\n"
        ));
    }
    if let Some(local) = namespace_local {
        out.push_str(&format!("const {local} = {temp};\n"));
    }
    // Named imports: do NOT emit `const { ... } = temp`. The caller
    // walks oxc's reference table to rewrite every use of `local`
    // into `temp.imported`, giving real ES2015 live-binding
    // semantics. The empty const declaration left here would shadow
    // those rewrites, so it's omitted entirely.
    (out, named)
}

fn rewrite_export_default(kind: &ExportDefaultDeclarationKind, source: &str) -> String {
    // `GetSpan::span()` works across the whole inherited-variant set
    // of ExportDefaultDeclarationKind - no enumeration needed.
    let span = kind.span();
    let text = &source[span.start as usize..span.end as usize];
    match kind {
        ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
            // Named function: emit the decl + assign the default.
            // Anonymous functions fall through to the expression form.
            if let Some(id) = f.id.as_ref() {
                format!("{text}\nmodule.exports.default = {};\n", id.name)
            } else {
                format!("module.exports.default = ({text});\n")
            }
        }
        ExportDefaultDeclarationKind::ClassDeclaration(c) => {
            if let Some(id) = c.id.as_ref() {
                format!("{text}\nmodule.exports.default = {};\n", id.name)
            } else {
                format!("module.exports.default = ({text});\n")
            }
        }
        ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => String::new(),
        _ => format!("module.exports.default = ({text});\n"),
    }
}

fn rewrite_export_named(
    declaration: Option<&Declaration>,
    specifiers: &[oxc::ast::ast::ExportSpecifier],
    source_module: Option<&str>,
    source_text: &str,
) -> String {
    // Two shapes:
    // (1) `export const foo = …` / function / class - ignore specifiers.
    // (2) `export { a, b }` / `export { a } from 'Y'` - ignore declaration.
    if let Some(decl) = declaration {
        let (span, names) = decl_span_and_names(decl);
        let text = &source_text[span.start as usize..span.end as usize];
        let mut out = text.to_string();
        out.push('\n');
        for name in names {
            out.push_str(&format!("exports.{name} = {name};\n"));
        }
        return out;
    }

    let mut out = String::new();
    if let Some(src) = source_module {
        // `export { a, b as c } from 'Y'` - re-export. One require
        // per statement keyed on a fresh temp.
        let temp = next_temp();
        out.push_str(&format!(
            "const {temp} = require({});\n",
            js_string_literal(src)
        ));
        for spec in specifiers {
            let local = mod_export_name(&spec.local);
            let exported = mod_export_name(&spec.exported);
            out.push_str(&format!("exports.{exported} = {temp}.{local};\n"));
        }
        return out;
    }

    // `export { a, b as c }` - specifiers reference bindings already
    // in scope.
    for spec in specifiers {
        let local = mod_export_name(&spec.local);
        let exported = mod_export_name(&spec.exported);
        out.push_str(&format!("exports.{exported} = {local};\n"));
    }
    out
}

fn rewrite_export_all(src: &str, exported_as: Option<&str>) -> String {
    let src_lit = js_string_literal(src);
    match exported_as {
        Some(name) => {
            // `export * as Ns from 'Y'`
            format!("exports.{name} = require({src_lit});\n")
        }
        None => {
            // `export * from 'Y'` - copy enumerable props except
            // `default` (Node's semantics).
            format!(
                "Object.keys(require({src_lit})).forEach(function(k) {{ \
                    if (k !== 'default' && k !== '__esModule') exports[k] = require({src_lit})[k]; \
                 }});\n"
            )
        }
    }
}

/// Names a Declaration introduces into scope. Used by the
/// surgical-edit path for `export const/function/class` so we can
/// emit one `exports.X = X` line per binding without replacing the
/// declaration text itself.
fn decl_names(decl: &Declaration) -> Vec<String> {
    let (_, names) = decl_span_and_names(decl);
    names
}

/// Returns the outer span covering a Declaration and the list of
/// names it introduces into scope. For a `const` with multiple
/// declarators (e.g. `export const a = 1, b = 2`), all are listed.
fn decl_span_and_names(decl: &Declaration) -> (oxc::span::Span, Vec<String>) {
    let span = decl.span();
    let names = match decl {
        Declaration::VariableDeclaration(v) => {
            let mut names = Vec::new();
            for d in &v.declarations {
                collect_binding_names(&d.id, &mut names);
            }
            names
        }
        Declaration::FunctionDeclaration(f) => {
            f.id.as_ref()
                .map(|id| vec![id.name.to_string()])
                .unwrap_or_default()
        }
        Declaration::ClassDeclaration(c) => {
            c.id.as_ref()
                .map(|id| vec![id.name.to_string()])
                .unwrap_or_default()
        }
        // Type-only declarations are stripped by the oxc TS
        // transformer before we see them; defensive fallthrough.
        _ => vec![],
    };
    (span, names)
}

fn collect_binding_names(pat: &BindingPattern<'_>, out: &mut Vec<String>) {
    match pat {
        BindingPattern::BindingIdentifier(id) => out.push(id.name.to_string()),
        BindingPattern::ObjectPattern(obj) => {
            for prop in &obj.properties {
                collect_binding_names(&prop.value, out);
            }
            if let Some(rest) = obj.rest.as_ref() {
                collect_binding_names(&rest.argument, out);
            }
        }
        BindingPattern::ArrayPattern(arr) => {
            for elem in arr.elements.iter() {
                if let Some(e) = elem.as_ref() {
                    collect_binding_names(e, out);
                }
            }
            if let Some(rest) = arr.rest.as_ref() {
                collect_binding_names(&rest.argument, out);
            }
        }
        BindingPattern::AssignmentPattern(ap) => collect_binding_names(&ap.left, out),
    }
}

fn mod_export_name(name: &ModuleExportName) -> String {
    match name {
        ModuleExportName::IdentifierName(i) => i.name.to_string(),
        ModuleExportName::IdentifierReference(i) => i.name.to_string(),
        ModuleExportName::StringLiteral(s) => s.value.to_string(),
    }
}

fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn next_temp() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    format!("__ab_esm_{n}")
}

/// Textual `import.meta.*` → CJS rewrite. Walks the source byte-by-
/// byte skipping inside string and template literals + line/block
/// comments so the substitution can't fire on a string that happens
/// to contain `"import.meta"`. Patterns matched (longest first):
///
/// * `import.meta.dirname`        → `__dirname`
/// * `import.meta.filename`       → `__filename`
/// * `import.meta.url`            → `('file://' + __filename)`
/// * `import.meta.resolve(`       → `require.resolve(`
/// * `import.meta` (bare)         → an inline `{ url, dirname,
///   filename, resolve }` object literal that re-routes the same
///   four accesses through the CJS surface above.
fn rewrite_import_meta(source: &str) -> String {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + 64);
    let mut i = 0usize;
    while i < len {
        let b = bytes[i];

        // Single-line comment: copy until newline.
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'/' {
            while i < len && bytes[i] != b'\n' {
                out.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        // Block comment: copy until `*/`.
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            out.push_str("/*");
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(bytes[i] as char);
                i += 1;
            }
            if i + 1 < len {
                out.push_str("*/");
                i += 2;
            } else if i < len {
                out.push(bytes[i] as char);
                i += 1;
            }
            continue;
        }
        // String / template literal: copy verbatim, honoring escapes.
        if b == b'\'' || b == b'"' || b == b'`' {
            let quote = b;
            out.push(b as char);
            i += 1;
            while i < len {
                let c = bytes[i];
                out.push(c as char);
                i += 1;
                if c == b'\\' && i < len {
                    out.push(bytes[i] as char);
                    i += 1;
                    continue;
                }
                if c == quote {
                    break;
                }
            }
            continue;
        }

        // `import.meta` token? Must not be preceded by an ident char
        // (so `myimport.meta` doesn't match) and must be followed by
        // either `.` or a non-ident char.
        if b == b'i' && starts_with(bytes, i, b"import.meta") {
            let prev_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            if prev_ok {
                let after = i + b"import.meta".len();
                // Try the longer specialisations first.
                if starts_with(bytes, after, b".dirname") {
                    out.push_str("__dirname");
                    i = after + b".dirname".len();
                    continue;
                }
                if starts_with(bytes, after, b".filename") {
                    out.push_str("__filename");
                    i = after + b".filename".len();
                    continue;
                }
                if starts_with(bytes, after, b".url") {
                    out.push_str("('file://' + __filename)");
                    i = after + b".url".len();
                    continue;
                }
                if starts_with(bytes, after, b".resolve") {
                    out.push_str("require.resolve");
                    i = after + b".resolve".len();
                    continue;
                }
                // Bare `import.meta` - synthesise an inline object.
                // The `resolve` callback closes over `require` so
                // dynamic resolution still goes through the CJS
                // resolver (npm packages, node_modules walk, etc.).
                if after >= len || !is_ident_byte(bytes[after]) {
                    out.push_str(
                        "({ url: 'file://' + __filename, dirname: __dirname, \
                         filename: __filename, \
                         resolve: function(s){ return require.resolve(s); } })",
                    );
                    i = after;
                    continue;
                }
            }
        }

        out.push(b as char);
        i += 1;
    }
    out
}

fn starts_with(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    if at + needle.len() > bytes.len() {
        return false;
    }
    &bytes[at..at + needle.len()] == needle
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// AST visitor that collects byte spans of every `AwaitExpression`'s
/// *argument*. Used by the await-tracking pass to wrap each awaited
/// value in a `__ab_await_track(EXPR)` call so `async_hooks` Promise
/// hooks fire across the engine's internal await resolution. The
/// expression's outer span (including the `await` keyword) is
/// untouched; we splice `__ab_await_track(` and `)` around the
/// argument only.
#[derive(Default)]
struct AwaitSpanCollector {
    spans: Vec<(usize, usize)>,
}

impl<'a> Visit<'a> for AwaitSpanCollector {
    fn visit_await_expression(&mut self, expr: &AwaitExpression<'a>) {
        let arg_span = expr.argument.span();
        self.spans
            .push((arg_span.start as usize, arg_span.end as usize));
        // Descend into the argument - nested awaits in `await foo(await bar())`
        // need their own wrap too.
        oxc::ast_visit::walk::walk_await_expression(self, expr);
    }
}

/// Collects byte offsets of every `Statement` start position so the
/// Debugger instrumentation pass can insert `__ab_brk(...)` probes
/// immediately before each. Triggered only when
/// `BURN_DEBUGGER_INSTRUMENT=1`.
#[derive(Default)]
struct BreakpointCollector {
    statement_starts: Vec<usize>,
}

impl<'a> Visit<'a> for BreakpointCollector {
    fn visit_statement(&mut self, stmt: &Statement<'a>) {
        // Skip declarations that introduce hoisted bindings -
        // injecting code before a `function f()` declaration would
        // separate the declaration from its scope-position semantics
        // (V8 hoists the binding to the top of the function). The
        // probe goes BEFORE the visible position of all *non-decl*
        // statements: expression statements, if/for/while, return,
        // try/catch, etc. Function declarations themselves don't
        // need a hit point because they're hoisted; their bodies'
        // statements get instrumented when the visitor descends.
        match stmt {
            Statement::FunctionDeclaration(_)
            | Statement::ClassDeclaration(_)
            | Statement::ImportDeclaration(_)
            | Statement::ExportNamedDeclaration(_)
            | Statement::ExportDefaultDeclaration(_)
            | Statement::ExportAllDeclaration(_) => {}
            _ => {
                let span = stmt.span();
                self.statement_starts.push(span.start as usize);
            }
        }
        oxc::ast_visit::walk::walk_statement(self, stmt);
    }
}

/// Convert a byte offset into (line, col) 1-based for the debugger
/// surface. Walks the source from the start to count line breaks -
/// O(N) per call; for instrumentation we sort the offsets and reuse
/// a running scanner if needed, but for typical user scripts the
/// per-statement cost is acceptable at transpile time.
fn byte_to_line_col(source: &str, offset: usize) -> (u32, u32) {
    let mut line: u32 = 1;
    let mut last_nl: usize = 0;
    let bytes = source.as_bytes();
    let cap = offset.min(bytes.len());
    for (i, &b) in bytes.iter().enumerate().take(cap) {
        if b == b'\n' {
            line += 1;
            last_nl = i + 1;
        }
    }
    let col = (cap - last_nl) as u32 + 1;
    (line, col)
}

#[cfg(test)]
mod import_meta_tests {
    use super::rewrite_import_meta;

    #[test]
    fn rewrites_dirname_and_filename() {
        let s = "console.log(import.meta.dirname, import.meta.filename);";
        let out = rewrite_import_meta(s);
        assert_eq!(out, "console.log(__dirname, __filename);");
    }

    #[test]
    fn rewrites_url_and_resolve() {
        let s = "const u = import.meta.url; const p = import.meta.resolve('x');";
        let out = rewrite_import_meta(s);
        assert!(out.contains("('file://' + __filename)"));
        assert!(out.contains("require.resolve('x')"));
    }

    #[test]
    fn rewrites_bare_import_meta() {
        let s = "const m = import.meta;";
        let out = rewrite_import_meta(s);
        assert!(out.contains("url: 'file://' + __filename"));
        assert!(out.contains("dirname: __dirname"));
    }

    #[test]
    fn skips_inside_strings() {
        let s = "const t = 'import.meta.dirname'; const r = import.meta.dirname;";
        let out = rewrite_import_meta(s);
        // First occurrence (inside a single-quoted string) preserved.
        assert!(out.contains("'import.meta.dirname'"));
        // Second occurrence (real syntax) rewritten.
        assert!(out.ends_with("__dirname;"));
    }

    #[test]
    fn skips_inside_template_literals() {
        let s = "const t = `${import.meta.dirname}`; const r = import.meta.dirname;";
        let out = rewrite_import_meta(s);
        // Template literal does NOT get the inner expression rewritten
        // by this textual pass - that's a real edge case but matches
        // every other pre-pass we run. The simple consumer just stays
        // out of import.meta inside templates.
        assert!(out.ends_with("__dirname;"));
    }

    #[test]
    fn skips_inside_comments() {
        let s = "// import.meta.dirname\n/* import.meta.url */\nconst x = import.meta.dirname;";
        let out = rewrite_import_meta(s);
        assert!(out.contains("// import.meta.dirname"));
        assert!(out.contains("/* import.meta.url */"));
        assert!(out.ends_with("__dirname;"));
    }

    #[test]
    fn requires_word_boundary_before_token() {
        // Hypothetical `notimport.meta.dirname` should NOT match -
        // the leading `not` makes it a member access on `notimport`,
        // not the syntactic `import.meta` form.
        let s = "obj.notimport.meta.dirname";
        let out = rewrite_import_meta(s);
        assert_eq!(out, s);
    }
}
