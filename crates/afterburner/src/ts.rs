// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! TypeScript strip-types via [oxc].
//!
//! Per Q4-locked decision: **strip-types only**. No type checking, no
//! type-based codegen, no JSX transform. `tsc --noEmit` stays the
//! user's concern.
//!
//! The oxc transformer preserves `isolatedModules` semantics — every
//! file is stripped independently, so cross-file const-enum inlining
//! and emit-based type imports don't apply. That matches how modern
//! bundlers (esbuild, bun, swc) handle TS strip.
//!
//! `.tsx` is rejected with a typed error. Adding JSX is outside the
//! strip-only scope; the plan's `JsxOptions` path can be wired later
//! behind a separate `jsx` feature.
//!
//! [oxc]: https://oxc.rs

use oxc::allocator::Allocator;
use oxc::codegen::Codegen;
use oxc::parser::Parser;
use oxc::semantic::SemanticBuilder;
use oxc::span::SourceType;
use oxc::transformer::{TransformOptions, Transformer, TypeScriptOptions};
use std::path::Path;

/// Transpile `source` from a TS file at `path` into plain JavaScript.
///
/// Returns `Err` if:
///
/// * `path`'s extension is `.tsx` — JSX transform isn't in the strip-
///   only scope. Callers get a clear message rather than a silent
///   "invalid JS" downstream error.
/// * The TS parser reports *syntactic* errors. Type errors are not
///   reported — that's `tsc`'s job.
/// * The extension resolver rejects the path (e.g. unknown extension
///   dressed as `.ts`).
pub fn transpile(source: &str, path: &Path) -> Result<String, TsError> {
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("tsx"))
    {
        return Err(TsError::JsxNotSupported);
    }
    let source_type = SourceType::from_path(path).map_err(|e| TsError::BadExtension {
        path: path.display().to_string(),
        inner: e.to_string(),
    })?;

    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() {
        return Err(TsError::Parse {
            path: path.display().to_string(),
            errors: parsed
                .errors
                .iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join("\n"),
        });
    }
    let mut program = parsed.program;

    // `only_remove_type_imports` tells the transformer to stop at
    // type-stripping — don't emit runtime helpers, don't rewrite
    // imports, don't do const-enum inlining. Matches `tsc
    // --isolatedModules` semantics, which is what modern bundlers
    // (esbuild, swc) emit in strip mode.
    let opts = TransformOptions {
        typescript: TypeScriptOptions {
            only_remove_type_imports: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let scoping = SemanticBuilder::new()
        .with_excess_capacity(2.0)
        .build(&program)
        .semantic
        .into_scoping();

    Transformer::new(&allocator, path, &opts).build_with_scoping(scoping, &mut program);

    // Codegen with inline source map: oxc emits the SourceMap, we
    // base64-data-url it onto the end of the file so stack traces
    // can map back to the original TS line numbers when source-map
    // support is enabled at runtime via
    // `module.setSourceMapsSupport(true)`.
    use oxc::codegen::CodegenOptions;
    let codegen = Codegen::new()
        .with_options(CodegenOptions {
            source_map_path: Some(path.to_path_buf()),
            ..Default::default()
        })
        .build(&program);
    let mut code = codegen.code;
    if let Some(map) = codegen.map.as_ref() {
        code.push_str("\n//# sourceMappingURL=");
        code.push_str(&map.to_data_url());
        code.push('\n');
    }
    // after TS strip, lower any remaining ESM declarations to
    // CJS so `import` / `export` in TS files runs under our existing
    // CommonJS runtime. Plain CJS code contains no ESM declarations
    // and passes through unchanged.
    crate::esm::rewrite_esm_to_cjs(&code, path).map_err(|e| TsError::Parse {
        path: path.display().to_string(),
        errors: e,
    })
}

/// Public helper for the CLI run path so `.js` / `.mjs` files with
/// `import` / `export` are lowered to CJS even without the TS strip.
/// No-op for plain CJS source — the function returns the input
/// unchanged if no ESM declarations are present.
pub fn lower_esm_js(source: &str, path: &Path) -> Result<String, TsError> {
    crate::esm::rewrite_esm_to_cjs(source, path).map_err(|e| TsError::Parse {
        path: path.display().to_string(),
        errors: e,
    })
}

/// Typed errors the transpile step surfaces. Separate from
/// [`AfterburnerError`] because TS parse/config errors aren't a
/// runtime sandbox concern — the callers at the CLI / library edge
/// convert them into user-facing messages.
///
/// [`AfterburnerError`]: crate::AfterburnerError
#[derive(Debug, thiserror::Error)]
pub enum TsError {
    #[error(
        ".tsx (JSX) is not supported by the strip-types transpiler; enable a JSX-aware feature or pre-transpile with an external tool"
    )]
    JsxNotSupported,

    #[error("{path}: TypeScript parse error:\n{errors}")]
    Parse { path: String, errors: String },

    #[error("{path}: unable to resolve source type from extension ({inner})")]
    BadExtension { path: String, inner: String },
}

/// True if `path` has a TypeScript extension we should auto-transpile
/// (`.ts`, `.mts`, `.cts`). `.tsx` matches but transpile will reject
/// it with [`TsError::JsxNotSupported`] — callers don't need to
/// filter that out themselves.
pub fn is_typescript(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("ts" | "mts" | "cts" | "tsx")
    )
}
