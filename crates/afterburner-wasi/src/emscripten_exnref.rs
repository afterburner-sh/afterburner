// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! In-process legacy-EH -> exnref translation for Emscripten SIDE_MODULE `.so`
//! files.
//!
//! ## Why this exists
//!
//! The deterministic engine ([`crate::embedder_vm::deterministic_engine`]) enables
//! the new exnref/`try_table` exception-handling proposal, not the legacy
//! try/catch proposal: wasmtime's Cranelift backend dropped legacy-EH code
//! generation, so a module that contains the legacy `try` instruction is
//! rejected at compile time with
//! `legacy_exceptions feature required for try instruction`.
//!
//! The main runtime wasm is translated to exnref ahead of time, and the
//! runtime-bundle engine ([`crate::bundle`] / `bundle_fetch.rs`) likewise
//! repackages each wheel with its `.so` translated. But a SIDE_MODULE
//! that reaches the engine straight from a *stock* wheel (the `dlopen` /
//! `pre_load_side_module` path mounting an untranslated wheel) is still legacy.
//!
//! CPython 3.14's Pyodide is built with a newer Emscripten/LLVM that emits
//! legacy EH in the C-extension `.so` (e.g. numpy's `_multiarray_umath.so`),
//! where the CPython 3.13 / Pyodide 0.28.x wheels happened not to for the
//! modules on the import path. So on 3.14 the very first side module CPython
//! `dlopen`s fails to compile, surfacing as the generic
//! `ImportError: unknown dlopen() error`.
//!
//! ## What this does
//!
//! [`maybe_translate_side_module`] detects whether a `.so`'s code uses the
//! legacy-EH encoding and, only then, runs the same `wasm-opt
//! --translate-to-exnref` lowering the build bundler uses to rewrite the EH
//! sections into `try_table`. The translation operates on the already-built
//! stock `.so` bytes (an EH-proposal re-encoding of an existing object file);
//! it never recompiles the wheel from source and never mutates the wheel on
//! disk. A `.so` with no EH, or one already in exnref form, is returned
//! untouched (zero overhead, byte-identical input).
//!
//! ## Determinism
//!
//! `wasm-opt --translate-to-exnref` is a pure function of its input bytes and
//! flags, so a given stock `.so` always lowers to the same exnref bytes (the
//! build bundler relies on this same byte-stability to cache its output). The
//! translated bytes are therefore identical across runs, the compiled native
//! code is identical, and a `.so`-loading path consumes identical fuel on every
//! run. Results are cached on disk keyed by the SHA-256 of the stock bytes (in
//! the owner-only private cache dir) so repeated loads and repeated processes
//! skip the lowering entirely.

use std::path::PathBuf;
use std::process::Command;

use afterburner_core::{AfterburnerError, Result};
use wasmparser::{Operator, Parser, Payload};

use crate::pyo_trace;

/// `wasm-opt` flags that translate legacy try/catch EH to the exnref proposal
/// while preserving the SIDE_MODULE structure (the `dylink.0` custom section,
/// the `GOT.func` / `GOT.mem` imports, and the active element segments).
///
/// Kept byte-for-byte in sync with the runtime-bundle engine's
/// `bundle_fetch::WASM_OPT_FLAGS`: the on-demand `.so` translation here and the
/// bundle assembly there must apply the identical lowering so a stock `.so`
/// translated on this path is the same as one translated when the bundle is
/// assembled. `bundle_fetch.rs` is `#[path]`-included into both the runtime and
/// the build script, so its copy serves the build-time prefetch too; a
/// divergence would mean a runtime-translated `.so` differs from its bundled
/// twin.
const WASM_OPT_FLAGS: &[&str] = &[
    "--translate-to-exnref",
    "--enable-exception-handling",
    "--enable-reference-types",
    "--enable-bulk-memory",
    "--enable-simd",
    "--enable-sign-ext",
    "--enable-nontrapping-float-to-int",
    "--enable-mutable-globals",
    "--enable-multivalue",
];

/// Return the `.so` bytes the engine should compile: the input borrowed
/// unchanged when it carries no legacy EH, or an owned `wasm-opt
/// --translate-to-exnref` lowering of it when it does.
///
/// `path` is the guest path of the `.so`, used only for diagnostics. Returning a
/// [`Cow`](std::borrow::Cow) keeps the no-translation path zero-copy (a
/// SIDE_MODULE `.so` is up to ~100 MiB - polars - and is most commonly already
/// exnref via the bundled runtime, so cloning it would be pure waste), while the
/// translated path owns a fresh buffer. The caller derefs either to `&[u8]` for
/// `Module::new`.
///
/// # Errors
///
/// Returns `Err` only when a translation is *required* but cannot be performed:
/// `wasm-opt` is not on `PATH` (nor at the emsdk fallback), or it fails. The
/// message names the stock-vs-bundled distinction so the fix (install `wasm-opt`
/// or use the bundled runtime) is actionable. A `.so` that needs no translation
/// never touches `wasm-opt` and so never fails here.
pub fn maybe_translate_side_module<'a>(
    wasm_bytes: &'a [u8],
    path: &str,
) -> Result<std::borrow::Cow<'a, [u8]>> {
    if !uses_legacy_eh(wasm_bytes) {
        return Ok(std::borrow::Cow::Borrowed(wasm_bytes));
    }
    pyo_trace!("[exnref] {path}: legacy-EH detected, translating to exnref");
    Ok(std::borrow::Cow::Owned(translate_to_exnref(
        wasm_bytes, path,
    )?))
}

/// Detect whether a wasm module's code section uses the legacy-EH encoding
/// (the `try` / `catch` / `catch_all` / `delegate` / `rethrow` instructions).
///
/// `wasmparser::Parser::new` decodes with `WasmFeatures::all()`, so legacy-EH
/// instructions parse into their dedicated [`Operator`] variants rather than
/// erroring. We match on those variants directly: it is wasmparser's own
/// decoding of the bytes, not a scan for opcode values (which also occur as
/// instruction immediates and so cannot be matched by hand). The exnref
/// proposal instead uses `try_table` ([`Operator::TryTable`]), which is *not*
/// matched here, so an already-translated module reads as not-legacy.
///
/// Reading stops at the first legacy op in the first function that has one, so
/// a legacy module is detected cheaply; an exnref / no-EH module is confirmed
/// only after a full (but allocation-free) operator walk. A per-function parse
/// error ends that function's walk without flagging it: a genuine malformation
/// is left for `Module::new` to report authoritatively, rather than this
/// detector masking it as an EH issue.
fn uses_legacy_eh(wasm_bytes: &[u8]) -> bool {
    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let Ok(Payload::CodeSectionEntry(body)) = payload else {
            continue;
        };
        let Ok(mut ops) = body.get_operators_reader() else {
            continue;
        };
        while !ops.eof() {
            match ops.read() {
                Ok(
                    Operator::Try { .. }
                    | Operator::Catch { .. }
                    | Operator::CatchAll
                    | Operator::Delegate { .. }
                    | Operator::Rethrow { .. },
                ) => return true,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
    false
}

/// Translate `wasm_bytes` to exnref via `wasm-opt --translate-to-exnref`,
/// caching the result on disk keyed by the SHA-256 of the input.
///
/// The cache lives in the owner-only private cache dir
/// (`wasm_engine::private_cache_dir`); a cache hit returns the stored
/// bytes with no `wasm-opt` invocation. On a miss the lowering runs and the
/// result is written back (best-effort: a write failure is a warning, not an
/// error, and the freshly translated bytes are still returned).
fn translate_to_exnref(wasm_bytes: &[u8], path: &str) -> Result<Vec<u8>> {
    let key = hex::encode(afterburner_core::sha256(wasm_bytes));
    let cache_path = cache_dir().map(|d| d.join(format!("exnref-{key}.so")));

    if let Some(cp) = cache_path.as_ref()
        && let Ok(cached) = std::fs::read(cp)
        && !cached.is_empty()
    {
        pyo_trace!("[exnref] {path}: cache hit ({} bytes)", cached.len());
        return Ok(cached);
    }

    let wasm_opt = find_wasm_opt().ok_or_else(|| {
        AfterburnerError::Engine(format!(
            "side module {path} uses legacy exception-handling and must be translated to exnref, \
             but `wasm-opt` was not found on PATH, at $BURN_WASM_OPT, or at \
             $HOME/emsdk/upstream/bin/wasm-opt. Install Binaryen (wasm-opt), or run the bundled \
             Python runtime whose wheels are translated at build time."
        ))
    })?;

    // Use per-process-unique temp files in the private cache dir so neither two
    // translations within this process nor the same `.so` translated by another
    // process race on the same path (the shared, deterministic artifact is the
    // content-addressed cache file written at the end, not these scratch files).
    // `wasm-opt` reads/writes files, not stdio, so a temp round-trip is required.
    let tmp_dir = cache_dir().unwrap_or_else(std::env::temp_dir);
    let uniq = format!("{}-{key}", std::process::id());
    let in_path = tmp_dir.join(format!("exnref-in-{uniq}.wasm"));
    let out_path = tmp_dir.join(format!("exnref-out-{uniq}.wasm"));
    std::fs::write(&in_path, wasm_bytes).map_err(|e| {
        AfterburnerError::Engine(format!("exnref translate {path}: write input: {e}"))
    })?;

    let status = Command::new(&wasm_opt)
        .args(WASM_OPT_FLAGS)
        .arg(&in_path)
        .arg("-o")
        .arg(&out_path)
        .status();
    let _ = std::fs::remove_file(&in_path);

    let status = status.map_err(|e| {
        AfterburnerError::Engine(format!("exnref translate {path}: spawn wasm-opt: {e}"))
    })?;
    if !status.success() {
        let _ = std::fs::remove_file(&out_path);
        return Err(AfterburnerError::Engine(format!(
            "exnref translate {path}: wasm-opt exited {status}"
        )));
    }

    let translated = std::fs::read(&out_path).map_err(|e| {
        AfterburnerError::Engine(format!("exnref translate {path}: read output: {e}"))
    })?;
    let _ = std::fs::remove_file(&out_path);

    // Write-back to the content-addressed cache (best-effort).
    if let Some(cp) = cache_path.as_ref()
        && let Err(e) = std::fs::write(cp, &translated)
    {
        pyo_trace!("[exnref] {path}: cache write failed: {e}");
    }

    pyo_trace!(
        "[exnref] {path}: translated {} -> {} bytes",
        wasm_bytes.len(),
        translated.len()
    );
    Ok(translated)
}

/// The owner-only private cache dir, or `None` when unavailable. Thin re-export
/// of the engine's cache-dir helper so translated `.so` files sit alongside the
/// `.cwasm` compile cache under one owner-only root.
fn cache_dir() -> Option<PathBuf> {
    crate::wasm_engine::private_cache_dir()
}

/// Locate `wasm-opt` at runtime: `$BURN_WASM_OPT` first (an explicit override),
/// then `PATH`, then the emsdk fallback Pyodide builds ship. Returns `None` when
/// none is present (the caller then surfaces an actionable error only if a
/// translation was actually required).
///
/// Mirrors the build-time `build::find_wasm_opt`, with the `$BURN_WASM_OPT`
/// override added for the runtime (a build runs in a known toolchain; a runtime
/// may need to be pointed at a specific binary). The two cannot share code: the
/// build helper lives in the build script's own crate graph.
fn find_wasm_opt() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BURN_WASM_OPT") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(out) = Command::new("wasm-opt").arg("--version").output()
        && out.status.success()
    {
        return Some(PathBuf::from("wasm-opt"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = PathBuf::from(home).join("emsdk/upstream/bin/wasm-opt");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid wasm module with no code section at all uses no EH.
    #[test]
    fn empty_module_is_not_legacy() {
        // `\0asm` + version 1, no sections.
        let wasm = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert!(!uses_legacy_eh(&wasm));
    }

    /// A no-EH module is returned byte-identical and zero-copy (a borrowed
    /// `Cow`, never rewritten or cloned) and never touches `wasm-opt`.
    #[test]
    fn no_eh_module_is_passthrough() {
        let wasm = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let out = maybe_translate_side_module(&wasm, "test.so").expect("passthrough");
        assert!(
            matches!(out, std::borrow::Cow::Borrowed(_)),
            "no-EH module must pass through as a zero-copy borrow"
        );
        assert_eq!(
            out.as_ref(),
            wasm.as_slice(),
            "no-EH module must pass through unchanged"
        );
    }

    /// Garbage that is not a wasm module parses to zero code entries, so it is
    /// classified as not-legacy and handed on (the engine then rejects it with
    /// the authoritative error rather than this detector masking it).
    #[test]
    fn non_wasm_is_not_legacy() {
        assert!(!uses_legacy_eh(b"not a wasm module at all"));
    }
}
