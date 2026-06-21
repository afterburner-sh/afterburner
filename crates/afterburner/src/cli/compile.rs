// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn compile [dir] -o <out>` - build a pre-compiled `.afb`.
//!
//! For sealed packages (no capability grants), this command wraps the
//! package's `source/main.js` in a stdin/stdout harness, invokes `javy`
//! (a build-time tool) to produce a self-contained `wasm32-wasip1` module,
//! and packs the result into a `.afb` alongside the original source. The
//! engine's `register_precompiled` path then loads the module directly
//! instead of compiling JS per call.
//!
//! For capability-bearing packages (non-sealed manifold), this command
//! produces a dynamically-linked `wasm32-wasip1-dyn` module via
//! `javy build -C dynamic -C plugin=...`. The dyn module imports from the
//! shared Afterburner Javy plugin at runtime, so capability gating is
//! enforced by the engine's two-instance linking model: the plugin's
//! `afterburner:host` imports carry the caller's `Manifold`, and a
//! `crypto.createHash` call is denied under a sealed Manifold and granted
//! under one with `crypto: true`.
//!
//! `javy` is required only here - the runtime never shells to it.
//! Required version: 8.1.1.

use afterburner_cloud::afterburner_afb::Afb;
use afterburner_cloud::afterburner_afb::digest::{digest, hex};
use afterburner_cloud::afterburner_afb::pack::Builder;
use afterburner_cloud::pkg::{self, LocalPackage};
use afterburner_node_compat::PLENUM_BUNDLE;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use super::registry::{coord_str, print_digest, transpile_ts_sources};
use super::style;

/// `burn compile [dir] -o <out>` entry point.
pub fn compile(dir: Option<&Path>, out: Option<&Path>) -> Result<()> {
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let mut local = pkg::LocalPackage::load(dir)?;
    transpile_ts_sources(&mut local)?;

    let out_path = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(local.output_filename()));

    if local.manifold.is_sealed() {
        compile_sealed(local, &out_path)
    } else {
        compile_capability(local, &out_path)
    }
}

/// Sealed package: run javy on the EFFECTIVE source, bundle the wasm, set
/// runtime.target.
///
/// For multi-file packages the effective source is the linked composition
/// (virtual FS + require bootstrap) produced by `Afb::linked_source` - the
/// same source the runtime's warm path uses. For single-file packages it is
/// the bare entry, as before.
///
/// If linking fails because the package declares external afb dependencies
/// that cannot be resolved at compile time, we fall back to a source-only
/// `.afb` and print a clear note so the caller is never left with a broken
/// precompiled module.
fn compile_sealed(local: LocalPackage, out_path: &Path) -> Result<()> {
    let coord = coord_str(&local);

    // Build a source-only .afb first so we can reparse it and call the
    // standard linker. This reuses the same code path as `burn package`.
    let (source_bytes, _) =
        style::spin("packing source", || local.build()).context("building source .afb")?;

    let afb = Afb::from_bytes(&source_bytes).context("reparsing source .afb (this is a bug)")?;

    // Compute the effective JS source the engine would compile.
    // For multi-file packages, the linked source uses require() on the
    // virtual filesystem. Javy's QuickJS environment has no built-in
    // require(), so prepend the plenum bundle which installs it globally.
    let effective_src: String = if afb.needs_linking() {
        match afb.linked_source(&[], &[]) {
            Ok(src) => format!("{PLENUM_BUNDLE}\n{src}"),
            Err(e) => {
                // The package declares external afb dependencies that we
                // cannot resolve at compile time. Emit a source-only .afb
                // and a clear note rather than a broken precompiled module.
                eprintln!(
                    "note: precompiled WASM does not yet support dependency-linked \
                     packages ({e}); shipping source-only .afb instead"
                );
                std::fs::write(out_path, &source_bytes)
                    .with_context(|| format!("writing {}", out_path.display()))?;
                let digest = digest(&source_bytes);
                println!("{} {}", style::ok("packaged"), style::accent(&coord));
                print_digest(source_bytes.len() as u64, &hex(&digest));
                println!(
                    "  {} {}",
                    style::muted("->"),
                    style::value(&out_path.display().to_string())
                );
                return Ok(());
            }
        }
    } else {
        afb.entry_source()
            .context("reading entry source")?
            .to_owned()
    };

    let wasm_bytes = style::spin("compiling to wasm", || javy_compile(&effective_src))?;

    // Build the final .afb with both source (unchanged) and the precompiled
    // member. Set runtime.target so the engine knows to look under precompiled/.
    let mut manifest = afb.manifest.clone();
    manifest.runtime.target = Some("wasm32-wasip1".into());

    let mut b = Builder::new(manifest, afb.manifold.clone());
    for (path, data) in &afb.source {
        b = b.source(path.clone(), data.clone());
    }
    b = b.precompiled("precompiled/wasm32-wasip1/main.wasm", wasm_bytes);

    let (bytes, digest) =
        style::spin("packing", || b.build()).context("building precompiled .afb")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(&coord),
        style::gold("(precompiled wasm32-wasip1)")
    );
    print_digest(bytes.len() as u64, &hex(&digest));
    println!(
        "  {} {}",
        style::muted("->"),
        style::value(&out_path.display().to_string())
    );
    Ok(())
}

/// Capability-bearing package: build a dynamically-linked `.afb`.
///
/// The dyn module imports from the shared Afterburner Javy plugin at runtime
/// (two-instance linking model). Capability gating is preserved: the plugin's
/// `afterburner:host` imports carry the caller's `Manifold`.
///
/// Falls back to source-only if `javy` is absent or the dyn build fails.
fn compile_capability(local: LocalPackage, out_path: &Path) -> Result<()> {
    let coord = coord_str(&local);

    // Build a source-only .afb first so we can reparse and use the linker.
    let (source_bytes, _) =
        style::spin("packing source", || local.build()).context("building source .afb")?;

    let afb = Afb::from_bytes(&source_bytes).context("reparsing source .afb (this is a bug)")?;

    // Compute the effective JS source the engine would compile.
    let effective_src: String = if afb.needs_linking() {
        match afb.linked_source(&[], &[]) {
            Ok(src) => format!("{PLENUM_BUNDLE}\n{src}"),
            Err(e) => {
                eprintln!(
                    "note: precompiled dyn WASM does not support dependency-linked \
                     packages ({e}); shipping source-only .afb instead"
                );
                std::fs::write(out_path, &source_bytes)
                    .with_context(|| format!("writing {}", out_path.display()))?;
                let digest = digest(&source_bytes);
                println!("{} {}", style::ok("packaged"), style::accent(&coord));
                print_digest(source_bytes.len() as u64, &hex(&digest));
                println!(
                    "  {} {}",
                    style::muted("->"),
                    style::value(&out_path.display().to_string())
                );
                return Ok(());
            }
        }
    } else {
        afb.entry_source()
            .context("reading entry source")?
            .to_owned()
    };

    // Attempt the dynamically-linked build. Fall back to source-only when javy
    // is absent or the build fails (a clear note is always emitted).
    let wasm_result = style::spin("compiling to dyn wasm", || javy_compile_dyn(&effective_src));
    let wasm_bytes = match wasm_result {
        Ok(b) => b,
        Err(e) => {
            eprintln!("note: dyn WASM build failed ({e}); shipping source-only .afb instead");
            std::fs::write(out_path, &source_bytes)
                .with_context(|| format!("writing {}", out_path.display()))?;
            let digest = digest(&source_bytes);
            println!("{} {}", style::ok("packaged"), style::accent(&coord));
            print_digest(source_bytes.len() as u64, &hex(&digest));
            println!(
                "  {} {}",
                style::muted("->"),
                style::value(&out_path.display().to_string())
            );
            return Ok(());
        }
    };

    let mut manifest = afb.manifest.clone();
    manifest.runtime.target = Some("wasm32-wasip1-dyn".into());

    let mut b = Builder::new(manifest, afb.manifold.clone());
    for (path, data) in &afb.source {
        b = b.source(path.clone(), data.clone());
    }
    b = b.precompiled("precompiled/wasm32-wasip1-dyn/main.wasm", wasm_bytes);

    let (bytes, digest) = style::spin("packing", || b.build()).context("building dyn .afb")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(&coord),
        style::gold("(precompiled wasm32-wasip1-dyn)")
    );
    print_digest(bytes.len() as u64, &hex(&digest));
    println!(
        "  {} {}",
        style::muted("->"),
        style::value(&out_path.display().to_string())
    );
    Ok(())
}

/// Wrap `source_js` in the stdin/stdout harness, invoke `javy`, and return
/// the compiled WASM bytes. Shells out to the `javy` binary (build-time
/// only; the engine never calls this function).
///
/// The wrapper pattern is taken from `crates/afterburner-wasi/tests/fixtures/build.sh`:
/// - A `const module = { exports: undefined };` preamble lets a CommonJS
///   `module.exports = fn` assignment work inside a WASI module.
/// - A Javy.IO stdin/stdout harness reads JSON, calls the exported function,
///   and writes the JSON result back.
/// - `javy build -J event-loop=y -J javy-stream-io=y -C deterministic=y`
///   produces a deterministic, self-contained wasm32-wasip1 module.
fn javy_compile(source_js: &str) -> Result<Vec<u8>> {
    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());

    // Use a dedicated temp directory keyed by process ID so concurrent
    // `burn compile` invocations don't collide.
    let work_dir = std::env::temp_dir().join(format!("burn-compile-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir).context("creating work directory")?;

    let src_path = work_dir.join("wrapped.js");
    let wasm_path = work_dir.join("main.wasm");

    // Build the wrapped source: preamble + original source + harness.
    let wrapped = build_wrapped_source(source_js);
    std::fs::write(&src_path, wrapped.as_bytes()).context("writing wrapped source")?;

    // Invoke javy; capture the outcome so we can clean up regardless.
    let invoke_result = run_javy_sealed(&javy, &src_path, &wasm_path);

    // Read the wasm bytes before cleaning up the work directory.
    let wasm_result = invoke_result
        .and_then(|()| std::fs::read(&wasm_path).with_context(|| "reading compiled wasm"));

    // Best-effort cleanup; do not propagate cleanup errors over the real result.
    let _ = std::fs::remove_dir_all(&work_dir);

    wasm_result
}

/// Wrap `source_js` in the stdin/stdout harness, invoke `javy build -C dynamic`
/// against the embedded Afterburner plugin, and return the compiled WASM bytes.
///
/// The dyn module imports `afterburner-plugin-v1::{cabi_realloc, invoke, memory}`
/// from the shared plugin at runtime instead of bundling QuickJS inline.
/// `-J` flags (event-loop, stream-io) are NOT passed when `-C plugin=...` is in
/// use; those options are only valid for the built-in plugin.
fn javy_compile_dyn(source_js: &str) -> Result<Vec<u8>> {
    use afterburner_wasi::AFTERBURNER_PLUGIN_BYTES;

    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());

    let work_dir = std::env::temp_dir().join(format!("burn-compile-dyn-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir).context("creating dyn work directory")?;

    let src_path = work_dir.join("wrapped.js");
    let wasm_path = work_dir.join("main.wasm");
    let plugin_path = work_dir.join("afterburner_plugin.wasm");

    // Write the plugin bytes so javy can reference them by path.
    std::fs::write(&plugin_path, AFTERBURNER_PLUGIN_BYTES)
        .context("writing plugin wasm for dyn build")?;

    let wrapped = build_wrapped_source(source_js);
    std::fs::write(&src_path, wrapped.as_bytes()).context("writing wrapped source")?;

    let invoke_result = run_javy_dyn(&javy, &src_path, &wasm_path, &plugin_path);

    let wasm_result = invoke_result
        .and_then(|()| std::fs::read(&wasm_path).with_context(|| "reading compiled dyn wasm"));

    let _ = std::fs::remove_dir_all(&work_dir);

    wasm_result
}

/// Build the wrapped JS source string: CommonJS preamble + user source +
/// Javy.IO stdin/stdout harness (the pattern from build.sh).
fn build_wrapped_source(source_js: &str) -> String {
    format!(
        "const module = {{ exports: undefined }};\n\
         {source_js}\n\
         const __fn = module.exports;\n\
         const __chunks = [];\n\
         const __buf = new Uint8Array(65536);\n\
         while (true) {{ const n = Javy.IO.readSync(0, __buf); if (n <= 0) break; __chunks.push(__buf.slice(0, n)); }}\n\
         let __t = 0; for (const c of __chunks) __t += c.length;\n\
         const __all = new Uint8Array(__t);\n\
         let __o = 0; for (const c of __chunks) {{ __all.set(c, __o); __o += c.length; }}\n\
         const __in = JSON.parse(new TextDecoder().decode(__all));\n\
         const __res = __fn(__in);\n\
         Javy.IO.writeSync(1, new TextEncoder().encode(JSON.stringify(__res)));\n",
        source_js = source_js,
    )
}

/// Invoke `javy build` for a sealed (self-contained) module.
/// Returns a clear, actionable error when `javy` is absent.
fn run_javy_sealed(javy: &str, src_path: &Path, wasm_path: &Path) -> Result<()> {
    let status = std::process::Command::new(javy)
        .args([
            "build",
            "-J",
            "event-loop=y",
            "-J",
            "javy-stream-io=y",
            "-C",
            "deterministic=y",
            src_path.to_str().unwrap_or(""),
            "-o",
            wasm_path.to_str().unwrap_or(""),
        ])
        .status()
        .map_err(|e| javy_not_found_or(javy, e))?;

    if !status.success() {
        let code = status.code().map_or(-1, |c| c);
        anyhow::bail!("`javy build` (sealed) exited with code {code}");
    }
    Ok(())
}

/// Invoke `javy build -C dynamic` for a dynamically-linked module.
/// The `-J` options are not compatible with `-C plugin=...` and are omitted.
fn run_javy_dyn(javy: &str, src_path: &Path, wasm_path: &Path, plugin_path: &Path) -> Result<()> {
    let plugin_arg = format!("plugin={}", plugin_path.to_str().unwrap_or(""));
    let status = std::process::Command::new(javy)
        .args([
            "build",
            "-C",
            "dynamic",
            "-C",
            &plugin_arg,
            "-C",
            "deterministic=y",
            src_path.to_str().unwrap_or(""),
            "-o",
            wasm_path.to_str().unwrap_or(""),
        ])
        .status()
        .map_err(|e| javy_not_found_or(javy, e))?;

    if !status.success() {
        let code = status.code().map_or(-1, |c| c);
        anyhow::bail!("`javy build` (dyn) exited with code {code}");
    }
    Ok(())
}

/// Map a spawn error to a helpful "javy not found" message or a generic
/// spawn error.
fn javy_not_found_or(javy: &str, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!(
            "`javy` was not found on PATH. Install javy 8.1.1 to use `burn compile`.\n\
             Download from: https://github.com/bytecodealliance/javy/releases/tag/v8.1.1"
        )
    } else {
        anyhow::anyhow!("spawning `{javy}`: {e}")
    }
}
