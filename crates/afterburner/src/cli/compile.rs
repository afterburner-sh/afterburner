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
//! Capability-bearing packages build a normal source-only `.afb` (the
//! same as `burn package`) and print one informational note to stderr.
//! No error, no silent gap.
//!
//! `javy` is required only here - the runtime never shells to it.
//! Required version: 8.1.1.

use afterburner_cloud::afterburner_afb::digest::hex;
use afterburner_cloud::afterburner_afb::pack::Builder;
use afterburner_cloud::pkg::{self, LocalPackage};
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
        compile_source_only(local, &out_path)
    }
}

/// Sealed package: run javy, bundle the wasm, set runtime.target.
fn compile_sealed(local: LocalPackage, out_path: &Path) -> Result<()> {
    // Locate the entry source. Entry is always under `source/` (validated by
    // LocalPackage::load), and the key in `local.sources` is the archive-
    // relative path, e.g. `"source/main.js"`.
    let entry_key = &local.manifest.package.entry;
    let entry_bytes = local.sources.get(entry_key).ok_or_else(|| {
        anyhow::anyhow!(
            "entry {:?} not found in loaded sources (this is a bug)",
            entry_key
        )
    })?;
    let entry_src = std::str::from_utf8(entry_bytes)
        .with_context(|| format!("entry {entry_key:?} is not UTF-8"))?;

    let wasm_bytes = style::spin("compiling to wasm", || javy_compile(entry_src))?;

    // Build the .afb with both source (unchanged) and the precompiled member.
    // Set runtime.target so the engine knows to look under precompiled/.
    let mut manifest = local.manifest.clone();
    manifest.runtime.target = Some("wasm32-wasip1".into());

    let mut b = Builder::new(manifest, local.manifold.clone());
    for (path, data) in &local.sources {
        b = b.source(path.clone(), data.clone());
    }
    b = b.precompiled("precompiled/wasm32-wasip1/main.wasm", wasm_bytes);

    let (bytes, digest) =
        style::spin("packing", || b.build()).context("building precompiled .afb")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(&coord_str(&local)),
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

/// Capability-bearing package: build source-only .afb and note the limitation.
fn compile_source_only(local: LocalPackage, out_path: &Path) -> Result<()> {
    eprintln!(
        "note: precompiled WASM is sealed-only for now; \
         this package has capability grants so it ships source (same as `burn package`)"
    );

    let (bytes, digest) =
        style::spin("packing", || local.build()).context("building source-only .afb")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {}",
        style::ok("packaged"),
        style::accent(&coord_str(&local))
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
    let invoke_result = run_javy(&javy, &src_path, &wasm_path);

    // Read the wasm bytes before cleaning up the work directory.
    let wasm_result = invoke_result
        .and_then(|()| std::fs::read(&wasm_path).with_context(|| "reading compiled wasm"));

    // Best-effort cleanup; do not propagate cleanup errors over the real result.
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

/// Invoke `javy build` to compile `src_path` to `wasm_path`.
/// Returns a clear, actionable error when `javy` is absent.
fn run_javy(javy: &str, src_path: &Path, wasm_path: &Path) -> Result<()> {
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
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "`javy` was not found on PATH. Install javy 8.1.1 to use `burn compile`.\n\
                     Download from: https://github.com/bytecodealliance/javy/releases/tag/v8.1.1"
                )
            } else {
                anyhow::anyhow!("spawning `{javy}`: {e}")
            }
        })?;

    if !status.success() {
        let code = status.code().map_or(-1, |c| c);
        anyhow::bail!("`javy build` exited with code {code}");
    }
    Ok(())
}
