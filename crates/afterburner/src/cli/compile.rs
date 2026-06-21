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

use afterburner_cloud::afterburner_afb::digest::{digest, hex};
use afterburner_cloud::afterburner_afb::pack::Builder;
use afterburner_cloud::afterburner_afb::{Afb, DepReq, parse_dep_req};
use afterburner_cloud::pkg::{self, LocalPackage};
use afterburner_node_compat::PLENUM_BUNDLE;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::registry::{coord_str, print_digest, transpile_ts_sources};
use super::style;

/// Resolve the transitive closure of local filesystem dependencies for a package.
///
/// For each `"ns/name" = range_or_pin` entry in `deps`, this function loads the
/// sibling package from `packages_dir/<name>/`, builds a source `.afb`, validates
/// the version or digest against the declared requirement, and recurses into that
/// dep's own `[dependencies]`. Returns the full closure in deps-before-dependents
/// order (leaves first), deduped by coordinate. Mirrors `resolve_dep_closure` in
/// the burndb runtime.
///
/// Returns an error if any sibling directory is absent or the version check fails,
/// so the caller's source-only fallback fires with a clear message.
fn resolve_local_deps(
    deps: &BTreeMap<String, String>,
    packages_dir: &Path,
) -> Result<Vec<(String, Afb)>> {
    let mut resolved: BTreeMap<String, Afb> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for (coord, value) in deps {
        resolve_one(coord, value, packages_dir, &mut resolved, &mut order)?;
    }
    Ok(order
        .into_iter()
        .map(|c| {
            let a = resolved.remove(&c).unwrap();
            (c, a)
        })
        .collect())
}

/// Recursively resolve a single dependency and its transitive closure, appending
/// to `resolved`/`order` in topological order (leaves before dependents).
fn resolve_one(
    coord: &str,
    value: &str,
    packages_dir: &Path,
    resolved: &mut BTreeMap<String, Afb>,
    order: &mut Vec<String>,
) -> Result<()> {
    if resolved.contains_key(coord) {
        return Ok(()); // diamond dep - resolve each coordinate once
    }
    // Derive local dir name from "ns/name" -> "name".
    let local_name = coord.rsplit_once('/').map(|(_, n)| n).unwrap_or(coord);
    let dep_dir = packages_dir.join(local_name);
    let mut dep_local = pkg::LocalPackage::load(&dep_dir)
        .with_context(|| format!("loading local dep {coord:?} from {}", dep_dir.display()))?;
    super::registry::transpile_ts_sources(&mut dep_local)?;
    let (dep_bytes, _) = dep_local
        .build()
        .with_context(|| format!("building dep {coord:?}"))?;
    let dep_afb =
        Afb::from_bytes(&dep_bytes).with_context(|| format!("parsing built dep {coord:?}"))?;

    // Validate the declared requirement against the local dep's version/digest.
    let req = parse_dep_req(value)
        .with_context(|| format!("dep {coord:?}: invalid requirement {value:?}"))?;
    match &req {
        DepReq::Pin(pin) => {
            let actual = format!("sha256:{}", hex(&dep_afb.digest));
            if &actual != pin {
                anyhow::bail!("local dep {coord:?} digest {actual} does not match pinned {pin}");
            }
        }
        DepReq::Range(vreq) => {
            let dep_ver =
                semver::Version::parse(&dep_afb.manifest.package.version).with_context(|| {
                    format!(
                        "local dep {coord:?} has invalid version {:?}",
                        dep_afb.manifest.package.version
                    )
                })?;
            if !vreq.matches(&dep_ver) {
                anyhow::bail!("local dep {coord:?} version {dep_ver} does not satisfy {vreq}");
            }
        }
    }

    // Insert before recursing: guards against cycles in the dep graph.
    let child_deps = dep_afb.manifest.dependencies.clone();
    resolved.insert(coord.to_string(), dep_afb);

    // Recurse into transitive deps first (topological: leaves before roots).
    for (child_coord, child_val) in &child_deps {
        resolve_one(child_coord, child_val, packages_dir, resolved, order)?;
    }
    order.push(coord.to_string());
    Ok(())
}

/// `burn compile [dir] -o <out>` entry point.
pub fn compile(dir: Option<&Path>, out: Option<&Path>, packages_dir: Option<&Path>) -> Result<()> {
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let mut local = pkg::LocalPackage::load(dir)?;
    transpile_ts_sources(&mut local)?;

    let out_path = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(local.output_filename()));

    // Default packages_dir: parent of the package dir (monorepo siblings layout).
    let default_packages_dir: PathBuf;
    let packages_dir: &Path = match packages_dir {
        Some(p) => p,
        None => {
            default_packages_dir = dir.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
            &default_packages_dir
        }
    };

    compile_with_local_package(local, packages_dir, &out_path)
}

/// Compile a local package to a precompiled `.afb`, writing to `out_path`.
/// Used by `burn compile`, `burn package --compile`, and `burn publish --compile`.
pub fn compile_with_local_package(
    local: LocalPackage,
    packages_dir: &Path,
    out_path: &Path,
) -> Result<()> {
    if local.manifold.is_sealed() {
        compile_sealed(local, out_path, packages_dir)
    } else {
        compile_capability(local, out_path, packages_dir)
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
/// Local dep resolution via `--packages-dir` is attempted first. If linking
/// fails (missing dep dir or real error), we fall back to a source-only `.afb`
/// and print a clear note so the caller is never left with a broken precompiled
/// module.
fn compile_sealed(local: LocalPackage, out_path: &Path, packages_dir: &Path) -> Result<()> {
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
        let link_result = (|| -> Result<String> {
            let deps = resolve_local_deps(&afb.manifest.dependencies, packages_dir)?;
            let refs: Vec<(&str, &Afb)> = deps.iter().map(|(c, a)| (c.as_str(), a)).collect();
            let src = afb.linked_source(&refs, &[]).context("linking source")?;
            Ok(format!("{PLENUM_BUNDLE}\n{src}"))
        })();
        match link_result {
            Ok(src) => src,
            Err(e) => {
                // Local dep resolution or linking failed: emit source-only .afb
                // with a clear note. The caller is never left with a broken module.
                eprintln!(
                    "note: precompiled WASM does not yet support dependency-linked \
                     packages ({e}); shipping source-only .afb instead"
                );
                std::fs::write(out_path, &source_bytes)
                    .with_context(|| format!("writing {}", out_path.display()))?;
                let d = digest(&source_bytes);
                println!("{} {}", style::ok("packaged"), style::accent(&coord));
                print_digest(source_bytes.len() as u64, &hex(&d));
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
    let batch_wasm_bytes = style::spin("compiling batch wasm", || {
        javy_compile_batch(&effective_src)
    })?;
    let columnar_wasm_bytes = style::spin("compiling columnar wasm", || {
        javy_compile_columnar(&effective_src)
    })?;

    // Build the final .afb with source (unchanged) plus three precompiled members:
    //   precompiled/wasm32-wasip1/main.wasm         - single-row JSON in/out
    //   precompiled/wasm32-wasip1-batch/main.wasm   - array-in / array-out
    //   precompiled/wasm32-wasip1-columnar/main.wasm - binary-frame in/out
    // Set runtime.target so the engine knows to look under precompiled/.
    let mut manifest = afb.manifest.clone();
    manifest.runtime.target = Some("wasm32-wasip1".into());

    let mut b = Builder::new(manifest, afb.manifold.clone());
    for (path, data) in &afb.source {
        b = b.source(path.clone(), data.clone());
    }
    b = b.precompiled("precompiled/wasm32-wasip1/main.wasm", wasm_bytes);
    b = b.precompiled(
        "precompiled/wasm32-wasip1-batch/main.wasm",
        batch_wasm_bytes,
    );
    b = b.precompiled(
        "precompiled/wasm32-wasip1-columnar/main.wasm",
        columnar_wasm_bytes,
    );

    let (bytes, d) = style::spin("packing", || b.build()).context("building precompiled .afb")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(&coord),
        style::gold("(precompiled wasm32-wasip1)")
    );
    print_digest(bytes.len() as u64, &hex(&d));
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
fn compile_capability(local: LocalPackage, out_path: &Path, packages_dir: &Path) -> Result<()> {
    let coord = coord_str(&local);

    // Build a source-only .afb first so we can reparse and use the linker.
    let (source_bytes, _) =
        style::spin("packing source", || local.build()).context("building source .afb")?;

    let afb = Afb::from_bytes(&source_bytes).context("reparsing source .afb (this is a bug)")?;

    // Compute the effective JS source the engine would compile.
    let effective_src: String = if afb.needs_linking() {
        let link_result = (|| -> Result<String> {
            let deps = resolve_local_deps(&afb.manifest.dependencies, packages_dir)?;
            let refs: Vec<(&str, &Afb)> = deps.iter().map(|(c, a)| (c.as_str(), a)).collect();
            let src = afb.linked_source(&refs, &[]).context("linking source")?;
            Ok(format!("{PLENUM_BUNDLE}\n{src}"))
        })();
        match link_result {
            Ok(src) => src,
            Err(e) => {
                eprintln!(
                    "note: precompiled dyn WASM does not support dependency-linked \
                     packages ({e}); shipping source-only .afb instead"
                );
                std::fs::write(out_path, &source_bytes)
                    .with_context(|| format!("writing {}", out_path.display()))?;
                let d = digest(&source_bytes);
                println!("{} {}", style::ok("packaged"), style::accent(&coord));
                print_digest(source_bytes.len() as u64, &hex(&d));
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
            let d = digest(&source_bytes);
            println!("{} {}", style::ok("packaged"), style::accent(&coord));
            print_digest(source_bytes.len() as u64, &hex(&d));
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

    let (bytes, d) = style::spin("packing", || b.build()).context("building dyn .afb")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(&coord),
        style::gold("(precompiled wasm32-wasip1-dyn)")
    );
    print_digest(bytes.len() as u64, &hex(&d));
    println!(
        "  {} {}",
        style::muted("->"),
        style::value(&out_path.display().to_string())
    );
    Ok(())
}

/// Like [`javy_compile`] but wraps the source in the batch harness
/// (array-in / array-out) instead of the single-row harness.
fn javy_compile_batch(source_js: &str) -> Result<Vec<u8>> {
    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());
    let work_dir = std::env::temp_dir().join(format!("burn-compile-batch-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir).context("creating batch work directory")?;
    let src_path = work_dir.join("wrapped_batch.js");
    let wasm_path = work_dir.join("main.wasm");
    let wrapped = build_wrapped_source_batch(source_js);
    std::fs::write(&src_path, wrapped.as_bytes()).context("writing batch wrapped source")?;
    let invoke_result = run_javy_sealed(&javy, &src_path, &wasm_path);
    let wasm_result = invoke_result
        .and_then(|()| std::fs::read(&wasm_path).with_context(|| "reading compiled batch wasm"));
    let _ = std::fs::remove_dir_all(&work_dir);
    wasm_result
}

/// Like [`javy_compile`] but wraps the source in the columnar harness
/// (binary-frame-in / binary-frame-out).
fn javy_compile_columnar(source_js: &str) -> Result<Vec<u8>> {
    let javy = std::env::var("JAVY").unwrap_or_else(|_| "javy".into());
    let work_dir =
        std::env::temp_dir().join(format!("burn-compile-columnar-{}", std::process::id()));
    std::fs::create_dir_all(&work_dir).context("creating columnar work directory")?;
    let src_path = work_dir.join("wrapped_columnar.js");
    let wasm_path = work_dir.join("main.wasm");
    let wrapped = build_wrapped_source_columnar(source_js);
    std::fs::write(&src_path, wrapped.as_bytes()).context("writing columnar wrapped source")?;
    let invoke_result = run_javy_sealed(&javy, &src_path, &wasm_path);
    let wasm_result = invoke_result
        .and_then(|()| std::fs::read(&wasm_path).with_context(|| "reading compiled columnar wasm"));
    let _ = std::fs::remove_dir_all(&work_dir);
    wasm_result
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

/// Build the batch-wrapped JS source: array-in / array-out harness.
///
/// Reads a JSON array from stdin, applies the single-row `module.exports`
/// function across each element (mapping null/undefined to null), and writes
/// the JSON array result to stdout. One WASM boundary crossing per batch.
fn build_wrapped_source_batch(source_js: &str) -> String {
    format!(
        "const module = {{ exports: undefined }};\n\
         {source_js}\n\
         const __single = module.exports;\n\
         if (typeof __single !== \"function\") {{ throw new TypeError(\"burndb: module.exports must be a function for invoke_batch\"); }}\n\
         const __chunks = [];\n\
         const __buf = new Uint8Array(65536);\n\
         while (true) {{ const n = Javy.IO.readSync(0, __buf); if (n <= 0) break; __chunks.push(__buf.slice(0, n)); }}\n\
         let __t = 0; for (const c of __chunks) __t += c.length;\n\
         const __all = new Uint8Array(__t);\n\
         let __o = 0; for (const c of __chunks) {{ __all.set(c, __o); __o += c.length; }}\n\
         const __rows = JSON.parse(new TextDecoder().decode(__all));\n\
         const __out = __rows.map((r) => (r === null || r === undefined) ? null : __single(r));\n\
         Javy.IO.writeSync(1, new TextEncoder().encode(JSON.stringify(__out)));\n",
        source_js = source_js,
    )
}

/// Build the columnar-wrapped JS source: binary-frame-in / binary-frame-out harness.
///
/// Reads the binary columnar batch frame (BatchHeader + ColumnHeader[] + data
/// buffers, the same layout produced by afterburner-wasi::columnar::encode_batch)
/// from stdin, exposes each column to the user UDF as a TypedArray view, calls
/// `module.exports(batch)`, encodes the result batch in the same binary format,
/// and writes it to stdout.
///
/// The binary frame layout (all integers LE):
///   BatchHeader (16 bytes): [row_count: u32][column_count: u32][columns_offset: u32][_reserved: u32]
///   ColumnHeader (28 bytes each): [dtype: u8][_pad: 3 bytes][data_offset: u32][validity_offset: u32]
///                                 [name_offset: u32][name_len: u32][heap_offset: u32][heap_len: u32]
///
/// dtype tags: Bool=1 Int8=2 Int16=3 Int32=4 Int64=5 UInt8=6 UInt16=7 UInt32=8 UInt64=9
///             Float32=10 Float64=11 Utf8=12 Date32=13 Timestamp=14
///             (Decimal128=15 Interval=16 Uuid=17 Bytea=18 Jsonb=19 reserved)
///
/// The user's `module.exports(batch)` receives `{ row_count, columns: { name: TypedArray, ... } }`
/// and returns `{ row_count, columns: { name: TypedArray, ... } }`.
fn build_wrapped_source_columnar(source_js: &str) -> String {
    format!(
        "const module = {{ exports: undefined }};\n\
         {source_js}\n\
         const __udf = module.exports;\n\
         if (typeof __udf !== \"function\") {{ throw new TypeError(\"burndb: module.exports must be a function for invoke_columnar\"); }}\n\
         // Read binary frame from stdin.\n\
         const __chunks = [];\n\
         const __buf = new Uint8Array(65536);\n\
         while (true) {{ const n = Javy.IO.readSync(0, __buf); if (n <= 0) break; __chunks.push(__buf.slice(0, n)); }}\n\
         let __t = 0; for (const c of __chunks) __t += c.length;\n\
         const __frame = new Uint8Array(__t);\n\
         let __fo = 0; for (const c of __chunks) {{ __frame.set(c, __fo); __fo += c.length; }}\n\
         const __dv = new DataView(__frame.buffer);\n\
         // Parse BatchHeader (16 bytes).\n\
         const __row_count = __dv.getUint32(0, true);\n\
         const __col_count = __dv.getUint32(4, true);\n\
         const __col_tbl   = __dv.getUint32(8, true);\n\
         // dtype -> [TypedArray constructor, element bytes]\n\
         const __DTYPE = {{ 1:[Uint8Array,1], 2:[Int8Array,1], 3:[Int16Array,2], 4:[Int32Array,4],\n\
           5:[BigInt64Array,8], 6:[Uint8Array,1], 7:[Uint16Array,2], 8:[Uint32Array,4],\n\
           9:[BigUint64Array,8], 10:[Float32Array,4], 11:[Float64Array,8],\n\
           12:[Uint8Array,1], 13:[Int32Array,4], 14:[BigInt64Array,8] }};\n\
         // Parse ColumnHeader[] (28 bytes each) and build batch.\n\
         const __cols = {{}};\n\
         const __col_meta = [];\n\
         const COL_HDR = 28;\n\
         for (let i = 0; i < __col_count; i++) {{\n\
           const h = __col_tbl + i * COL_HDR;\n\
           const dtype       = __frame[h];\n\
           const data_off    = __dv.getUint32(h + 4, true);\n\
           const name_off    = __dv.getUint32(h + 12, true);\n\
           const name_len    = __dv.getUint32(h + 16, true);\n\
           const name = new TextDecoder().decode(__frame.slice(name_off, name_off + name_len));\n\
           const info = __DTYPE[dtype];\n\
           if (!info) {{ throw new Error(\"burndb: unsupported columnar dtype \" + dtype + \" for column '\" + name + \"'\"); }}\n\
           const [TCon, stride] = info;\n\
           const elem_count = __row_count;\n\
           const byte_len = elem_count * stride;\n\
           // Construct a TypedArray view directly into the frame buffer.\n\
           const col_view = new TCon(__frame.buffer, data_off, elem_count);\n\
           __cols[name] = col_view;\n\
           __col_meta.push({{ name, dtype, stride }});\n\
         }}\n\
         const __result = __udf({{ row_count: __row_count, columns: __cols }});\n\
         // Encode result batch using the same binary frame layout.\n\
         const __res_row_count = (__result && typeof __result.row_count === \"number\") ? __result.row_count : __row_count;\n\
         const __res_cols = (__result && __result.columns) ? Object.entries(__result.columns) : [];\n\
         // dtype reverse map: TypedArray constructor -> tag + stride\n\
         const __DTAG = [\n\
           [Int8Array,    2, 1], [Int16Array,  3, 2], [Int32Array,   4, 4],\n\
           [BigInt64Array,5, 8], [Uint8Array,  6, 1], [Uint16Array,  7, 2],\n\
           [Uint32Array,  8, 4], [BigUint64Array,9,8],[Float32Array,10, 4],\n\
           [Float64Array,11, 8]\n\
         ];\n\
         function __dtype_of(arr) {{\n\
           for (const [TCon, tag, stride] of __DTAG) {{ if (arr instanceof TCon) return [tag, stride]; }}\n\
           throw new Error(\"burndb: unsupported TypedArray type in columnar result: \" + arr.constructor.name);\n\
         }}\n\
         // Two-pass layout: header, then column-header table, then data+names.\n\
         const __BH = 16;\n\
         const __CH = 28;\n\
         const __align8 = (x) => (x + 7) & ~7;\n\
         // Resolve col info upfront.\n\
         const __rci = __res_cols.map(([name, arr]) => {{\n\
           const [tag, stride] = __dtype_of(arr);\n\
           return {{ name, arr, tag, stride }};\n\
         }});\n\
         let __cursor = __align8(__BH + __rci.length * __CH);\n\
         const __offsets = [];\n\
         for (const ci of __rci) {{\n\
           __cursor = __align8(__cursor);\n\
           const data_off = __cursor;\n\
           __cursor += ci.arr.length * ci.stride;\n\
           const name_off = __cursor;\n\
           __cursor += ci.name.length;\n\
           __offsets.push({{ data_off, name_off }});\n\
         }}\n\
         const __out_buf = new Uint8Array(__cursor);\n\
         const __out_dv = new DataView(__out_buf.buffer);\n\
         // Write BatchHeader.\n\
         __out_dv.setUint32(0, __res_row_count, true);\n\
         __out_dv.setUint32(4, __rci.length, true);\n\
         __out_dv.setUint32(8, __BH, true);\n\
         __out_dv.setUint32(12, 0, true);\n\
         // Write ColumnHeaders.\n\
         for (let i = 0; i < __rci.length; i++) {{\n\
           const ci = __rci[i];\n\
           const off = __offsets[i];\n\
           const h = __BH + i * __CH;\n\
           __out_buf[h] = ci.tag;\n\
           __out_dv.setUint32(h + 4, off.data_off, true);\n\
           __out_dv.setUint32(h + 8, 0, true);\n\
           __out_dv.setUint32(h + 12, off.name_off, true);\n\
           __out_dv.setUint32(h + 16, ci.name.length, true);\n\
           __out_dv.setUint32(h + 20, 0, true);\n\
           __out_dv.setUint32(h + 24, 0, true);\n\
         }}\n\
         // Write column data and names.\n\
         for (let i = 0; i < __rci.length; i++) {{\n\
           const ci = __rci[i];\n\
           const off = __offsets[i];\n\
           const raw = new Uint8Array(ci.arr.buffer, ci.arr.byteOffset, ci.arr.byteLength);\n\
           __out_buf.set(raw, off.data_off);\n\
           const name_bytes = new TextEncoder().encode(ci.name);\n\
           __out_buf.set(name_bytes, off.name_off);\n\
         }}\n\
         Javy.IO.writeSync(1, __out_buf);\n",
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
