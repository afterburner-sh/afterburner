// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

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
//! For non-JS/TS packages (`language = "rust"`, `"go"`, `"c"`, `"cpp"`),
//! the language-native toolchain is invoked to produce a `wasm32-wasip1`
//! WASI command module. The language is read exclusively from
//! `[package] language` in `afb.toml` - no file-extension auto-detection.
//!
//! For `language = "ruby"`, the package is compiled to a self-contained
//! `wasm32-wasip1` module via `wasi-vfs pack`: the stock `ruby.wasm`
//! interpreter with the package's `source/` tree and the Ruby stdlib
//! pre-embedded.
//!
//! For `language = "python"`, the package is compiled to a self-contained
//! `.afb` bundle (`runtime.target = "emscripten-pyodide"`) containing the
//! CPython.wasm (exnref-translated Pyodide), the Python stdlib zip, resolved
//! `[pip]` wheels (pure-Python or Pyodide ABI only), and the package source.
//! `burn run out.afb` executes the bundle with no re-fetch and no env vars.
//!
//! `javy` is required only for JS/TS - the runtime never shells to it.
//! Required version: 8.1.1.

mod cc; // C/C++ multi-file -> wasm32-wasip1 WASI command (wasi-sdk); used by `lang`.
pub mod lang;
pub mod python_wasm; // Python -> self-contained emscripten-pyodide .afb bundle
mod ruby_wasm; // Ruby -> self-contained wasm32-wasip1 via wasi-vfs
pub use ruby_wasm::{GUEST_SRC_MOUNT, gem_load_path_dirs, guest_entry_path};

use afterburner_cloud::afterburner_afb::Afb;
use afterburner_cloud::afterburner_afb::digest::{digest, hex};
use afterburner_cloud::afterburner_afb::manifest::{DepReq, GitRef};
use afterburner_cloud::afterburner_afb::pack::Builder;
use afterburner_cloud::lock::{LOCKFILE_NAME, Lockfile};
use afterburner_cloud::pkg::{self, LocalPackage};
use afterburner_node_compat::PLENUM_BUNDLE;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use lang::SourceLang;

use super::registry::{coord_str, print_digest, transpile_ts_sources};
use super::style;

/// Resolve the transitive closure of dependencies for a package.
///
/// Dispatches on each [`DepReq`] variant:
/// - `Path`: loads the sibling from the path relative to `depending_dir`,
///   builds a source `.afb`, and recurses into its transitive deps.
/// - `Pin`/`Range`: looks up the content-addressed cache (populated by
///   `burn install`). For `Range`, reads `burn.lock` in `depending_dir` to
///   find the resolved digest. Fails clearly when the cache is empty.
/// - `Git`: clones the repo into a stable temp dir keyed by url+ref,
///   builds a source `.afb`, and recurses.
///
/// Returns the full closure in deps-before-dependents order (leaves first),
/// deduped by coordinate.
fn resolve_deps(
    deps: &BTreeMap<String, DepReq>,
    depending_dir: &Path,
) -> Result<Vec<(String, Afb)>> {
    let mut resolved: BTreeMap<String, Afb> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for (coord, req) in deps {
        resolve_one_dep(coord, req, depending_dir, &mut resolved, &mut order)?;
    }
    Ok(order
        .into_iter()
        .map(|c| {
            let a = resolved.remove(&c).unwrap();
            (c, a)
        })
        .collect())
}

/// Recursively resolve a single dependency and its transitive closure,
/// appending to `resolved`/`order` in topological order (leaves before
/// dependents).
fn resolve_one_dep(
    coord: &str,
    req: &DepReq,
    depending_dir: &Path,
    resolved: &mut BTreeMap<String, Afb>,
    order: &mut Vec<String>,
) -> Result<()> {
    if resolved.contains_key(coord) {
        return Ok(()); // diamond dep - resolve each coordinate once
    }

    match req {
        DepReq::Path(p) => {
            let dep_dir = depending_dir.join(p);
            let mut dep_local = pkg::LocalPackage::load(&dep_dir).with_context(|| {
                format!(
                    "loading path dep {coord:?} from {} (relative to {})",
                    dep_dir.display(),
                    depending_dir.display()
                )
            })?;
            super::registry::transpile_ts_sources(&mut dep_local)?;
            let (dep_bytes, _) = dep_local
                .build()
                .with_context(|| format!("building path dep {coord:?}"))?;
            let dep_afb = Afb::from_bytes(&dep_bytes)
                .with_context(|| format!("parsing built path dep {coord:?}"))?;

            // The dep's own path deps are relative to its own directory.
            let dep_pkg_dir = dep_dir.canonicalize().unwrap_or_else(|_| dep_dir.clone());
            let child_deps = dep_afb.manifest.dependencies.clone();
            resolved.insert(coord.to_string(), dep_afb);
            for (child_coord, child_req) in &child_deps {
                resolve_one_dep(child_coord, child_req, &dep_pkg_dir, resolved, order)?;
            }
            order.push(coord.to_string());
        }

        DepReq::Pin(pin) => {
            let hex_str = pin.trim_start_matches("sha256:").to_string();
            let cache_path = afterburner_cloud::cache::path_for(&hex_str)
                .with_context(|| format!("cache path for dep {coord:?}"))?;
            if !cache_path.exists() {
                anyhow::bail!(
                    "registry dep {coord:?} (pin {pin}) is not in the local cache; \
                     run `burn install` first"
                );
            }
            let bytes = std::fs::read(&cache_path)
                .with_context(|| format!("reading cached dep {coord:?}"))?;
            let dep_afb =
                Afb::from_bytes(&bytes).with_context(|| format!("parsing cached dep {coord:?}"))?;
            let child_deps = dep_afb.manifest.dependencies.clone();
            resolved.insert(coord.to_string(), dep_afb);
            for (child_coord, child_req) in &child_deps {
                resolve_one_dep(child_coord, child_req, depending_dir, resolved, order)?;
            }
            order.push(coord.to_string());
        }

        DepReq::Range(_) => {
            // Range dep: look up the resolved digest in burn.lock.
            let lock_path = depending_dir.join(LOCKFILE_NAME);
            let lock_text = std::fs::read_to_string(&lock_path).with_context(|| {
                format!(
                    "registry dep {coord:?} is a range but no {LOCKFILE_NAME} found in {}; \
                     run `burn install` first",
                    depending_dir.display()
                )
            })?;
            let lock = Lockfile::parse(&lock_text)
                .with_context(|| format!("parsing {LOCKFILE_NAME} for dep {coord:?}"))?;
            let hex_str = lock
                .packages
                .iter()
                .find(|p| p.name == coord)
                .map(|p| p.digest.trim_start_matches("sha256:").to_string())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "registry dep {coord:?} not found in {LOCKFILE_NAME}; \
                         run `burn install` first"
                    )
                })?;
            let cache_path = afterburner_cloud::cache::path_for(&hex_str)
                .with_context(|| format!("cache path for dep {coord:?}"))?;
            if !cache_path.exists() {
                anyhow::bail!(
                    "registry dep {coord:?} is not in the local cache \
                     (expected sha256:{hex_str}); run `burn install` first"
                );
            }
            let bytes = std::fs::read(&cache_path)
                .with_context(|| format!("reading cached dep {coord:?}"))?;
            let dep_afb =
                Afb::from_bytes(&bytes).with_context(|| format!("parsing cached dep {coord:?}"))?;
            let child_deps = dep_afb.manifest.dependencies.clone();
            resolved.insert(coord.to_string(), dep_afb);
            for (child_coord, child_req) in &child_deps {
                resolve_one_dep(child_coord, child_req, depending_dir, resolved, order)?;
            }
            order.push(coord.to_string());
        }

        DepReq::Git { url, reference } => {
            let ref_str = match reference {
                GitRef::Tag(t) => t.clone(),
                GitRef::Branch(b) => b.clone(),
                GitRef::Rev(r) => r.clone(),
            };
            // Stable temp dir keyed by url+ref so repeated builds skip re-cloning.
            let cache_key = {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                url.hash(&mut h);
                ref_str.hash(&mut h);
                format!("{:x}", h.finish())
            };
            let git_cache = std::env::temp_dir().join("burn-git-deps").join(&cache_key);

            if !git_cache.join("afb.toml").exists() {
                if git_cache.exists() {
                    std::fs::remove_dir_all(&git_cache).ok();
                }
                std::fs::create_dir_all(&git_cache)
                    .with_context(|| format!("creating git cache dir for {coord:?}"))?;

                let clone_status = match reference {
                    GitRef::Tag(_) | GitRef::Branch(_) => std::process::Command::new("git")
                        .args(["clone", "--depth", "1", "--branch", &ref_str, url, "."])
                        .current_dir(&git_cache)
                        .status()
                        .with_context(|| format!("spawning git clone for {coord:?}"))?,
                    GitRef::Rev(_) => {
                        let s = std::process::Command::new("git")
                            .args(["clone", url, "."])
                            .current_dir(&git_cache)
                            .status()
                            .with_context(|| format!("spawning git clone for {coord:?}"))?;
                        if s.success() {
                            std::process::Command::new("git")
                                .args(["checkout", &ref_str])
                                .current_dir(&git_cache)
                                .status()
                                .with_context(|| {
                                    format!("git checkout {ref_str:?} for {coord:?}")
                                })?
                        } else {
                            s
                        }
                    }
                };
                if !clone_status.success() {
                    anyhow::bail!(
                        "git clone of {url:?} (ref: {ref_str:?}) for dep {coord:?} failed"
                    );
                }
            }

            let mut dep_local = pkg::LocalPackage::load(&git_cache).with_context(|| {
                format!("loading git dep {coord:?} from {}", git_cache.display())
            })?;
            super::registry::transpile_ts_sources(&mut dep_local)?;
            let (dep_bytes, _) = dep_local
                .build()
                .with_context(|| format!("building git dep {coord:?}"))?;
            let dep_afb = Afb::from_bytes(&dep_bytes)
                .with_context(|| format!("parsing built git dep {coord:?}"))?;
            let child_deps = dep_afb.manifest.dependencies.clone();
            resolved.insert(coord.to_string(), dep_afb);
            for (child_coord, child_req) in &child_deps {
                resolve_one_dep(child_coord, child_req, &git_cache, resolved, order)?;
            }
            order.push(coord.to_string());
        }
    }
    Ok(())
}

/// Language-dispatching compile entry point shared by `burn compile` and
/// `burn package --compile`/`--wasm-only`.
///
/// Reads `[package] language` from `local.manifest` and dispatches:
/// - JS/TS: transpile TS (no-op for plain JS), then the Javy path
///   (source + precompiled WASM).
/// - Python/Ruby: pack the `source/` tree as-is (no precompiled WASM) - the
///   bundled CPython / CRuby interpreter runs the source at `burn run` time.
/// - Rust/Go/C/C++: native toolchain -> WASM -> `.afb`.
///
/// `wasm_only` controls whether source members are included in the output
/// `.afb`. Pass `true` for `--wasm-only` (FullWasm mode), `false` otherwise.
/// `--wasm-only` is rejected for Python/Ruby: an interpreted package has no
/// WASM artifact to ship, so dropping the source would leave nothing runnable.
pub fn dispatch_compile(
    dir: &Path,
    mut local: pkg::LocalPackage,
    out_path: &Path,
    wasm_only: bool,
) -> Result<()> {
    let lang = SourceLang::from_str(&local.manifest.package.language)
        .with_context(|| format!("invalid [package] language in {}/afb.toml", dir.display()))?;

    if lang.is_js_family() {
        transpile_ts_sources(&mut local)?;
        compile_with_local_package(local, out_path, wasm_only)
    } else if lang == SourceLang::Ruby {
        // Ruby: compile to a self-contained wasm32-wasip1 via wasi-vfs.
        // The stock ruby.wasm + the package's source/gems are embedded in the VFS.
        let pkg_dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        ruby_wasm::compile_ruby_to_wasm(local, &pkg_dir, out_path, wasm_only)
    } else if lang == SourceLang::Python {
        // Python: compile to a self-contained emscripten-pyodide .afb bundle.
        // The bundle carries CPython.wasm + stdlib + pip wheels + source so
        // burn run executes it standalone with no re-fetch and no env vars.
        let pkg_dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        python_wasm::compile_python_to_wasm(local, &pkg_dir, out_path, wasm_only)
    } else if lang.is_interpretable() {
        // Other interpreted languages: shipped as source (currently no members
        // of this branch remain since Python is handled above).
        if wasm_only {
            anyhow::bail!(
                "a {lang_name} package is interpreted (it ships as source and runs on the \
                 bundled runtime); there is no WASM artifact, so `--wasm-only` is not \
                 applicable. Use `burn compile` (source `.afb`) instead.",
                lang_name = format!("{lang:?}").to_lowercase(),
            );
        }
        pack_source_afb(local, out_path)
    } else {
        let entry = local.manifest.package.entry.clone();
        let pkg_dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
        compile_native_to_afb(local, lang, &pkg_dir, &entry, out_path, wasm_only)
    }
}

/// Pack an interpreted-language package (Python / Ruby) into a source `.afb`.
///
/// Mirrors the JS/TS source-`.afb` path: the `source/` tree (entry + sibling
/// modules), `afb.toml` (carrying `[package] language = python|ruby`), and
/// `manifold.json` are packed through the one canonical codec
/// ([`pkg::LocalPackage::build`] -> [`afterburner_afb::pack::Builder`]), so the
/// artifact is byte-identical to one `burn package` would emit and to the
/// registry tooling. No `precompiled/*` member is added: `burn run <pkg.afb>`
/// unpacks the source and runs it on the bundled CPython / CRuby interpreter.
fn pack_source_afb(local: LocalPackage, out_path: &Path) -> Result<()> {
    let coord = coord_str(&local);
    let (bytes, d) =
        style::spin("packing source", || local.build()).context("building source .afb")?;
    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;
    println!(
        "{} {} {}",
        style::ok("packaged"),
        style::accent(&coord),
        style::gold("(source)")
    );
    print_digest(bytes.len() as u64, &hex(&d));
    println!(
        "  {} {}",
        style::muted("->"),
        style::value(&out_path.display().to_string())
    );
    Ok(())
}

/// `burn compile [dir] -o <out>` entry point.
///
/// Reads `[package] language` from the manifest to determine the compile
/// backend. JS/TS use the Javy path (source + precompiled). All other
/// languages use the native-to-WASM path (`compile_native` in `lang.rs`),
/// which produces a `wasm32-wasip1` WASI command module bundled into the
/// `.afb` with `[runtime] target = "wasm32-wasip1"`.
///
/// The `language` field is the only dispatch criterion - no auto-detection
/// from file extensions.
pub fn compile(dir: Option<&Path>, out: Option<&Path>) -> Result<()> {
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let local = pkg::LocalPackage::load(dir)?;
    let out_path = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(local.output_filename()));
    dispatch_compile(dir, local, &out_path, false)
}

/// Compile a native (compiled-to-WASM) language package (Rust/Go/C/C++) to a
/// `.afb`.
///
/// Invokes the language toolchain, reads the produced WASM bytes, and
/// bundles them into a `.afb` with `[runtime] target = "wasm32-wasip1"`.
/// The source files are included unless `wasm_only` is true.
///
/// JS/TS (the Javy path) and Python/Ruby (interpreted, packed as source) are
/// dispatched elsewhere in [`dispatch_compile`] and never reach here.
fn compile_native_to_afb(
    local: LocalPackage,
    lang: SourceLang,
    pkg_dir: &Path,
    entry: &str,
    out_path: &Path,
    wasm_only: bool,
) -> Result<()> {
    let coord = coord_str(&local);
    let lang_name = match lang {
        SourceLang::Rust => "Rust",
        SourceLang::Go => "Go",
        SourceLang::C => "C",
        SourceLang::Cpp => "C++",
        SourceLang::Js | SourceLang::Ts => unreachable!("JS/TS not handled here"),
        SourceLang::Python => {
            unreachable!("Python is compiled via python_wasm, not the native toolchain path")
        }
        SourceLang::Ruby => {
            unreachable!("Ruby is compiled via wasi-vfs, not the native toolchain path")
        }
    };

    // Build the source-only .afb first (for the manifest + manifold).
    let (source_bytes, _) =
        style::spin("packing source", || local.build()).context("building source .afb")?;
    let afb = Afb::from_bytes(&source_bytes).context("reparsing source .afb (this is a bug)")?;

    // Compile to WASM via the native toolchain.
    let wasm_bytes = style::spin(&format!("compiling {lang_name} to wasm"), || {
        lang::compile_native(lang, pkg_dir, entry)
    })?;

    // Bundle the WASM into the .afb.
    bundle_wasm_into_afb(&afb, wasm_bytes, out_path, &coord, wasm_only)
}

/// Bundle a WASM binary into a `.afb` archive with `[runtime] target =
/// "wasm32-wasip1"`.
///
/// This is the shared helper used by both the native compile path and
/// (potentially) other paths that produce a WASI command module.
/// Source members from `afb` are included; `[runtime] target` is set to
/// `"wasm32-wasip1"` so `burn run` dispatches to `EmbedderVm::run_command`.
pub fn bundle_wasm_into_afb(
    afb: &Afb,
    wasm_bytes: Vec<u8>,
    out_path: &Path,
    coord: &str,
    wasm_only: bool,
) -> Result<()> {
    let mut manifest = afb.manifest.clone();
    manifest.runtime.target = Some("wasm32-wasip1".into());

    let mut b = Builder::new(manifest, afb.manifold.clone());
    if !wasm_only {
        for (path, data) in &afb.source {
            b = b.source(path.clone(), data.clone());
        }
    }
    b = b.precompiled("precompiled/wasm32-wasip1/main.wasm", wasm_bytes);

    let (bytes, bundle_digest) = style::spin("packing", || b.build()).context("building .afb")?;

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(coord),
        style::gold("(precompiled wasm32-wasip1)")
    );
    print_digest(bytes.len() as u64, &hex(&bundle_digest));
    println!(
        "  {} {}",
        style::muted("->"),
        style::value(&out_path.display().to_string())
    );
    Ok(())
}

/// Compile a local package to a precompiled `.afb`, writing to `out_path`.
/// Used by `burn compile`, `burn package --compile`, and `burn publish --compile`.
///
/// When `wasm_only` is true the emitted `.afb` contains no `source/*` members.
/// In that mode any fallback path that would have shipped source instead
/// returns an error - source leakage is never silent.
pub fn compile_with_local_package(
    local: LocalPackage,
    out_path: &Path,
    wasm_only: bool,
) -> Result<()> {
    if local.manifold.is_sealed() {
        compile_sealed(local, out_path, wasm_only)
    } else {
        compile_capability(local, out_path, wasm_only)
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
/// Dep resolution uses the dependency type declared in afb.toml:
/// - Path deps: resolved relative to the package directory.
/// - Registry deps (Pin/Range): loaded from the content-addressed cache.
/// - Git deps: cloned into a temp dir.
///
/// If linking fails (missing dep dir or real error), we fall back to a
/// source-only `.afb` and print a clear note so the caller is never left
/// with a broken precompiled module.
fn compile_sealed(local: LocalPackage, out_path: &Path, wasm_only: bool) -> Result<()> {
    let coord = coord_str(&local);
    let pkg_dir = local
        .dir
        .canonicalize()
        .unwrap_or_else(|_| local.dir.clone());

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
            let deps = resolve_deps(&afb.manifest.dependencies, &pkg_dir)?;
            let refs: Vec<(&str, &Afb)> = deps.iter().map(|(c, a)| (c.as_str(), a)).collect();
            let src = afb.linked_source(&refs, &[]).context("linking source")?;
            Ok(format!("{PLENUM_BUNDLE}\n{src}"))
        })();
        match link_result {
            Ok(src) => src,
            Err(e) => {
                if wasm_only {
                    // In WASM-only mode we must not fall back to shipping source.
                    anyhow::bail!(
                        "full-WASM packaging requires precompilation but dependency \
                         linking failed: {e}"
                    );
                }
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

    // Build the final .afb with (optionally) source plus three precompiled members:
    //   precompiled/wasm32-wasip1/main.wasm         - single-row JSON in/out
    //   precompiled/wasm32-wasip1-batch/main.wasm   - array-in / array-out
    //   precompiled/wasm32-wasip1-columnar/main.wasm - binary-frame in/out
    // Set runtime.target so the engine knows to look under precompiled/.
    let mut manifest = afb.manifest.clone();
    manifest.runtime.target = Some("wasm32-wasip1".into());

    let mut b = Builder::new(manifest, afb.manifold.clone());
    if !wasm_only {
        for (path, data) in &afb.source {
            b = b.source(path.clone(), data.clone());
        }
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

    let (bytes, d) = if wasm_only {
        style::spin("packing (wasm-only)", || b.build_wasm_only())
            .context("building wasm-only .afb")?
    } else {
        style::spin("packing", || b.build()).context("building precompiled .afb")?
    };

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    let label = if wasm_only {
        "(precompiled wasm32-wasip1, no source)"
    } else {
        "(precompiled wasm32-wasip1)"
    };
    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(&coord),
        style::gold(label)
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
fn compile_capability(local: LocalPackage, out_path: &Path, wasm_only: bool) -> Result<()> {
    let coord = coord_str(&local);
    let pkg_dir = local
        .dir
        .canonicalize()
        .unwrap_or_else(|_| local.dir.clone());

    // Build a source-only .afb first so we can reparse and use the linker.
    let (source_bytes, _) =
        style::spin("packing source", || local.build()).context("building source .afb")?;

    let afb = Afb::from_bytes(&source_bytes).context("reparsing source .afb (this is a bug)")?;

    // Compute the effective JS source the engine would compile.
    let effective_src: String = if afb.needs_linking() {
        let link_result = (|| -> Result<String> {
            let deps = resolve_deps(&afb.manifest.dependencies, &pkg_dir)?;
            let refs: Vec<(&str, &Afb)> = deps.iter().map(|(c, a)| (c.as_str(), a)).collect();
            let src = afb.linked_source(&refs, &[]).context("linking source")?;
            Ok(format!("{PLENUM_BUNDLE}\n{src}"))
        })();
        match link_result {
            Ok(src) => src,
            Err(e) => {
                if wasm_only {
                    anyhow::bail!(
                        "full-WASM packaging requires precompilation but dependency \
                         linking failed: {e}"
                    );
                }
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
    // In WASM-only mode, fall back is forbidden - propagate the error instead.
    let wasm_result = style::spin("compiling to dyn wasm", || javy_compile_dyn(&effective_src));
    let wasm_bytes = match wasm_result {
        Ok(b) => b,
        Err(e) => {
            if wasm_only {
                return Err(e.context(
                    "full-WASM packaging requires precompilation but dyn WASM build failed",
                ));
            }
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
    if !wasm_only {
        for (path, data) in &afb.source {
            b = b.source(path.clone(), data.clone());
        }
    }
    b = b.precompiled("precompiled/wasm32-wasip1-dyn/main.wasm", wasm_bytes);

    let (bytes, d) = if wasm_only {
        style::spin("packing (wasm-only)", || b.build_wasm_only())
            .context("building wasm-only dyn .afb")?
    } else {
        style::spin("packing", || b.build()).context("building dyn .afb")?
    };

    std::fs::write(out_path, &bytes).with_context(|| format!("writing {}", out_path.display()))?;

    let label = if wasm_only {
        "(precompiled wasm32-wasip1-dyn, no source)"
    } else {
        "(precompiled wasm32-wasip1-dyn)"
    };
    println!(
        "{} {} {}",
        style::ok("compiled"),
        style::accent(&coord),
        style::gold(label)
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
