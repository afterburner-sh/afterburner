// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `burn run FILE args…` and `burn -e CODE args…` - execute a
//! top-level script.
//!
//! Routes through the plugin's **daemon mode** (Q2-A): user source
//! runs via `daemon-init`; if it didn't install any HTTP listeners
//! (or `setInterval` - B3) the script exits cleanly like a plain
//! one-shot. When listeners are present the CLI transitions into
//! the dispatcher event loop until SIGINT.
//!
//! The UDF shape (`module.exports = (data) => …`) remains available
//! via `burn thrust`.
//!
//! **Exit codes** follow Node's convention: clean completion → 0,
//! `process.exit(n)` → n, and any uncaught error → 1 - including a
//! top-level `throw`, a rejected promise assigned to
//! `module.exports`, and an exported async function that throws (the
//! script envelope awaits an exported thenable; see
//! `afterburner-plugin/src/envelope.rs::wrap_script_source`). The
//! error message + stack go to stderr. A *resolved* exported promise
//! exits 0 with its value discarded.
//!
//! `.ts` / `.mts` / `.cts` files are transpiled via `oxc` before
//! dispatch when the crate is built with the `ts` feature. Without
//! `ts`, running a `.ts` file surfaces a typed error pointing at the
//! feature flag rather than letting the JS parser choke on
//! type annotations.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use super::args::Cli;
use super::daemon::{execute, script_label};

// Import the SourceLang type for language-dispatch in `run_package_or_file`.
use super::compile::lang::SourceLang;

#[cfg(feature = "wasm")]
use afterburner_wasi::embedder_vm::WasiCommandOpts;

/// Extensions that are natively compiled to WASM and run directly,
/// bypassing the JS engine.
fn is_native_script(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    matches!(
        ext.as_deref(),
        Some("rs" | "go" | "c" | "cpp" | "cxx" | "cc" | "py" | "pyw" | "rb")
    )
}

/// Recover a script's `process.argv[2..]` straight from the raw process
/// argv, slicing everything after the FILE token.
///
/// Needed because when a script's own arguments collide with a burn
/// subcommand name (`burn app.js install foo`, or npm's internal
/// `node npm-cli.js install foo` re-entering through the PATH shim as
/// `burn npm-cli.js install foo`), clap binds the colliding token as a
/// `Cmd` and swallows the rest, so they never reach `cli.rest_args`.
/// The script is an explicit "run this file", so its args are whatever
/// followed the FILE token in argv.
pub fn script_args_from_argv(file: &std::path::Path) -> Vec<String> {
    let file_str = file.to_string_lossy();
    let argv: Vec<String> = std::env::args().collect();
    match argv.iter().skip(1).position(|a| *a == *file_str) {
        // `position` is relative to `skip(1)`; +1 back to the full-argv
        // index of the FILE token, +1 more to start after it.
        Some(pos) => argv[pos + 2..].to_vec(),
        None => Vec::new(),
    }
}

/// Recover an eval script's `process.argv[1..]` from raw argv when a
/// trailing arg collided with a subcommand name and clap swallowed the
/// positionals into `cli.command` (`burn -e CODE install foo`).
///
/// The args are every argv token after the eval `CODE` value. `CODE`
/// arrives via `-e`/`--eval` in any of `-e CODE`, `-eCODE`,
/// `--eval CODE`, `--eval=CODE`; we slice after the token that *equals*
/// `code` (the separate-value forms) or, failing that, after the first
/// token that carries `code` as an attached value.
pub fn eval_args_from_argv(code: &str) -> Vec<String> {
    let argv: Vec<String> = std::env::args().collect();
    let tail = argv.iter().skip(1).enumerate();
    // Separate-value form: a token equal to CODE preceded by -e/--eval.
    for (i, tok) in tail.clone() {
        if tok == code {
            return argv[i + 2..].to_vec();
        }
    }
    // Attached-value form: `-eCODE` / `--eval=CODE`.
    for (i, tok) in tail {
        let attached =
            tok.strip_prefix("-e") == Some(code) || tok.strip_prefix("--eval=") == Some(code);
        if attached {
            return argv[i + 2..].to_vec();
        }
    }
    Vec::new()
}

/// `burn run` dispatch: run an explicit FILE, or - when none is given -
/// the current package's entry resolved from `afb.toml` (cargo-style).
///
/// When the package declares a native source language (Rust/Go/C/Python),
/// the compiled `.afb` is located, the `precompiled/wasm32-wasip1/main.wasm`
/// member is extracted, and the module is executed via
/// `EmbedderVm::run_command` as a WASI command. A clear error is emitted
/// when no `.afb` exists yet (directing the user to `burn compile` first).
///
/// JS/TS packages follow the existing daemon/eval path unchanged.
pub fn run_package_or_file(
    cli: &Cli,
    file: Option<&std::path::Path>,
    user_args: &[String],
) -> Result<()> {
    match file {
        Some(p) => {
            // An explicit .afb file: run the WASM inside it directly.
            if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("afb")) {
                return run_afb(p, user_args);
            }
            run_file(cli, &p.to_path_buf(), user_args)
        }
        None => {
            let dir = std::path::Path::new(".");
            let (lang, afb_name) = resolve_package_lang_and_output(dir)?;
            match SourceLang::from_str(&lang) {
                Ok(l @ (SourceLang::Python | SourceLang::Ruby)) => {
                    // Interpreted package: run the `source/` tree directly on
                    // the bundled interpreter with sibling modules mounted, the
                    // same path `burn run <pkg.afb>` takes. No compile step.
                    run_interpreted_dir(dir, l, user_args)
                }
                Ok(l) if !l.is_js_family() => {
                    // Compiled native package (Rust/Go/C/C++): run the compiled
                    // .afb via EmbedderVm.
                    let afb_path = dir.join(&afb_name);
                    if !afb_path.exists() {
                        anyhow::bail!(
                            "no compiled package found at {}; \
                             run `burn compile` first to build the native WASM",
                            afb_path.display()
                        );
                    }
                    run_afb(&afb_path, user_args)
                }
                _ => {
                    // JS/TS or unrecognized: existing path.
                    let entry = resolve_package_entry(dir)?;
                    // cargo builds on `cargo run`; burn links missing [npm] deps on
                    // `burn run` (no-op when node_modules exists or none declared).
                    super::registry::ensure_npm_linked(dir)?;
                    run_file(cli, &entry, user_args)
                }
            }
        }
    }
}

/// Resolve `([package] language, output_filename)` from the `afb.toml` in `dir`.
///
/// Returns `("js", <default_output>)` when the language field is absent.
fn resolve_package_lang_and_output(dir: &Path) -> Result<(String, String)> {
    let manifest_path = dir.join("afb.toml");
    if !manifest_path.exists() {
        anyhow::bail!(
            "no afb.toml in the current directory - `burn run` with no FILE \
             runs the current package's entry. Pass a file (`burn run script.js`) \
             or run inside a package (`burn init` to create one)."
        );
    }
    let text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let doc: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing {}", manifest_path.display()))?;
    let lang = doc
        .get("package")
        .and_then(|p| p.get("language"))
        .and_then(|l| l.as_str())
        .unwrap_or("js")
        .to_string();
    let name = doc
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("package");
    let namespace = doc
        .get("package")
        .and_then(|p| p.get("namespace"))
        .and_then(|n| n.as_str())
        .unwrap_or("local");
    let version = doc
        .get("package")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("0.1.0");
    let afb_name = format!("{namespace}-{name}-{version}.afb");
    Ok((lang, afb_name))
}

/// Run a `.afb` package.
///
/// Dispatches on `[package] language`:
/// - Python / Ruby: an interpreted package ships as source. The `source/`
///   tree is run on the bundled CPython / CRuby interpreter with the package
///   directory mounted and on the module search path, so sibling-module
///   imports resolve. No precompiled WASM is required.
/// - Everything else (Rust/Go/C/C++ and precompiled JS/TS): the
///   `precompiled/wasm32-wasip1/main.wasm` member is extracted and executed as
///   a WASI command module via `EmbedderVm::run_command`, with stdout forwarded
///   and the WASM exit code propagated. A clear error is returned when no
///   precompiled WASM member is present (e.g. a source-only JS package),
///   directing the user to `burn compile`.
#[cfg(feature = "wasm")]
fn run_afb(afb_path: &Path, user_args: &[String]) -> Result<()> {
    use afterburner_cloud::afterburner_afb::Afb;

    let bytes = fs::read(afb_path).with_context(|| format!("reading {}", afb_path.display()))?;
    let afb =
        Afb::from_bytes(&bytes).with_context(|| format!("parsing .afb {}", afb_path.display()))?;

    // Dispatch on runtime.target first (authoritative for compiled packages),
    // then fall back to the language field for source .afb packages.
    let runtime_target = afb.manifest.runtime.target.as_deref().unwrap_or("");
    if runtime_target == crate::cli::compile::python_wasm::RUNTIME_TARGET {
        return run_python_wasm_afb(afb_path, &afb, user_args);
    }

    match SourceLang::from_str(&afb.manifest.package.language) {
        Ok(SourceLang::Python) => run_python_afb(afb_path, &afb, user_args),
        Ok(SourceLang::Ruby) => {
            // A Ruby package compiled via `burn compile` has runtime.target = "wasm32-wasip1"
            // and contains precompiled/wasm32-wasip1/main.wasm (the vfs-packed module).
            // A Ruby source .afb (legacy / direct `burn package`) has no precompiled member
            // and runs on the bundled interpreter.
            let is_compiled = afb
                .manifest
                .runtime
                .target
                .as_deref()
                .is_some_and(|t| t == "wasm32-wasip1");
            if is_compiled {
                run_ruby_wasm_afb(afb_path, &afb, user_args)
            } else {
                run_ruby_afb(afb_path, &afb, user_args)
            }
        }
        _ => run_wasm_afb(afb_path, &afb, user_args),
    }
}

/// Run a precompiled-WASM `.afb` (Rust/Go/C/C++ or precompiled JS/TS) by
/// extracting its `precompiled/wasm32-wasip1/main.wasm` and executing it as a
/// WASI command module.
#[cfg(feature = "wasm")]
fn run_wasm_afb(
    afb_path: &Path,
    afb: &afterburner_cloud::afterburner_afb::Afb,
    user_args: &[String],
) -> Result<()> {
    use afterburner_wasi::embedder_vm::EmbedderVm;

    // Find the WASI command WASM. Prefer the plain (non-dyn, non-batch, non-columnar) target.
    let wasm_bytes = afb
        .precompiled
        .iter()
        .find(|(k, _)| k.as_str() == "precompiled/wasm32-wasip1/main.wasm")
        .map(|(_, v)| v.as_slice())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no precompiled/wasm32-wasip1/main.wasm; \
                 run `burn compile` to produce a native WASM package",
                afb_path.display()
            )
        })?;

    let vm = EmbedderVm::new().context("creating EmbedderVm")?;
    let module = vm
        .compile(wasm_bytes, true, |_| Ok(()))
        .context("compiling WASM module")?;

    let mut args = vec![afb_path.to_string_lossy().into_owned()];
    args.extend_from_slice(user_args);
    let opts = WasiCommandOpts::new().args(args);

    let output = vm
        .run_command(&module, opts, None)
        .context("running WASM command")?;

    // Forward stdout to the process stdout.
    if !output.stdout.is_empty() {
        use std::io::Write;
        std::io::stdout()
            .write_all(&output.stdout)
            .context("writing WASM stdout")?;
    }

    // Propagate the WASM exit code. EmbedderRunOutput.result holds the exit
    // code as i64 (0 = success). Non-zero exits are POSIX convention: not an
    // error in Rust's sense, but we mirror it to the process exit code.
    let exit_code = output.result as i32;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// The entry source bytes of a Python/Ruby source `.afb`, as UTF-8.
///
/// Looks up `manifest.package.entry` (e.g. `source/main.py`) in the unpacked
/// `source/` map and decodes it. Errors clearly when the entry is missing or
/// not UTF-8 - an interpreted package's entry is always a text source file.
#[cfg(feature = "wasm")]
fn afb_entry_source(afb: &afterburner_cloud::afterburner_afb::Afb) -> Result<&str> {
    let entry = &afb.manifest.package.entry;
    let bytes = afb.source.get(entry).ok_or_else(|| {
        anyhow::anyhow!(
            "package entry {entry:?} (from afb.toml) is not present under source/ in the .afb"
        )
    })?;
    std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("package entry {entry:?} is not valid UTF-8"))
}

/// Run a Python source `.afb` on the bundled CPython runtime.
///
/// Collects any `vendor/pip/*.whl` members from `afb.vendor` (FORMAT_MINOR >= 3)
/// and passes them to the Python runner so they are mounted into site-packages
/// before CPython's import machinery activates. Packages without `[pip]`
/// dependencies have an empty vendor map and run identically to before.
#[cfg(feature = "wasm")]
fn run_python_afb(
    afb_path: &Path,
    afb: &afterburner_cloud::afterburner_afb::Afb,
    user_args: &[String],
) -> Result<()> {
    use afterburner_wasi::pyodide_runner::{PyPackage, run_python_package};
    use std::collections::BTreeMap;
    use std::io::Write;

    let entry_source = afb_entry_source(afb)
        .with_context(|| format!("reading Python entry of {}", afb_path.display()))?;

    // Collect vendored pip wheels (vendor/pip/*.whl) from the archive, in
    // sorted key order for deterministic mount sequence.
    let vendor_pip_wheels: Vec<Vec<u8>> = afb
        .vendor
        .iter()
        .filter(|(k, _)| k.starts_with("vendor/pip/") && k.ends_with(".whl"))
        .map(|(_, v)| v.clone())
        .collect();

    // Guest layout: every `source/<rel>` member lands at `/pkg/source/<rel>`,
    // and `/pkg/source` is the sys.path entry, so `import sibling` resolves a
    // sibling module (the entry runs via `-c`, but its siblings are imported
    // from disk).
    const GUEST_PKG_ROOT: &str = "/pkg";
    let sys_path_dir = format!("{GUEST_PKG_ROOT}/source");

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (rel, data) in &afb.source {
        files.insert(format!("{GUEST_PKG_ROOT}/{rel}"), data.clone());
    }
    let pkg = PyPackage {
        files,
        sys_path_dir,
        vendor_pip_wheels,
    };

    let out = run_python_package(entry_source, &pkg)
        .map_err(|e| anyhow::anyhow!("python runtime error: {e}"))?;

    if !out.stdout.is_empty() {
        std::io::stdout()
            .write_all(&out.stdout)
            .context("writing python stdout")?;
    }
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
    let _ = user_args;
    Ok(())
}

/// Run a pre-compiled Ruby `.afb` (produced by `burn compile` with language = "ruby").
///
/// The `.afb` contains `precompiled/wasm32-wasip1/main.wasm`: the stock `ruby.wasm`
/// with the package source and Ruby stdlib pre-embedded in a virtual filesystem by
/// `wasi-vfs`. The module needs no host preopens; it is run as a WASI command
/// module with argv = `[<pkg_name>, "/src/<entry>"]` so CRuby reads the embedded
/// `/src/<entry>` as its script. `user_args` are appended after the entry path.
#[cfg(feature = "wasm")]
fn run_ruby_wasm_afb(
    afb_path: &Path,
    afb: &afterburner_cloud::afterburner_afb::Afb,
    user_args: &[String],
) -> Result<()> {
    use crate::cli::compile::guest_entry_path;
    use afterburner_wasi::embedder_vm::EmbedderVm;

    let wasm_bytes = afb
        .precompiled
        .iter()
        .find(|(k, _)| k.as_str() == "precompiled/wasm32-wasip1/main.wasm")
        .map(|(_, v)| v.as_slice())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{}: Ruby compiled package has no precompiled/wasm32-wasip1/main.wasm; \
                 re-run `burn compile` to rebuild it",
                afb_path.display()
            )
        })?;

    let vm = EmbedderVm::new().context("creating EmbedderVm")?;
    let module = vm
        .compile(wasm_bytes, true, |_| Ok(()))
        .context("compiling Ruby wasm module")?;

    // argv[0] = conventional program name (the package path), argv[1] = guest script path.
    // ruby.wasm treats argv[0] as its program name and argv[1] as the script to run.
    let entry_rel = &afb.manifest.package.entry;
    let guest_script = guest_entry_path(entry_rel);
    let mut args = vec![afb_path.to_string_lossy().into_owned(), guest_script];
    args.extend_from_slice(user_args);
    let opts = WasiCommandOpts::new().args(args);

    // Ruby's WASM port has a large startup cost (VM init, require loading).
    // Use the same fuel budget as the source-package runner (RUBY_FUEL).
    let output = vm
        .run_command(
            &module,
            opts,
            Some(afterburner_wasi::ruby_runner::RUBY_FUEL),
        )
        .context("running Ruby wasm command")?;

    if !output.stdout.is_empty() {
        use std::io::Write;
        std::io::stdout()
            .write_all(&output.stdout)
            .context("writing Ruby wasm stdout")?;
    }
    if !output.stderr.is_empty() {
        use std::io::Write;
        std::io::stderr()
            .write_all(&output.stderr)
            .context("writing Ruby wasm stderr")?;
    }

    let exit_code = output.result as i32;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Run a compiled Python `.afb` (produced by `burn compile` with language = "python").
///
/// The `.afb` carries `runtime.target = "emscripten-pyodide"` and bundles:
/// - `precompiled/emscripten-pyodide/pyodide.wasm` - the CPython Emscripten binary.
/// - `precompiled/emscripten-pyodide/python_stdlib.zip` - the Python stdlib.
/// - `vendor/pip/*.whl` - resolved pip wheels (if any).
/// - `source/<rel>` - the package source (entry + siblings).
///
/// The runner materializes the wasm + stdlib to a temp dir (PyRuntime holds
/// PathBuf), reconstitutes the runtime from those paths, mounts the vendored
/// wheels and the package source into the in-memory FS, then calls
/// `run_pyodide_package_with` - identical to the source-package path but with
/// zero network access and zero env vars required.
#[cfg(feature = "wasm")]
fn run_python_wasm_afb(
    afb_path: &Path,
    afb: &afterburner_cloud::afterburner_afb::Afb,
    user_args: &[String],
) -> Result<()> {
    use crate::cli::compile::python_wasm::reconstruct_runtime_from_afb;
    use afterburner_wasi::pyodide_runner::{PyPackage, run_pyodide_package_with};
    use std::collections::BTreeMap;
    use std::io::Write;

    let entry_source = afb_entry_source(afb)
        .with_context(|| format!("reading Python entry of {}", afb_path.display()))?;

    // Materialize the runtime artefacts to a temp dir.
    let tmp_root = std::env::temp_dir().join(format!(
        "burn-py-wasm-afb-{}-{}",
        std::process::id(),
        afb_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let (rt, pip_wheel_bytes) = reconstruct_runtime_from_afb(afb, &tmp_root)
        .with_context(|| format!("reconstructing Python runtime from {}", afb_path.display()))?;

    // Mount the package's source tree under /pkg (same layout as run_python_afb).
    const GUEST_PKG_ROOT: &str = "/pkg";
    let sys_path_dir = format!("{GUEST_PKG_ROOT}/source");
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (rel, data) in &afb.source {
        files.insert(format!("{GUEST_PKG_ROOT}/{rel}"), data.clone());
    }

    let pkg = PyPackage {
        files,
        sys_path_dir,
        vendor_pip_wheels: pip_wheel_bytes,
    };

    let run_result = run_pyodide_package_with(&rt, entry_source, &pkg)
        .map_err(|e| anyhow::anyhow!("python runtime error: {e}"));

    // Best-effort cleanup; never mask the real error.
    let _ = fs::remove_dir_all(&tmp_root);
    let out = run_result?;

    if !out.stdout.is_empty() {
        std::io::stdout()
            .write_all(&out.stdout)
            .context("writing python stdout")?;
    }
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
    let _ = user_args;
    Ok(())
}

/// Python compiled .afb runner when the `wasm` feature is absent: honest error.
#[cfg(not(feature = "wasm"))]
fn run_python_wasm_afb(
    afb_path: &Path,
    _afb: &afterburner_cloud::afterburner_afb::Afb,
    _user_args: &[String],
) -> Result<()> {
    anyhow::bail!(
        "running compiled Python packages requires the `wasm` feature \
         (rebuild with `--features wasm`). Package: {}",
        afb_path.display()
    )
}

/// Run a Ruby source `.afb` on the bundled CRuby runtime.
///
/// When the archive carries `vendor/gem/**` members (FORMAT_MINOR >= 3), they
/// are mounted read-only at the guest path and prepended to `$LOAD_PATH` via
/// `-I` so `require 'gemname'` resolves offline without a gem toolchain.
#[cfg(feature = "wasm")]
fn run_ruby_afb(
    afb_path: &Path,
    afb: &afterburner_cloud::afterburner_afb::Afb,
    user_args: &[String],
) -> Result<()> {
    use afterburner_wasi::ruby_runner::{resolve_ruby_runtime, run_ruby_afb_with};
    use std::io::Write;

    let entry_rel = &afb.manifest.package.entry;
    if !afb.source.contains_key(entry_rel) {
        anyhow::bail!(
            "package entry {entry_rel:?} (from afb.toml) is not present under source/ in {}",
            afb_path.display()
        );
    }

    let rt = resolve_ruby_runtime()
        .with_context(|| format!("resolving Ruby runtime for {}", afb_path.display()))?;

    // Materialize the `source/` tree to a temp dir (the CRuby WASI path reads
    // via preopens; the vendor extraction is handled inside run_ruby_afb_with).
    let tmp_root = std::env::temp_dir().join(format!("burn-rb-pkg-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp_root);
    for (rel, data) in &afb.source {
        let dest = tmp_root.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::write(&dest, data).with_context(|| format!("writing {}", dest.display()))?;
    }

    let run_result = run_ruby_afb_with(&rt, &tmp_root, entry_rel, &afb.vendor);
    let _ = fs::remove_dir_all(&tmp_root);
    let out = run_result.map_err(|e| anyhow::anyhow!("ruby runtime error: {e}"))?;

    if !out.stdout.is_empty() {
        std::io::stdout()
            .write_all(&out.stdout)
            .context("writing ruby stdout")?;
    }
    if !out.stderr.is_empty() {
        std::io::stderr()
            .write_all(&out.stderr)
            .context("writing ruby stderr")?;
    }
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
    let _ = user_args;
    Ok(())
}

/// Run a Python package from its `source/` map (archive-relative path ->
/// bytes) on the bundled CPython runtime. The single canonical Python-package
/// run path, shared by `burn run <pkg.afb>` and the in-directory `burn run`
/// (no FILE) path.
///
/// Every `source/<rel>` member is mounted into the guest in-memory filesystem
/// under `/pkg/source/<rel>`, `/pkg/source` is prepended to `sys.path`, and
/// `entry_source` is run via `-c` - so a package whose entry does
/// `import helper` resolves the sibling `source/helper.py`. `user_args` are
/// reserved for a future `sys.argv` wiring (the Pyodide `-c` boot does not
/// take positional argv yet).
#[cfg(feature = "wasm")]
fn run_python_package_from_sources(
    entry_source: &str,
    sources: &std::collections::BTreeMap<String, Vec<u8>>,
    _user_args: &[String],
) -> Result<()> {
    use afterburner_wasi::pyodide_runner::{PyPackage, run_python_package};
    use std::collections::BTreeMap;
    use std::io::Write;

    // Guest layout: every `source/<rel>` member lands at `/pkg/source/<rel>`,
    // and `/pkg/source` is the sys.path entry, so `import sibling` resolves a
    // sibling module (the entry runs via `-c`, but its siblings are imported
    // from disk).
    const GUEST_PKG_ROOT: &str = "/pkg";
    let sys_path_dir = format!("{GUEST_PKG_ROOT}/source");

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (rel, data) in sources {
        files.insert(format!("{GUEST_PKG_ROOT}/{rel}"), data.clone());
    }
    let pkg = PyPackage {
        files,
        sys_path_dir,
        vendor_pip_wheels: Vec::new(),
    };

    let out = run_python_package(entry_source, &pkg)
        .map_err(|e| anyhow::anyhow!("python runtime error: {e}"))?;

    if !out.stdout.is_empty() {
        std::io::stdout()
            .write_all(&out.stdout)
            .context("writing python stdout")?;
    }
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
    Ok(())
}

/// Run a Ruby package from its `source/` map (archive-relative path -> bytes)
/// on the bundled CRuby runtime. The single canonical Ruby-package run path,
/// shared by `burn run <pkg.afb>` and the in-directory `burn run` (no FILE)
/// path.
///
/// The `source/` tree is written to a temp directory, that directory is
/// preopened read-only and added to `$LOAD_PATH`, and the entry is run by its
/// path - so `require_relative './helper'` and `require 'helper'` both resolve
/// the sibling `source/helper.rb`. `user_args` are reserved for a future
/// `ARGV` wiring.
#[cfg(feature = "wasm")]
fn run_ruby_package_from_sources(
    entry_rel: &str,
    sources: &std::collections::BTreeMap<String, Vec<u8>>,
    _user_args: &[String],
) -> Result<()> {
    use afterburner_wasi::ruby_runner::run_ruby_package;
    use std::io::Write;

    // Materialize the `source/` tree to a temp dir so the WASI runtime can
    // preopen it (the CRuby path reads from the host FS via preopens, unlike
    // the Pyodide in-memory FS). A process-id-keyed dir avoids collisions.
    let tmp_root = std::env::temp_dir().join(format!("burn-rb-pkg-{}", std::process::id()));
    // Clean any stale dir from a recycled pid, then recreate.
    let _ = fs::remove_dir_all(&tmp_root);
    for (rel, data) in sources {
        let dest = tmp_root.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::write(&dest, data).with_context(|| format!("writing {}", dest.display()))?;
    }

    let run_result = run_ruby_package(&tmp_root, entry_rel);

    // Best-effort cleanup; never mask the real result.
    let _ = fs::remove_dir_all(&tmp_root);

    let out = run_result.map_err(|e| anyhow::anyhow!("ruby runtime error: {e}"))?;

    if !out.stdout.is_empty() {
        std::io::stdout()
            .write_all(&out.stdout)
            .context("writing ruby stdout")?;
    }
    if !out.stderr.is_empty() {
        std::io::stderr()
            .write_all(&out.stderr)
            .context("writing ruby stderr")?;
    }
    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
    Ok(())
}

/// Run an interpreted package (Python / Ruby) straight from its directory
/// (`burn run` with no FILE, inside a package), reusing the same
/// source-tree-mounting run path as `burn run <pkg.afb>`.
///
/// Loads the package's `source/` tree from disk via `LocalPackage` (the same
/// loader the packer uses, so the source set is identical to what a `.afb`
/// would carry) and delegates to the shared per-language package runner.
#[cfg(feature = "wasm")]
fn run_interpreted_dir(dir: &Path, lang: SourceLang, user_args: &[String]) -> Result<()> {
    use afterburner_cloud::pkg::LocalPackage;

    let local =
        LocalPackage::load(dir).with_context(|| format!("loading package at {}", dir.display()))?;
    let entry_rel = local.manifest.package.entry.clone();
    let entry_bytes = local.sources.get(&entry_rel).ok_or_else(|| {
        anyhow::anyhow!("package entry {entry_rel:?} (from afb.toml) is not present under source/")
    })?;

    match lang {
        SourceLang::Python => {
            let entry_source = std::str::from_utf8(entry_bytes)
                .map_err(|_| anyhow::anyhow!("Python entry {entry_rel:?} is not valid UTF-8"))?;
            run_python_package_from_sources(entry_source, &local.sources, user_args)
        }
        SourceLang::Ruby => run_ruby_package_from_sources(&entry_rel, &local.sources, user_args),
        other => anyhow::bail!("run_interpreted_dir called for non-interpreted language {other:?}"),
    }
}

/// Interpreted-package directory runner when the `wasm` feature is absent:
/// honest error.
#[cfg(not(feature = "wasm"))]
fn run_interpreted_dir(dir: &Path, _lang: SourceLang, _user_args: &[String]) -> Result<()> {
    anyhow::bail!(
        "running interpreted packages requires the `wasm` feature \
         (rebuild with `--features wasm`). Package: {}",
        dir.display()
    )
}

#[cfg(not(feature = "wasm"))]
fn run_afb(afb_path: &Path, _user_args: &[String]) -> Result<()> {
    anyhow::bail!(
        "running native WASM packages requires the `wasm` feature (rebuild with `--features wasm`). \
         Package: {}",
        afb_path.display()
    )
}

// ---- single-file native script runner ---------------------------------------

/// Compile a bare native source file on-the-fly and run it as a WASI
/// command module with capabilities derived from the CLI sandbox flags.
///
/// The extension declares the language (no afb.toml needed):
/// `.rs` -> `rustc --target wasm32-wasip1`
/// `.go` -> `GOOS=wasip1 GOARCH=wasm go build`
/// `.c`  -> `clang --target=wasm32-wasip1 --sysroot=<wasi-sdk>` (WASI command)
/// `.cpp` / `.cxx` / `.cc` -> `clang++ --target=wasm32-wasip1 --sysroot=<wasi-sdk>`
/// `.py` / `.pyw` -> Pyodide embedder (zero-config bundle; `BURN_PYTHON_RUNTIME` override)
/// `.rb` -> bundled ruby.wasm embedder (zero-config bundle; `BURN_RUBY_RUNTIME` override)
///
/// Sandbox posture: SEALED BY DEFAULT (no fs preopens, no net, no env).
/// Grants are applied via the standard `--allow-*` / `-A` flags on the CLI.
#[cfg(feature = "wasm")]
fn run_native_script(cli: &Cli, path: &Path, user_args: &[String]) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(ext.as_deref(), Some("py" | "pyw")) {
        return run_python_source(path, user_args);
    }
    if matches!(ext.as_deref(), Some("rb")) {
        return run_ruby_source(path, user_args);
    }
    use super::compile::lang::compile_single_file;
    let abs = path
        .canonicalize()
        .with_context(|| format!("resolving path {}", path.display()))?;
    let wasm_bytes = compile_single_file(&abs)?;
    run_wasm_bytes(cli, &abs, &wasm_bytes, user_args)
}

#[cfg(not(feature = "wasm"))]
fn run_native_script(_cli: &Cli, path: &Path, _user_args: &[String]) -> Result<()> {
    anyhow::bail!(
        "running native source files requires the `wasm` feature \
         (rebuild with `--features wasm`). File: {}",
        path.display()
    )
}

/// Run a `.py` source file via the Pyodide embedder.
///
/// Uses the self-contained, zero-config runtime: the build script bundles
/// Pyodide 0.28.3 (with numpy + pandas) into a target cache, so `burn run x.py`
/// works out of the box with no env vars. `BURN_PYTHON_RUNTIME` (a directory
/// with `pyodide-exnref.wasm` + `python_stdlib.zip`) remains an optional
/// override. Exits with the Python process exit code.
///
/// When neither the bundle nor an override is available (a build where
/// `wasm-opt` or the network was unavailable), emits an honest, actionable
/// error - never a fake success.
#[cfg(feature = "wasm")]
fn run_python_source(path: &Path, _user_args: &[String]) -> Result<()> {
    use afterburner_wasi::pyodide_runner::run_python;
    use std::io::Write;

    let source = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let out = run_python(&source).map_err(|e| anyhow::anyhow!("python runtime error: {e}"))?;

    if !out.stdout.is_empty() {
        std::io::stdout()
            .write_all(&out.stdout)
            .context("writing python stdout")?;
    }

    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
    Ok(())
}

/// Python source runner when the `wasm` feature is absent: honest error.
#[cfg(not(feature = "wasm"))]
fn run_python_source(path: &Path, _user_args: &[String]) -> Result<()> {
    anyhow::bail!(
        "running Python source files requires the `wasm` feature \
         (rebuild with `--features wasm`). File: {}",
        path.display()
    )
}

/// Run a `.rb` source file via the bundled ruby.wasm runtime.
///
/// Uses the self-contained, zero-config runtime: the build script fetches the
/// stock `ruby-3.4-wasm32-unknown-wasip1-full` release into a target cache and
/// extracts the standalone CRuby WASI module + its stdlib, so `burn run x.rb`
/// works out of the box with no env vars. `BURN_RUBY_RUNTIME` (a directory with
/// `ruby.wasm`) remains an optional override. Exits with the Ruby process exit
/// code.
///
/// When neither the bundle nor an override is available (a build where the
/// network was unavailable), emits an honest, actionable error - never a fake
/// success.
#[cfg(feature = "wasm")]
fn run_ruby_source(path: &Path, _user_args: &[String]) -> Result<()> {
    use afterburner_wasi::ruby_runner::run_ruby;
    use std::io::Write;

    let source = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let out = run_ruby(&source).map_err(|e| anyhow::anyhow!("ruby runtime error: {e}"))?;

    // Faithful streams: program output to stdout, Ruby diagnostics (an uncaught
    // exception, a syntax error) to stderr - so `burn run x.rb` behaves like a
    // real `ruby x.rb` and a failing script shows its reason.
    if !out.stdout.is_empty() {
        std::io::stdout()
            .write_all(&out.stdout)
            .context("writing ruby stdout")?;
    }
    if !out.stderr.is_empty() {
        std::io::stderr()
            .write_all(&out.stderr)
            .context("writing ruby stderr")?;
    }

    if out.exit_code != 0 {
        std::process::exit(out.exit_code);
    }
    Ok(())
}

/// Ruby source runner when the `wasm` feature is absent: honest error.
#[cfg(not(feature = "wasm"))]
fn run_ruby_source(path: &Path, _user_args: &[String]) -> Result<()> {
    anyhow::bail!(
        "running Ruby source files requires the `wasm` feature \
         (rebuild with `--features wasm`). File: {}",
        path.display()
    )
}

/// Execute raw WASM bytes as a WASI command via `EmbedderVm::run_command`,
/// wiring capabilities from the CLI sandbox flags.
#[cfg(feature = "wasm")]
fn run_wasm_bytes(cli: &Cli, path: &Path, wasm_bytes: &[u8], user_args: &[String]) -> Result<()> {
    use afterburner_wasi::embedder_vm::EmbedderVm;

    let vm = EmbedderVm::new().context("creating EmbedderVm")?;
    let module = vm
        .compile(wasm_bytes, true, |_| Ok(()))
        .context("compiling WASM module")?;

    let mut argv = vec![path.to_string_lossy().into_owned()];
    argv.extend_from_slice(user_args);

    let opts = wasi_opts_from_cli(cli, WasiCommandOpts::new().args(argv));

    let output = vm
        .run_command(&module, opts, None)
        .context("running WASM command")?;

    if !output.stdout.is_empty() {
        use std::io::Write;
        std::io::stdout()
            .write_all(&output.stdout)
            .context("writing WASM stdout")?;
    }

    let exit_code = output.result as i32;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Build `WasiCommandOpts` capability grants from the CLI sandbox flags.
///
/// Sealed by default (no grants). Each `--allow-*` flag adds its grant.
/// `-A` / `--allow-all` grants: filesystem root (rw), current dir (rw),
/// and inherits all current-process environment variables.
#[cfg(feature = "wasm")]
fn wasi_opts_from_cli(cli: &Cli, mut opts: WasiCommandOpts) -> WasiCommandOpts {
    use super::manifold::parse_allow_list;

    if cli.allow_all {
        // Full access: preopen host root read-write as guest `/`.
        // This covers all absolute paths the module might open.
        // Forward all current-process environment variables too.
        opts = opts.preopen_rw("/", "/");
        for (k, v) in std::env::vars() {
            opts = opts.env_var(k, v);
        }
        return opts;
    }

    // Granular grants from --allow-fs / --allow-fs-read / --allow-fs-write.
    if let Some(s) = cli.allow_fs.as_deref() {
        let paths = parse_allow_list(s);
        let roots: Vec<String> = if paths.is_empty() || paths.iter().any(|p| p == "*") {
            vec!["/".into()]
        } else {
            paths
        };
        for root in roots {
            opts = opts.preopen_rw(&root, &root);
        }
    }
    if let Some(s) = cli.allow_fs_read.as_deref() {
        let paths = parse_allow_list(s);
        let roots: Vec<String> = if paths.is_empty() || paths.iter().any(|p| p == "*") {
            vec!["/".into()]
        } else {
            paths
        };
        for root in roots {
            opts = opts.preopen_ro(&root, &root);
        }
    }
    if let Some(s) = cli.allow_fs_write.as_deref() {
        let paths = parse_allow_list(s);
        let roots: Vec<String> = if paths.is_empty() || paths.iter().any(|p| p == "*") {
            vec!["/".into()]
        } else {
            paths
        };
        for root in roots {
            opts = opts.preopen_rw(&root, &root);
        }
    }

    // --allow-env: forward the named env vars (or all on wildcard).
    if let Some(s) = cli.allow_env.as_deref() {
        let vars = parse_allow_list(s);
        if vars.is_empty() || vars.iter().any(|v| v == "*") {
            for (k, v) in std::env::vars() {
                opts = opts.env_var(k, v);
            }
        } else {
            for key in vars {
                if let Ok(val) = std::env::var(&key) {
                    opts = opts.env_var(key, val);
                }
            }
        }
    }

    // NOTE: --allow-net / --allow-listen have no WASI equivalent at the
    // embedder layer (WASI preview-1 has no network syscalls). Network
    // access from native WASM would require the WASI sockets proposal
    // (preview-2+), which is not wired here.
    // vertexia: network grants for WASI command modules need wasi-sockets (preview-2)

    opts
}

/// Resolve the entry file of the package rooted at `dir` from its
/// `afb.toml`. Errors clearly when there is no package here.
fn resolve_package_entry(dir: &std::path::Path) -> Result<PathBuf> {
    let manifest_path = dir.join("afb.toml");
    if !manifest_path.exists() {
        anyhow::bail!(
            "no afb.toml in the current directory - `burn run` with no FILE \
             runs the current package's entry. Pass a file (`burn run script.js`) \
             or run inside a package (`burn init` to create one)."
        );
    }
    let text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: toml::Value =
        toml::from_str(&text).with_context(|| format!("parsing {}", manifest_path.display()))?;
    let entry = manifest
        .get("package")
        .and_then(|p| p.get("entry"))
        .and_then(|e| e.as_str())
        .ok_or_else(|| anyhow::anyhow!("afb.toml has no [package].entry"))?;
    let path = dir.join(entry);
    if !path.exists() {
        anyhow::bail!(
            "package entry {entry:?} (from afb.toml) does not exist at {}",
            path.display()
        );
    }
    Ok(path)
}

pub fn run_file(cli: &Cli, path: &PathBuf, user_args: &[String]) -> Result<()> {
    // A bare native source file (.rs / .go / .c / .py / .rb) has no
    // afb.toml: the extension IS the language declaration. Compile
    // on-the-fly to WASM and run through the embedder with the
    // capability set derived from the CLI sandbox flags.
    if is_native_script(path) {
        return run_native_script(cli, path, user_args);
    }

    // Package-manager internals (npm/yarn/pnpm cli scripts re-entering
    // through the PATH shim) are host tooling, not user code: they need
    // fs/env/net to do their job, and a sealed run would brick `burn
    // --sandbox npm test` before the user's script even starts. Run THEM
    // open; the sandbox/grant flags still reach the actual scripts they
    // spawn via the flags baked into the shim (see `shim::ensure_shim_dir`).
    let opened;
    let cli = if cli.sandbox && is_pm_internal(path) {
        opened = pm_open(cli);
        &opened
    } else {
        cli
    };
    if cli.watch {
        return watch::run_with_watch(cli, path, user_args);
    }
    let source = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let label = script_label(path);
    let js_source = with_preload(cli, &maybe_transpile_ts(&source, path)?);
    if cli.internal_worker {
        // worker child mode. Bootstraps a `DaemonWorkers::new_child`
        // (which blocks on stdin for the init frame) and runs the
        // script under the same daemon-mode plumbing the parent uses.
        return super::worker::execute(cli, &js_source, &label, user_args);
    }
    execute(cli, &js_source, &label, user_args)
}

/// Whether `path` is a package manager's own cli script (the things the
/// PATH shim re-enters with when npm/yarn/pnpm internally spawn `node`).
/// Canonicalized first: `~/.nvm/versions/node/*/bin/npm` is a symlink into
/// `node_modules/npm/` and the shim hands us the symlink.
fn is_pm_internal(path: &Path) -> bool {
    let real = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let p = real.to_string_lossy().replace('\\', "/");
    let name = p.rsplit('/').next().unwrap_or("");
    matches!(name, "npm-cli.js" | "npx-cli.js" | "yarn.js" | "pnpm.cjs")
        || [
            "/node_modules/npm/",
            "/node_modules/yarn/",
            "/node_modules/pnpm/",
            "/node_modules/corepack/",
        ]
        .iter()
        .any(|frag| p.contains(frag))
}

/// `cli` with the manifold-restricting flags cleared - the open posture a
/// package manager's own code runs under.
fn pm_open(cli: &Cli) -> Cli {
    let mut open = cli.clone();
    open.sandbox = false;
    open.allow_net = None;
    open.allow_listen = None;
    open.allow_fs = None;
    open.allow_fs_read = None;
    open.allow_fs_write = None;
    open.allow_env = None;
    open
}

pub fn run_source(cli: &Cli, source: &str, user_args: &[String]) -> Result<()> {
    let prepared = with_preload(cli, source);
    if cli.internal_worker {
        return super::worker::execute(cli, &prepared, "[eval]", &[]);
    }
    execute(cli, &prepared, "[eval]", user_args)
}

/// Prepend `--require=mod` / `--import=mod` preload modules to the
/// user source, plus the `--permission` grant map. Both flags collapse
/// onto `require(spec)` here - burn has a single CJS-shaped resolver,
/// so the ESM `--import` form is a `require()` of a module that was
/// lowered through TS-strip + ESM rewrite at load time. Order matches
/// Node: `--require` first, then `--import`.
fn with_preload(cli: &Cli, source: &str) -> String {
    let permission_prelude = build_permission_prelude(cli);
    if cli.require.is_empty() && cli.import.is_empty() && permission_prelude.is_empty() {
        return source.to_string();
    }
    let mut out = String::with_capacity(source.len() + 256);
    out.push_str(&permission_prelude);
    for spec in cli.require.iter().chain(cli.import.iter()) {
        // Each spec gets its own try-wrapped require so a missing
        // preload doesn't kill the user script silently. Failures
        // surface on stderr and the script still runs.
        let escaped = spec.replace('\\', "\\\\").replace('\'', "\\'");
        out.push_str(&format!(
            "try {{ require('{escaped}'); }} catch (e) {{ \
             console.error('burn: preload failed for', '{escaped}', ':', e && e.message); \
            }}\n"
        ));
    }
    out.push_str(source);
    out
}

/// Build the JS prelude that installs `globalThis.__ab_permission_grants`
/// when `--permission` is set on the CLI. Empty when the flag is off -
/// `process.permission.has` then defaults to allow-all (manifold is the
/// real gate). Each `--allow-*` flag becomes one entry on the grants
/// map; the JS-side `has()` implementation does the prefix / wildcard
/// matching.
fn build_permission_prelude(cli: &Cli) -> String {
    if !cli.permission {
        return String::new();
    }
    let mut entries: Vec<String> = Vec::new();
    if let Some(v) = cli.allow_fs_read.as_deref() {
        entries.push(format!("'fs.read': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_fs_write.as_deref() {
        entries.push(format!("'fs.write': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_fs.as_deref() {
        // Plain --allow-fs grants both read and write on the same set.
        entries.push(format!("'fs.read': {}", json_string(v)));
        entries.push(format!("'fs.write': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_net.as_deref() {
        entries.push(format!("'net': {}", json_string(v)));
    }
    if let Some(v) = cli.allow_env.as_deref() {
        entries.push(format!("'env': {}", json_string(v)));
    }
    if cli.allow_child_process {
        entries.push("'child_process': true".to_string());
    }
    if cli.allow_worker {
        entries.push("'worker': true".to_string());
    }
    format!(
        "globalThis.__ab_permission_grants = {{ {} }};\n",
        entries.join(", ")
    )
}

fn json_string(s: &str) -> String {
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

mod watch {
    use super::{maybe_transpile_ts, script_label, with_preload};
    use crate::cli::args::Cli;
    use crate::cli::daemon::execute;
    use anyhow::{Context, Result};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    /// `--watch` loop: poll the entry script's mtime; when it changes,
    /// run a fresh execution. Polling at 250 ms feels close to inotify
    /// for an interactive workflow without taking a host-watcher
    /// dependency. Running the script is synchronous here - daemon
    /// mode exits naturally when listeners close, and we re-loop.
    /// We re-run on entry-script change only, matching Node's pre-22
    /// default; transitive `require()` tracking can land later.
    pub(super) fn run_with_watch(cli: &Cli, path: &Path, user_args: &[String]) -> Result<()> {
        let mut last_mtime = mtime_of(path);
        // Fire the script once immediately.
        run_once(cli, path, user_args)?;
        eprintln!("burn --watch: watching {} (Ctrl-C to exit)", path.display());
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let cur = mtime_of(path);
            if cur > last_mtime {
                last_mtime = cur;
                eprintln!("burn --watch: change detected, re-running…");
                if let Err(e) = run_once(cli, path, user_args) {
                    eprintln!("burn --watch: error: {e}");
                }
            }
        }
    }

    fn run_once(cli: &Cli, path: &Path, user_args: &[String]) -> Result<()> {
        let buf = path.to_path_buf();
        let _: PathBuf = buf;
        let source = fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
        let label = script_label(path);
        let js_source = with_preload(cli, &maybe_transpile_ts(&source, path)?);
        execute(cli, &js_source, &label, user_args)
    }

    fn mtime_of(path: &Path) -> SystemTime {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

/// With the `ts` feature: TS files are transpiled (strip-types +
/// ESM→CJS) via oxc, and `.js`/`.mjs` files are ESM-lowered to CJS
/// so `import`/`export` works under our CJS runtime.
///
/// Without the `ts` feature: TS files surface a typed error; `.js`
/// files pass through unchanged (no ESM lowering available without
/// the transpile dep graph).
#[cfg(feature = "ts")]
fn maybe_transpile_ts(source: &str, path: &std::path::Path) -> Result<String> {
    if crate::ts::is_typescript(path) {
        return crate::ts::transpile(source, path).map_err(|e| anyhow::anyhow!("{e}"));
    }
    // lower ESM in plain JS too. Plain CJS source contains no
    // ESM declarations and returns unchanged.
    crate::ts::lower_esm_js(source, path).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(not(feature = "ts"))]
fn maybe_transpile_ts(source: &str, path: &std::path::Path) -> Result<String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(
        ext.as_deref(),
        Some("ts") | Some("mts") | Some("cts") | Some("tsx")
    ) {
        anyhow::bail!(
            "burn: TypeScript support requires the `ts` cargo feature (rebuild with `cargo install afterburner --features ts`). \
             File: {}",
            path.display()
        );
    }
    Ok(source.to_string())
}
