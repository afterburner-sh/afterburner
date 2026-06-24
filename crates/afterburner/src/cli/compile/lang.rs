// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Source language identification and native-to-WASM compile backends.
//!
//! The source language is declared explicitly in `[package] language` in
//! `afb.toml`. No auto-detection is performed: the manifest is the single
//! source of truth.
//!
//! Supported languages and their compile paths:
//! - `js`/`javascript` and `ts`/`typescript` - Javy (existing path).
//! - `rust` - `cargo build --release --target wasm32-wasip1` (multi-module
//!   via Cargo over the shipped `source/` tree).
//! - `go`/`golang` - `GOOS=wasip1 GOARCH=wasm go build` over the package
//!   directory (multi-file / multi-package via the Go module system).
//! - `c` - `clang --target=wasm32-wasip1 --sysroot=<wasi-sdk>` over ALL
//!   `source/**/*.c`, producing a WASI **command** module (real `main`).
//!   A `Makefile`/`CMakeLists.txt`, when present, is preferred.
//! - `cpp`/`c++`/`cxx`/`cc` - `clang++ --target=wasm32-wasip1
//!   --sysroot=<wasi-sdk>` over ALL `source/**/*.{cpp,cxx,cc}` (emcc fallback).
//! - `python`/`py` and `ruby`/`rb` - interpreted: there is no WASM compile.
//!   `burn compile` packs the `source/` tree into a source `.afb` (handled in
//!   [`super::dispatch_compile`]); `burn run` executes it on the bundled
//!   CPython / CRuby interpreter. The dispatch never routes them here.

use super::cc;
use anyhow::{Context, Result};
use std::path::Path;
use std::str::FromStr;

/// Source language declared in `[package] language`.
///
/// Normalized from the string in `afb.toml` by [`SourceLang::from_str`].
/// Unknown values produce a clear error listing the supported identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLang {
    Js,
    Ts,
    Rust,
    Go,
    C,
    Cpp,
    Python,
    Ruby,
}

impl FromStr for SourceLang {
    type Err = anyhow::Error;

    /// Map the `[package] language` string to a [`SourceLang`].
    ///
    /// Normalizes aliases:
    /// - `js`/`javascript` -> `Js`
    /// - `ts`/`typescript` -> `Ts`
    /// - `rust` -> `Rust`
    /// - `go`/`golang` -> `Go`
    /// - `c` -> `C`
    /// - `cpp`/`c++`/`cxx`/`cc` -> `Cpp`
    /// - `python`/`py` -> `Python`
    /// - `ruby`/`rb` -> `Ruby`
    ///
    /// Any other value is a clear error naming the supported identifiers.
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "js" | "javascript" => Ok(Self::Js),
            "ts" | "typescript" => Ok(Self::Ts),
            "rust" => Ok(Self::Rust),
            "go" | "golang" => Ok(Self::Go),
            "c" => Ok(Self::C),
            "cpp" | "c++" | "cxx" | "cc" => Ok(Self::Cpp),
            "python" | "py" => Ok(Self::Python),
            "ruby" | "rb" => Ok(Self::Ruby),
            other => anyhow::bail!(
                "unsupported [package] language {other:?}; \
                 supported values: js, javascript, ts, typescript, rust, go, golang, \
                 c, cpp, c++, cxx, cc, python, py, ruby, rb"
            ),
        }
    }
}

impl SourceLang {
    /// Whether this language uses the Javy (JS/TS) compile path.
    pub fn is_js_family(self) -> bool {
        matches!(self, Self::Js | Self::Ts)
    }

    /// Whether this language can be shipped as source and interpreted at
    /// runtime (JS/TS via the JS engine, Python and Ruby via WASI runtimes).
    /// Rust, Go, C, and C++ compile to WASM and have no source interpreter -
    /// they must be precompiled before packaging.
    pub fn is_interpretable(self) -> bool {
        matches!(self, Self::Js | Self::Ts | Self::Python | Self::Ruby)
    }
}

/// Compile a compiled-to-WASM language package (Rust/Go/C/C++) to a WASM binary.
///
/// `lang` must be one of the compiled languages. JS/TS go through the Javy
/// path and Python/Ruby are interpreted (packed as source, run on the bundled
/// interpreter); both are dispatched in `cli::compile::dispatch_compile` and
/// never reach here. `pkg_dir` is the root of the package (where `afb.toml`
/// lives); `entry` is the value of `[package] entry` (e.g. `source/main.rs`).
///
/// Returns the raw bytes of a `wasm32-wasip1` WASI command module.
pub fn compile_native(lang: SourceLang, pkg_dir: &Path, entry: &str) -> Result<Vec<u8>> {
    match lang {
        SourceLang::Js | SourceLang::Ts => {
            anyhow::bail!("compile_native called for JS/TS - use the JS engine path instead (bug)")
        }
        SourceLang::Python | SourceLang::Ruby => compile_interpreted(lang),
        SourceLang::Rust => compile_rust(pkg_dir),
        SourceLang::Go => compile_go(pkg_dir, entry),
        SourceLang::C => cc::compile_c(pkg_dir, entry),
        SourceLang::Cpp => cc::compile_cpp(pkg_dir, entry),
    }
}

/// Compile a single bare source file (not a package) to a `wasm32-wasip1`
/// WASI command module. The file's extension determines the language.
///
/// Supported extensions: `.rs` (via `rustc`), `.go` (via `go build`),
/// `.c` (via `clang`/`emcc`), `.cpp`/`.cxx`/`.cc` (via `clang++`/`emcc`).
/// Returns an honest error for `.py`/`.rb` (runtime not bundled) and an
/// error for any other extension.
pub fn compile_single_file(source_path: &Path) -> Result<Vec<u8>> {
    let ext = source_path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("rs") => compile_single_file_rust(source_path),
        Some("go") => compile_single_file_go(source_path),
        Some("c") => compile_single_file_c(source_path),
        Some("cpp" | "cxx" | "cc") => compile_single_file_cpp(source_path),
        Some("py" | "pyw") => anyhow::bail!(
            "Python does not compile to a standalone .wasm here: it runs as source on the \
             bundled CPython-WASI runtime. Use `burn run file.py` to execute it."
        ),
        Some("rb") => anyhow::bail!(
            "Ruby does not compile to a standalone .wasm here: it runs as source on the \
             bundled ruby.wasm runtime. Use `burn run file.rb` to execute it."
        ),
        other => anyhow::bail!(
            "cannot compile {:?}: unsupported extension {:?}",
            source_path.display(),
            other.unwrap_or("<none>")
        ),
    }
}

/// Preflight the Rust toolchain before a compile: `rustc` must run and the
/// `wasm32-wasip1` target std must be installed. Returns a precise, actionable
/// error UP FRONT (compiler-missing vs target-missing) so a later non-zero
/// `rustc`/`cargo` exit is unambiguously a compile error, not a setup gap.
///
/// The target check reads `rustc --print sysroot` and looks for
/// `<sysroot>/lib/rustlib/wasm32-wasip1`, which works whether or not `rustup`
/// is the installer.
fn preflight_rust() -> Result<()> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let sysroot = std::process::Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "Rust is required to compile Rust to WebAssembly, but `rustc` was not \
                     found on PATH. Install it from https://rustup.rs"
                )
            } else {
                anyhow::anyhow!("running `rustc --print sysroot`: {e}")
            }
        })?;
    if !sysroot.status.success() {
        anyhow::bail!(
            "`rustc --print sysroot` failed; the Rust toolchain looks broken. \
             Reinstall from https://rustup.rs"
        );
    }
    let root = String::from_utf8_lossy(&sysroot.stdout);
    let target_lib = Path::new(root.trim()).join("lib/rustlib/wasm32-wasip1");
    if !target_lib.exists() {
        anyhow::bail!(
            "the `wasm32-wasip1` target is not installed for this Rust toolchain. \
             Add it with: rustup target add wasm32-wasip1"
        );
    }
    Ok(())
}

/// Preflight the Go toolchain before a compile: `go` must run and be >= 1.21
/// (the first release with the `wasip1` port). Actionable error up front.
fn preflight_go() -> Result<()> {
    let go = std::env::var("GO").unwrap_or_else(|_| "go".into());
    let out = std::process::Command::new(&go)
        .arg("version")
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "Go is required to compile Go to WebAssembly, but `go` was not found on \
                     PATH. Install Go 1.21 or newer from https://go.dev/dl"
                )
            } else {
                anyhow::anyhow!("running `go version`: {e}")
            }
        })?;
    if !out.status.success() {
        anyhow::bail!(
            "`go version` failed; the Go toolchain looks broken. Reinstall from https://go.dev/dl"
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if let Some((major, minor)) = parse_go_minor(&text)
        && (major, minor) < (1, 21)
    {
        anyhow::bail!(
            "Go {major}.{minor} is too old to target wasip1 (the GOOS=wasip1 port arrived \
             in Go 1.21). Upgrade to Go 1.21 or newer: https://go.dev/dl"
        );
    }
    Ok(())
}

/// Parse the `go1.NN.P` token from `go version` output into `(major, minor)`.
/// Returns `None` when the version cannot be parsed (then preflight is lenient
/// and lets the build proceed rather than blocking on an unrecognized banner).
fn parse_go_minor(version_output: &str) -> Option<(u32, u32)> {
    let tok = version_output
        .split_whitespace()
        .find(|t| t.starts_with("go1."))?;
    let mut parts = tok.strip_prefix("go")?.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod preflight_tests {
    use super::parse_go_minor;

    #[test]
    fn parses_go_version_banner() {
        assert_eq!(
            parse_go_minor("go version go1.22.3 linux/amd64"),
            Some((1, 22))
        );
        assert_eq!(
            parse_go_minor("go version go1.21.0 darwin/arm64"),
            Some((1, 21))
        );
        assert_eq!(
            parse_go_minor("go version go1.20 linux/amd64"),
            Some((1, 20))
        );
    }

    #[test]
    fn unparseable_banner_is_none() {
        assert_eq!(parse_go_minor("garbage output"), None);
        assert_eq!(parse_go_minor(""), None);
    }

    #[test]
    fn version_threshold_logic() {
        // The preflight blocks below 1.21; confirm the comparison the gate uses.
        assert!((1u32, 20u32) < (1, 21));
        assert!(!((1u32, 21u32) < (1, 21)));
        assert!(!((1u32, 22u32) < (1, 21)));
    }
}

/// Compile a single `.rs` file to `wasm32-wasip1` via `rustc`.
///
/// Uses `rustc --edition 2021 --target wasm32-wasip1` directly, so no
/// Cargo project is required. Clear remediation when `wasm32-wasip1` is
/// not installed: `rustup target add wasm32-wasip1`.
fn compile_single_file_rust(source_path: &Path) -> Result<Vec<u8>> {
    preflight_rust()?;
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let wasm_out = std::env::temp_dir().join(format!("burn-rs-{}.wasm", std::process::id()));

    let status = std::process::Command::new(&rustc)
        .args([
            "--edition",
            "2021",
            "--target",
            "wasm32-wasip1",
            "-O",
            source_path.to_str().unwrap_or(""),
            "-o",
            wasm_out.to_str().unwrap_or(""),
        ])
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "`rustc` was not found on PATH. \
                     Install Rust from https://rustup.rs"
                )
            } else {
                anyhow::anyhow!("spawning `rustc`: {e}")
            }
        })?;

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        anyhow::bail!(
            "`rustc --target wasm32-wasip1` exited with code {code} \
             (compilation failed; see the errors above)"
        );
    }

    let bytes = std::fs::read(&wasm_out)
        .with_context(|| format!("reading compiled Rust WASM {}", wasm_out.display()))?;
    let _ = std::fs::remove_file(&wasm_out);
    Ok(bytes)
}

/// Compile a single `.go` file to `wasm32-wasip1` WASM.
///
/// The parent directory is treated as the Go package directory so that
/// local imports within the same directory resolve correctly.
fn compile_single_file_go(source_path: &Path) -> Result<Vec<u8>> {
    // The package dir is the directory containing the file.
    let pkg_dir = source_path.parent().unwrap_or_else(|| Path::new("."));
    let entry = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    compile_go(pkg_dir, entry)
}

/// Compile a single `.c` file to a `wasm32-wasip1` WASI command module.
///
/// The parent directory is used as the working directory (for relative
/// `#include` paths) and the file name as the entry.
fn compile_single_file_c(source_path: &Path) -> Result<Vec<u8>> {
    let pkg_dir = source_path.parent().unwrap_or_else(|| Path::new("."));
    let entry = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    cc::compile_c(pkg_dir, entry)
}

/// Compile a single `.cpp`/`.cxx`/`.cc` file to a `wasm32-wasip1` WASI
/// command module.
///
/// The parent directory is used as the working directory (for relative
/// `#include` paths) and the file name as the entry.
fn compile_single_file_cpp(source_path: &Path) -> Result<Vec<u8>> {
    let pkg_dir = source_path.parent().unwrap_or_else(|| Path::new("."));
    let entry = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    cc::compile_cpp(pkg_dir, entry)
}

/// Compile a Rust package to `wasm32-wasip1` via Cargo.
///
/// Runs `cargo build --release --target wasm32-wasip1` inside `pkg_dir`.
/// Expects exactly one `.wasm` output under
/// `target/wasm32-wasip1/release/*.wasm`; errors when none or more than
/// one is found.
///
/// Clear remediation when the `wasm32-wasip1` target is not installed:
/// `rustup target add wasm32-wasip1`.
fn compile_rust(pkg_dir: &Path) -> Result<Vec<u8>> {
    preflight_rust()?;
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    let status = std::process::Command::new(&cargo)
        .args(["build", "--release", "--target", "wasm32-wasip1"])
        .current_dir(pkg_dir)
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "`cargo` was not found on PATH. \
                     Install Rust from https://rustup.rs"
                )
            } else {
                anyhow::anyhow!("spawning `cargo`: {e}")
            }
        })?;

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        // preflight_rust() already verified rustc + the wasm32-wasip1 target,
        // so a non-zero exit here is a genuine build error (shown above).
        anyhow::bail!(
            "`cargo build --target wasm32-wasip1` exited with code {code} \
             (build failed; see the errors above)"
        );
    }

    // Locate the produced .wasm file. There should be exactly one binary.
    let release_dir = pkg_dir.join("target/wasm32-wasip1/release");
    let wasm_files: Vec<_> = std::fs::read_dir(&release_dir)
        .with_context(|| format!("reading {}", release_dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "wasm")
                // Skip .d.wasm (debug info) and deps/
                && p.parent().is_some_and(|parent| parent == release_dir)
        })
        .collect();

    match wasm_files.as_slice() {
        [path] => {
            std::fs::read(path).with_context(|| format!("reading compiled WASM {}", path.display()))
        }
        [] => anyhow::bail!(
            "no .wasm output found under {}; \
             ensure Cargo.toml has `[[bin]]` or `[lib] crate-type = [\"cdylib\"]`",
            release_dir.display()
        ),
        paths => {
            // Multiple binaries: pick by the package name (Cargo.toml `name`).
            let pkg_name = read_cargo_package_name(pkg_dir).unwrap_or_default();
            let candidate = paths
                .iter()
                .find(|p| {
                    p.file_stem()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s == pkg_name || s.replace('-', "_") == pkg_name)
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "multiple .wasm files found under {} ({} total); \
                         could not determine which one to use. \
                         Ensure only one [[bin]] target is declared.",
                        release_dir.display(),
                        paths.len()
                    )
                })?;
            std::fs::read(candidate)
                .with_context(|| format!("reading compiled WASM {}", candidate.display()))
        }
    }
}

/// Read `[package] name` from `Cargo.toml` in `dir`.
/// Returns `None` on any parse failure (non-fatal; used for disambiguation only).
fn read_cargo_package_name(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let doc: toml::Table = toml::from_str(&text).ok()?;
    doc.get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(str::to_string)
}

/// Compile a Go package to `wasm32-wasip1` WASM.
///
/// Runs `GOOS=wasip1 GOARCH=wasm go build -o <tmp.wasm> <entry_or_dir>`.
/// `entry` from `afb.toml` is treated as the go source file if it has a
/// `.go` extension, otherwise the `pkg_dir` itself is passed (whole package).
fn compile_go(pkg_dir: &Path, entry: &str) -> Result<Vec<u8>> {
    preflight_go()?;
    let go = std::env::var("GO").unwrap_or_else(|_| "go".into());

    // Output to a temp file in the package dir so relative imports work.
    let wasm_out = std::env::temp_dir().join(format!("burn-go-{}.wasm", std::process::id()));

    // If the entry file is a single .go file, pass it directly; otherwise
    // build the whole package directory.
    let source_path = pkg_dir.join(entry);
    let build_target: String = if source_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("go"))
        && source_path.exists()
    {
        source_path.to_string_lossy().into_owned()
    } else {
        // Build the module/package directory.
        pkg_dir.to_string_lossy().into_owned()
    };

    let status = std::process::Command::new(&go)
        .args([
            "build",
            "-o",
            wasm_out.to_str().unwrap_or(""),
            &build_target,
        ])
        .env("GOOS", "wasip1")
        .env("GOARCH", "wasm")
        .current_dir(pkg_dir)
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "`go` was not found on PATH. \
                     Install Go from https://go.dev/dl"
                )
            } else {
                anyhow::anyhow!("spawning `go`: {e}")
            }
        })?;

    if !status.success() {
        let _ = std::fs::remove_file(&wasm_out);
        anyhow::bail!(
            "`GOOS=wasip1 GOARCH=wasm go build` exited with code {}",
            status.code().unwrap_or(-1)
        );
    }

    let bytes = std::fs::read(&wasm_out)
        .with_context(|| format!("reading compiled Go WASM {}", wasm_out.display()))?;
    let _ = std::fs::remove_file(&wasm_out);
    Ok(bytes)
}

/// Backend for an interpreted language (Python / Ruby) reached through the
/// WASM-compile dispatch.
///
/// Python and Ruby do not compile to a WASM artifact: a `burn compile` of such
/// a package packs the `source/` tree into a source `.afb` (see
/// `cli::compile::dispatch_compile` -> `pack_source_afb`), and `burn run`
/// executes that source on the bundled CPython / CRuby interpreter. So this
/// function is never reached on a correct dispatch; it returns a clear error
/// (rather than `unreachable!`) to fail loud, not panic, if a future caller
/// routes an interpreted language into the WASM path by mistake.
fn compile_interpreted(lang: SourceLang) -> Result<Vec<u8>> {
    let (lang_name, run_hint) = match lang {
        SourceLang::Python => ("Python", "burn run file.py"),
        SourceLang::Ruby => ("Ruby", "burn run file.rb"),
        other => anyhow::bail!("compile_interpreted called for non-interpreted language {other:?}"),
    };
    anyhow::bail!(
        "{lang_name} does not compile to a WASM artifact: it ships as source and runs on \
         the bundled interpreter. `burn compile` packs the source `.afb`; `{run_hint}` runs \
         it. Reaching the WASM-compile path for {lang_name} is a dispatch bug."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_aliases_parse_correctly() {
        assert_eq!(SourceLang::from_str("js").unwrap(), SourceLang::Js);
        assert_eq!(SourceLang::from_str("JavaScript").unwrap(), SourceLang::Js);
        assert_eq!(SourceLang::from_str("ts").unwrap(), SourceLang::Ts);
        assert_eq!(SourceLang::from_str("TypeScript").unwrap(), SourceLang::Ts);
        assert_eq!(SourceLang::from_str("rust").unwrap(), SourceLang::Rust);
        assert_eq!(SourceLang::from_str("Rust").unwrap(), SourceLang::Rust);
        assert_eq!(SourceLang::from_str("go").unwrap(), SourceLang::Go);
        assert_eq!(SourceLang::from_str("golang").unwrap(), SourceLang::Go);
        assert_eq!(SourceLang::from_str("Go").unwrap(), SourceLang::Go);
        assert_eq!(SourceLang::from_str("c").unwrap(), SourceLang::C);
        assert_eq!(SourceLang::from_str("C").unwrap(), SourceLang::C);
        assert_eq!(SourceLang::from_str("cpp").unwrap(), SourceLang::Cpp);
        assert_eq!(SourceLang::from_str("c++").unwrap(), SourceLang::Cpp);
        assert_eq!(SourceLang::from_str("cxx").unwrap(), SourceLang::Cpp);
        assert_eq!(SourceLang::from_str("cc").unwrap(), SourceLang::Cpp);
        assert_eq!(SourceLang::from_str("CPP").unwrap(), SourceLang::Cpp);
        assert_eq!(SourceLang::from_str("python").unwrap(), SourceLang::Python);
        assert_eq!(SourceLang::from_str("py").unwrap(), SourceLang::Python);
        assert_eq!(SourceLang::from_str("Python").unwrap(), SourceLang::Python);
    }

    #[test]
    fn unknown_language_gives_clear_error() {
        let err = SourceLang::from_str("haskell").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("haskell"), "must name the unknown lang: {msg}");
        assert!(msg.contains("rust"), "must list supported langs: {msg}");
        assert!(msg.contains("go"), "must list go: {msg}");
        assert!(msg.contains("python"), "must list python: {msg}");
    }

    #[test]
    fn ruby_parses_correctly() {
        assert_eq!(SourceLang::from_str("ruby").unwrap(), SourceLang::Ruby);
        assert_eq!(SourceLang::from_str("rb").unwrap(), SourceLang::Ruby);
        assert_eq!(SourceLang::from_str("Ruby").unwrap(), SourceLang::Ruby);
    }

    #[test]
    fn ruby_is_interpretable() {
        assert!(SourceLang::Ruby.is_interpretable());
        assert!(!SourceLang::Ruby.is_js_family());
    }

    #[test]
    fn ruby_via_wasm_compile_path_errors_as_interpreted() {
        // Ruby is interpreted: routing it through the WASM-compile path
        // (`compile_native`) is a dispatch bug, so it fails loud with a clear
        // "ships as source" message rather than producing a bogus artifact.
        use std::path::Path;
        let err =
            compile_native(SourceLang::Ruby, Path::new("/tmp"), "source/main.rb").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("source") && msg.contains("interpreter"),
            "must explain Ruby ships as source on the bundled interpreter: {msg}"
        );
    }

    #[test]
    fn js_family_predicate() {
        assert!(SourceLang::Js.is_js_family());
        assert!(SourceLang::Ts.is_js_family());
        assert!(!SourceLang::Rust.is_js_family());
        assert!(!SourceLang::Go.is_js_family());
        assert!(!SourceLang::C.is_js_family());
        assert!(!SourceLang::Cpp.is_js_family());
        assert!(!SourceLang::Python.is_js_family());
    }

    #[test]
    fn interpretable_predicate() {
        // JS/TS and Python can run as source; Rust/Go/C/C++ must be precompiled.
        assert!(SourceLang::Js.is_interpretable());
        assert!(SourceLang::Ts.is_interpretable());
        assert!(SourceLang::Python.is_interpretable());
        assert!(!SourceLang::Rust.is_interpretable());
        assert!(!SourceLang::Go.is_interpretable());
        assert!(!SourceLang::C.is_interpretable());
        assert!(!SourceLang::Cpp.is_interpretable());
    }

    #[test]
    fn cpp_parses_and_is_native() {
        let l = SourceLang::from_str("c++").unwrap();
        assert_eq!(l, SourceLang::Cpp);
        assert!(!l.is_js_family());
        assert!(!l.is_interpretable());
    }

    // The C/C++ compile backend (wasi-sdk discovery, multi-file source
    // collection, build-system, honest "wasi-sdk not found") is tested in
    // `super::cc`'s own `mod tests`.

    #[test]
    fn python_via_wasm_compile_path_errors_as_interpreted() {
        // Python is interpreted: routing it through the WASM-compile path
        // (`compile_native`) is a dispatch bug, so it fails loud with a clear
        // "ships as source" message rather than producing a bogus artifact.
        use std::path::Path;
        let err =
            compile_native(SourceLang::Python, Path::new("/tmp"), "source/main.py").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("source") && msg.contains("interpreter"),
            "must explain Python ships as source on the bundled interpreter: {msg}"
        );
    }

    // ---- compile_single_file dispatch -----------------------------------------

    #[test]
    fn single_file_py_points_at_burn_run() {
        // Python is interpreted, not compiled to a standalone .wasm: the
        // single-file compile path directs the user to `burn run` instead.
        use std::path::Path;
        let err = compile_single_file(Path::new("hello.py")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("burn run") && msg.contains("bundled"),
            "must point at the bundled-runtime run path: {msg}"
        );
    }

    #[test]
    fn single_file_rb_points_at_burn_run() {
        // Ruby is interpreted, not compiled to a standalone .wasm: the
        // single-file compile path directs the user to `burn run` instead.
        use std::path::Path;
        let err = compile_single_file(Path::new("hello.rb")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("burn run") && msg.contains("bundled"),
            "must point at the bundled-runtime run path: {msg}"
        );
    }

    #[test]
    fn single_file_unknown_extension_gives_clear_error() {
        use std::path::Path;
        let err = compile_single_file(Path::new("hello.haskell")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported") || msg.contains("haskell"),
            "must name the unsupported extension: {msg}"
        );
    }
}
