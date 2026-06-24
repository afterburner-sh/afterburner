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
//! - `python`/`py` and `ruby`/`rb` - pending (honest error; structure wired).

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

/// Compile a native language package (Rust/Go/C/C++/Python) to a WASM binary.
///
/// `lang` must not be `Js` or `Ts` (those go through the Javy path).
/// `pkg_dir` is the root of the package (where `afb.toml` lives).
/// `entry` is the value of `[package] entry` (e.g. `source/main.rs`).
///
/// Returns the raw bytes of a `wasm32-wasip1` WASI command module.
pub fn compile_native(lang: SourceLang, pkg_dir: &Path, entry: &str) -> Result<Vec<u8>> {
    match lang {
        SourceLang::Js | SourceLang::Ts => {
            anyhow::bail!("compile_native called for JS/TS - use the JS engine path instead (bug)")
        }
        SourceLang::Rust => compile_rust(pkg_dir),
        SourceLang::Go => compile_go(pkg_dir, entry),
        SourceLang::C => cc::compile_c(pkg_dir, entry),
        SourceLang::Cpp => cc::compile_cpp(pkg_dir, entry),
        SourceLang::Python => compile_python(pkg_dir, entry),
        SourceLang::Ruby => compile_ruby(pkg_dir, entry),
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
            "Python runtime not available: the CPython-WASI payload is not bundled. \
             Install it and re-run, or use a Python package with `burn compile`."
        ),
        Some("rb") => anyhow::bail!(
            "Ruby runtime not available: the ruby.wasm payload is not bundled. \
             Install it and re-run, or use a Ruby package with `burn compile`."
        ),
        other => anyhow::bail!(
            "cannot compile {:?}: unsupported extension {:?}",
            source_path.display(),
            other.unwrap_or("<none>")
        ),
    }
}

/// Compile a single `.rs` file to `wasm32-wasip1` via `rustc`.
///
/// Uses `rustc --edition 2021 --target wasm32-wasip1` directly, so no
/// Cargo project is required. Clear remediation when `wasm32-wasip1` is
/// not installed: `rustup target add wasm32-wasip1`.
fn compile_single_file_rust(source_path: &Path) -> Result<Vec<u8>> {
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
            "`rustc --target wasm32-wasip1` exited with code {code}. \
             If the target is missing: rustup target add wasm32-wasip1"
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
        // Check if the error is likely a missing target.
        let target_dir = pkg_dir.join("target/wasm32-wasip1");
        if !target_dir.exists() {
            return Err(anyhow::anyhow!(
                "`cargo build --target wasm32-wasip1` exited with code {code}. \
                 The wasm32-wasip1 target may not be installed. \
                 Fix with: rustup target add wasm32-wasip1"
            ));
        }
        anyhow::bail!("`cargo build --target wasm32-wasip1` exited with code {code}");
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

/// Python compile backend.
///
/// Python-WASM packaging requires the CPython-WASI payload (a WASM build
/// of the CPython interpreter). This payload is not yet bundled in
/// afterburner. This function emits an honest, actionable error.
///
/// The structure is wired so that when the payload lands, only this function
/// needs to change.
fn compile_python(_pkg_dir: &Path, _entry: &str) -> Result<Vec<u8>> {
    anyhow::bail!(
        "Python packaging needs the afterburner-python payload (pending). \
         Python-to-WASM support is wired but the CPython-WASI runtime bundle \
         is not yet included. Contributions welcome."
    )
}

/// Ruby compile backend.
///
/// Ruby-WASM packaging requires the ruby.wasm runtime bundle (a WASM build
/// of the CRuby interpreter). This payload is not yet bundled in
/// afterburner. This function emits an honest, actionable error.
///
/// The structure is wired so that when the payload lands, only this function
/// needs to change.
fn compile_ruby(_pkg_dir: &Path, _entry: &str) -> Result<Vec<u8>> {
    anyhow::bail!(
        "Ruby packaging needs the ruby.wasm runtime payload (pending). \
         Ruby-to-WASM support is wired but the ruby.wasm bundle \
         is not yet included. Contributions welcome."
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
    fn ruby_backend_gives_honest_pending_error() {
        use std::path::Path;
        let err = compile_ruby(Path::new("/tmp"), "source/main.rb").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("pending") || msg.contains("not yet"),
            "must indicate pending: {msg}"
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
    fn python_backend_gives_honest_pending_error() {
        use std::path::Path;
        let err = compile_python(Path::new("/tmp"), "source/main.py").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("pending") || msg.contains("not yet"),
            "must indicate pending: {msg}"
        );
    }

    // ---- compile_single_file dispatch -----------------------------------------

    #[test]
    fn single_file_py_gives_runtime_not_available() {
        use std::path::Path;
        let err = compile_single_file(Path::new("hello.py")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not available") || msg.contains("not bundled"),
            "must say runtime not available: {msg}"
        );
    }

    #[test]
    fn single_file_rb_gives_runtime_not_available() {
        use std::path::Path;
        let err = compile_single_file(Path::new("hello.rb")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not available") || msg.contains("not bundled"),
            "must say runtime not available: {msg}"
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
