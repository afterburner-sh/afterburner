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
//! - `rust` - `cargo build --release --target wasm32-wasip1`.
//! - `go`/`golang` - `GOOS=wasip1 GOARCH=wasm go build`.
//! - `c` - `clang --target=wasm32-wasi` or `emcc` (requires wasi-sdk/emcc).
//! - `python`/`py` - pending (honest error; structure is wired).

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
    Python,
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
    /// - `python`/`py` -> `Python`
    ///
    /// Any other value is a clear error naming the supported identifiers.
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "js" | "javascript" => Ok(Self::Js),
            "ts" | "typescript" => Ok(Self::Ts),
            "rust" => Ok(Self::Rust),
            "go" | "golang" => Ok(Self::Go),
            "c" => Ok(Self::C),
            "python" | "py" => Ok(Self::Python),
            other => anyhow::bail!(
                "unsupported [package] language {other:?}; \
                 supported values: js, javascript, ts, typescript, rust, go, golang, c, python, py"
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
    /// runtime (JS/TS via the JS engine, Python via the CPython-WASI runtime).
    /// Rust, Go, and C compile to WASM and have no source interpreter - they
    /// must be precompiled before packaging.
    pub fn is_interpretable(self) -> bool {
        matches!(self, Self::Js | Self::Ts | Self::Python)
    }
}

/// Compile a native language package (Rust/Go/C/Python) to a WASM binary.
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
        SourceLang::C => compile_c(pkg_dir, entry),
        SourceLang::Python => compile_python(pkg_dir, entry),
    }
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

/// Compile a C source file to `wasm32-wasi` WASM.
///
/// Tries `clang --target=wasm32-wasi` first, then `emcc`.
/// Emits a clear actionable error when neither tool is present.
fn compile_c(pkg_dir: &Path, entry: &str) -> Result<Vec<u8>> {
    let source = pkg_dir.join(entry);
    if !source.exists() {
        anyhow::bail!(
            "C entry file {:?} does not exist in {}",
            entry,
            pkg_dir.display()
        );
    }

    let wasm_out = std::env::temp_dir().join(format!("burn-c-{}.wasm", std::process::id()));

    // Try clang first (requires wasi-sdk on PATH or WASI_SDK_PATH).
    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let clang_result = std::process::Command::new(&clang)
        .args([
            "--target=wasm32-wasi",
            "-nostdlib",
            "-Wl,--no-entry",
            "-Wl,--export-all",
            source.to_str().unwrap_or(""),
            "-o",
            wasm_out.to_str().unwrap_or(""),
        ])
        .current_dir(pkg_dir)
        .status();

    match clang_result {
        Ok(s) if s.success() => {
            let bytes = std::fs::read(&wasm_out)
                .with_context(|| format!("reading C WASM {}", wasm_out.display()))?;
            let _ = std::fs::remove_file(&wasm_out);
            return Ok(bytes);
        }
        Ok(s) => {
            let _ = std::fs::remove_file(&wasm_out);
            let code = s.code().unwrap_or(-1);
            anyhow::bail!(
                "`clang --target=wasm32-wasi` exited with code {code}. \
                 Install wasi-sdk: https://github.com/WebAssembly/wasi-sdk/releases"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // clang not found - try emcc
        }
        Err(e) => anyhow::bail!("spawning `clang`: {e}"),
    }

    // Fallback: emcc
    let emcc_result = std::process::Command::new("emcc")
        .args([
            source.to_str().unwrap_or(""),
            "-o",
            wasm_out.to_str().unwrap_or(""),
            "-s",
            "WASM=1",
            "-s",
            "STANDALONE_WASM=1",
        ])
        .current_dir(pkg_dir)
        .status();

    match emcc_result {
        Ok(s) if s.success() => {
            let bytes = std::fs::read(&wasm_out)
                .with_context(|| format!("reading C WASM (emcc) {}", wasm_out.display()))?;
            let _ = std::fs::remove_file(&wasm_out);
            Ok(bytes)
        }
        Ok(s) => {
            let _ = std::fs::remove_file(&wasm_out);
            anyhow::bail!(
                "`emcc` exited with code {}. \
                 Install Emscripten: https://emscripten.org/docs/getting_started/downloads.html",
                s.code().unwrap_or(-1)
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "C compilation requires either `clang` with wasi-sdk or `emcc` (Emscripten). \
                 Neither was found on PATH.\n\
                 - wasi-sdk: https://github.com/WebAssembly/wasi-sdk/releases\n\
                 - Emscripten: https://emscripten.org/docs/getting_started/downloads.html"
            );
        }
        Err(e) => anyhow::bail!("spawning `emcc`: {e}"),
    }
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
        assert_eq!(SourceLang::from_str("python").unwrap(), SourceLang::Python);
        assert_eq!(SourceLang::from_str("py").unwrap(), SourceLang::Python);
        assert_eq!(SourceLang::from_str("Python").unwrap(), SourceLang::Python);
    }

    #[test]
    fn unknown_language_gives_clear_error() {
        let err = SourceLang::from_str("ruby").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ruby"), "must name the unknown lang: {msg}");
        assert!(msg.contains("rust"), "must list supported langs: {msg}");
        assert!(msg.contains("go"), "must list go: {msg}");
        assert!(msg.contains("python"), "must list python: {msg}");
    }

    #[test]
    fn js_family_predicate() {
        assert!(SourceLang::Js.is_js_family());
        assert!(SourceLang::Ts.is_js_family());
        assert!(!SourceLang::Rust.is_js_family());
        assert!(!SourceLang::Go.is_js_family());
        assert!(!SourceLang::C.is_js_family());
        assert!(!SourceLang::Python.is_js_family());
    }

    #[test]
    fn interpretable_predicate() {
        // JS/TS and Python can run as source; Rust/Go/C must be precompiled.
        assert!(SourceLang::Js.is_interpretable());
        assert!(SourceLang::Ts.is_interpretable());
        assert!(SourceLang::Python.is_interpretable());
        assert!(!SourceLang::Rust.is_interpretable());
        assert!(!SourceLang::Go.is_interpretable());
        assert!(!SourceLang::C.is_interpretable());
    }

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
}
