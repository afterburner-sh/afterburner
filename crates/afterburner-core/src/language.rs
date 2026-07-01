// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! The source language a run targets.
//!
//! Lives in core (not the facade) so every substrate contract - the
//! [`Session`](crate::session::Session) trait, the polyglot facade - names the
//! same one enum. The facade re-exports it as `afterburner::Language`.

/// A source language supported by the afterburner runtime.
///
/// Construct via [`Language::from_extension`] (from a file extension) or use
/// the variants directly.
///
/// `Rust`, `Go`, `C`, and `Cpp` have no source-interpreter path: they compile
/// to a `wasm32-wasip1` module that is registered and run through the
/// precompiled path, not interpreted from source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// JavaScript source, run via the JS/WASM engine.
    Js,
    /// TypeScript source, stripped to JS then run via the JS/WASM engine.
    Ts,
    /// Rust source. No source-interpreter; compile to a `wasm32-wasip1`
    /// module and register it.
    Rust,
    /// Go source. No source-interpreter; compile to a `wasm32-wasip1`
    /// module and register it.
    Go,
    /// C source. No source-interpreter; compile to a `wasm32-wasip1`
    /// module and register it.
    C,
    /// C++ source. No source-interpreter; compile to a `wasm32-wasip1`
    /// module and register it.
    Cpp,
    /// Python source, run via the bundled Pyodide/CPython-WASI runtime.
    Python,
    /// Ruby source, run via the bundled ruby.wasm/CRuby-WASI runtime.
    Ruby,
}

impl Language {
    /// Detect the language from a file extension (lowercased, without the dot).
    ///
    /// | Extension      | Language     |
    /// |----------------|--------------|
    /// | `rb`           | `Ruby`       |
    /// | `py`           | `Python`     |
    /// | `js`           | `Js`         |
    /// | `ts`           | `Ts`         |
    /// | `rs`           | `Rust`       |
    /// | `go`           | `Go`         |
    /// | `c`            | `C`          |
    /// | `cc`, `cpp`    | `Cpp`        |
    ///
    /// Returns `None` for any other extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.trim().to_ascii_lowercase().as_str() {
            "rb" => Some(Self::Ruby),
            "py" => Some(Self::Python),
            "js" => Some(Self::Js),
            "ts" => Some(Self::Ts),
            "rs" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "c" => Some(Self::C),
            "cc" | "cpp" => Some(Self::Cpp),
            _ => None,
        }
    }
}
