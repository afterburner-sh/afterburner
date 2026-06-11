// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 vertexclique

//! Native-addon rejection.
//!
//! Afterburner runs JavaScript in a Wasmtime sandbox — it can NEVER load a
//! native dynamic library, an N-API / C-ABI addon, or any other host-arch
//! machine code. A package that vendors such a thing (directly or through an
//! npm dependency) is not just unrunnable, it is a security red flag: native
//! addons exist precisely to escape the JS sandbox into the host process.
//!
//! So the rule is fail-closed at the earliest gate (pack AND vendor): if any
//! file in the archive's source tree looks like a native artifact, refuse —
//! naming the file — rather than ship a package that will explode (or worse,
//! try to dlopen something) at runtime.
//!
//! What we reject (by path/extension, before any bytes are trusted):
//! * `*.node` — N-API / nan native addons (the canonical case).
//! * platform dynamic libraries: `*.dll`, `*.dylib`, `*.so`, `*.so.N`.
//! * native build descriptors: `binding.gyp`, `*.gyp`, `*.gypi` — their mere
//!   presence means the package expects a C/C++ toolchain at install time.
//! * static objects / archives that only matter to a native linker:
//!   `*.o`, `*.a`, `*.lib`, `*.wasm` is ALLOWED (it's sandbox-native).
//!
//! This is path-based on purpose: it is cheap, total, and cannot be defeated
//! by obfuscated contents the way a heuristic byte-scan could.

use crate::{AfbError, Result};

/// Suffixes that mark a host-native artifact. Lowercased comparison.
const NATIVE_SUFFIXES: &[&str] = &[
    ".node",  // N-API / nan addon
    ".dll",   // Windows dynamic lib
    ".dylib", // macOS dynamic lib
    ".so",    // ELF shared object
    ".a",     // static archive
    ".lib",   // Windows import/static lib
    ".o",     // object file
    ".obj",   // Windows object file
    ".gyp",   // node-gyp build descriptor
    ".gypi",  // node-gyp include
];

/// Exact basenames that mark a native build (regardless of extension).
const NATIVE_BASENAMES: &[&str] = &["binding.gyp"];

/// Return the offending path if `path` names a host-native artifact.
///
/// Handles versioned ELF names (`libfoo.so.1.2`) by checking for a `.so.`
/// segment, not just a `.so` suffix.
pub fn native_artifact_reason(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);

    if NATIVE_BASENAMES.contains(&base) {
        return Some(format!("native build descriptor '{path}'"));
    }
    if lower.contains(".so.") {
        return Some(format!("native shared object '{path}'"));
    }
    for suf in NATIVE_SUFFIXES {
        if lower.ends_with(suf) {
            return Some(format!("native artifact '{path}' ({suf})"));
        }
    }
    None
}

/// Fail-closed scan over a package's source file paths. Errors on the FIRST
/// native artifact found (deterministic: callers pass a sorted map).
pub fn reject_native<'a, I>(paths: I) -> Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    for p in paths {
        if let Some(reason) = native_artifact_reason(p) {
            return Err(AfbError::NativeAddon {
                detail: format!(
                    "{reason}: Afterburner runs JavaScript in a WASM sandbox and \
                     cannot load native/C-ABI/N-API code. Remove the dependency or \
                     use a pure-JS/WASM alternative."
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_node_addon() {
        assert!(native_artifact_reason("source/node_modules/bcrypt/lib/binding/bcrypt_lib.node").is_some());
    }

    #[test]
    fn flags_versioned_so() {
        assert!(native_artifact_reason("source/node_modules/x/libssl.so.3").is_some());
        assert!(native_artifact_reason("source/node_modules/x/build/Release/x.so").is_some());
    }

    #[test]
    fn flags_binding_gyp_and_dylib_and_dll() {
        assert!(native_artifact_reason("source/node_modules/y/binding.gyp").is_some());
        assert!(native_artifact_reason("source/node_modules/y/a.dylib").is_some());
        assert!(native_artifact_reason("source/node_modules/y/a.DLL").is_some());
    }

    #[test]
    fn allows_pure_js_json_wasm_and_lookalikes() {
        for p in [
            "source/main.js",
            "source/main.ts",
            "source/pkg/index.mjs",
            "source/data.json",
            "source/node_modules/foo/foo.wasm", // sandbox-native, allowed
            "source/node_modules/foo/notanode.js",
            "source/node_modules/foo/readme.md",
            "source/node_modules/foo/nodes.js", // not *.node
        ] {
            assert!(native_artifact_reason(p).is_none(), "{p} must be allowed");
        }
    }

    #[test]
    fn reject_native_errors_on_first_hit() {
        let paths = vec![
            "source/main.js",
            "source/node_modules/bcrypt/bcrypt.node",
            "source/other.js",
        ];
        let err = reject_native(paths).unwrap_err();
        assert!(matches!(err, AfbError::NativeAddon { .. }));
    }

    #[test]
    fn reject_native_passes_pure_tree() {
        let paths = vec!["source/main.js", "source/node_modules/lodash/index.js"];
        assert!(reject_native(paths).is_ok());
    }
}
