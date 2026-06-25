// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 vertexclique

//! Native-addon rejection.
//!
//! Afterburner runs JavaScript in a Wasmtime sandbox - it can NEVER load a
//! native dynamic library, an N-API / C-ABI addon, or any other host-arch
//! machine code. A package that vendors such a thing (directly or through an
//! npm dependency) is not just unrunnable, it is a security red flag: native
//! addons exist precisely to escape the JS sandbox into the host process.
//!
//! So the rule is fail-closed at the earliest gate (pack AND vendor): if any
//! file in the archive's source tree looks like a native artifact, refuse -
//! naming the file - rather than ship a package that will explode (or worse,
//! try to dlopen something) at runtime.
//!
//! What we reject (by path/extension, before any bytes are trusted):
//! * `*.node` - N-API / nan native addons (the canonical case).
//! * platform dynamic libraries: `*.dll`, `*.dylib`, `*.so`, `*.so.N`.
//! * native build descriptors: `binding.gyp`, `*.gyp`, `*.gypi` - their mere
//!   presence means the package expects a C/C++ toolchain at install time.
//! * static objects / archives that only matter to a native linker:
//!   `*.o`, `*.a`, `*.lib`, `*.wasm` is ALLOWED (it's sandbox-native).
//!
//! **Sandbox-ABI exception** (`vendor/pip/` and `vendor/gem/` members only):
//! A `.so` whose filename carries the emscripten soabi tag
//! (`cpython-<xy>-wasm32-emscripten`) is compiled for the bundled Python
//! runtime's sandbox ABI, not for the host. It is loaded only inside the
//! sandbox (via the Python runtime's own `dlopen` equivalent), never by the
//! host OS linker. Such files are allowed. Every other `.so` in a vendor tree
//! (manylinux, macOS, Windows `.pyd`/`.dll`, a native gem extension) is
//! refused with an actionable error naming the file and the fix.
//!
//! This is path-based on purpose: it is cheap, total, and cannot be defeated
//! by obfuscated contents the way a heuristic byte-scan could.

use crate::{AfbError, Result};

/// Suffixes that mark a host-native artifact. Lowercased comparison.
const NATIVE_SUFFIXES: &[&str] = &[
    ".node",   // N-API / nan addon
    ".dll",    // Windows dynamic lib
    ".dylib",  // macOS dynamic lib
    ".so",     // ELF shared object
    ".a",      // static archive
    ".lib",    // Windows import/static lib
    ".o",      // object file
    ".obj",    // Windows object file
    ".gyp",    // node-gyp build descriptor
    ".gypi",   // node-gyp include
    ".pyd",    // Windows Python extension (native)
    ".bundle", // macOS Ruby/gem native extension
];

/// Exact basenames that mark a native build (regardless of extension).
const NATIVE_BASENAMES: &[&str] = &["binding.gyp"];

/// Soabi substring that identifies a `.so` compiled for the bundled Python
/// runtime's sandbox ABI (emscripten). Only this specific ABI is permitted
/// inside `vendor/pip/` and `vendor/gem/` members.
const SANDBOX_SOABI: &str = "wasm32-emscripten";

/// Return `true` if the archive path is under `vendor/pip/` or `vendor/gem/`
/// and the filename contains the sandbox soabi tag, meaning the `.so` targets
/// the bundled Python runtime's sandbox ABI rather than the host.
fn is_sandbox_abi_so(path: &str) -> bool {
    let is_vendor_pip_or_gem = path.starts_with("vendor/pip/") || path.starts_with("vendor/gem/");
    if !is_vendor_pip_or_gem {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    // The base must end in `.so` (or a versioned `.so.N` form handled below)
    // AND contain the sandbox soabi tag.
    (base.ends_with(".so") || base.contains(".so.")) && base.contains(SANDBOX_SOABI)
}

/// Return the offending path if `path` names a host-native artifact.
///
/// Handles versioned ELF names (`libfoo.so.1.2`) by checking for a `.so.`
/// segment, not just a `.so` suffix.
///
/// Applies the sandbox-ABI exception: a `.so` under `vendor/pip/` or
/// `vendor/gem/` carrying the emscripten soabi tag is permitted (it is
/// sandbox-native, not host-native).
pub fn native_artifact_reason(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);

    if NATIVE_BASENAMES.contains(&base) {
        return Some(format!("native build descriptor '{path}'"));
    }
    if lower.contains(".so.") {
        // Sandbox-ABI exception: emscripten soabi versioned .so under vendor/.
        if is_sandbox_abi_so(path) {
            return None;
        }
        return Some(format!("native shared object '{path}'"));
    }
    for suf in NATIVE_SUFFIXES {
        if lower.ends_with(suf) {
            // Sandbox-ABI exception: emscripten soabi .so under vendor/.
            if *suf == ".so" && is_sandbox_abi_so(path) {
                continue;
            }
            return Some(format!("native artifact '{path}' ({suf})"));
        }
    }
    None
}

/// Fail-closed scan over a package's file paths. Errors on the FIRST
/// native artifact found (deterministic: callers pass a sorted map).
///
/// The sandbox-ABI exception (emscripten `.so` under `vendor/pip/` or
/// `vendor/gem/`) is enforced here via [`native_artifact_reason`].
pub fn reject_native<'a, I>(paths: I) -> Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    for p in paths {
        if let Some(reason) = native_artifact_reason(p) {
            return Err(AfbError::NativeAddon {
                detail: format!(
                    "{reason}: this sandbox cannot load host-native or C-ABI code. \
                     Use a pure-Python/pure-Ruby package, or a wheel built for the \
                     Python runtime's sandbox ABI (cpython-<xy>-wasm32-emscripten). \
                     Host-native artifacts (manylinux, macOS, Windows, native gem \
                     extensions) are never vendored."
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
        assert!(
            native_artifact_reason("source/node_modules/bcrypt/lib/binding/bcrypt_lib.node")
                .is_some()
        );
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

    // ---- sandbox-ABI exception (vendor/pip/ and vendor/gem/) ----------------

    #[test]
    fn sandbox_abi_so_allowed_in_vendor_pip() {
        // A wheel .so with the emscripten soabi tag is sandbox-native: allowed.
        let emscripten_so = "vendor/pip/numpy-1.26.4-cpython-312-wasm32-emscripten.so";
        assert!(
            native_artifact_reason(emscripten_so).is_none(),
            "emscripten soabi .so in vendor/pip/ must be allowed"
        );
    }

    #[test]
    fn sandbox_abi_so_allowed_in_vendor_gem() {
        // Same exception applies to vendor/gem/ members.
        let emscripten_so = "vendor/gem/some_ext-1.0-cpython-311-wasm32-emscripten.so";
        assert!(
            native_artifact_reason(emscripten_so).is_none(),
            "emscripten soabi .so in vendor/gem/ must be allowed"
        );
    }

    #[test]
    fn manylinux_so_refused_in_vendor_pip() {
        // A manylinux wheel .so is host-native: refused even under vendor/pip/.
        let manylinux_so = "vendor/pip/numpy-1.26.4-cp312-cp312-manylinux_2_17_x86_64.so";
        assert!(
            native_artifact_reason(manylinux_so).is_some(),
            "manylinux .so in vendor/pip/ must be refused"
        );
    }

    #[test]
    fn pyd_refused_in_vendor_pip() {
        // A Windows Python extension (.pyd) is always host-native: refused.
        let pyd = "vendor/pip/numpy/core/_multiarray_umath.pyd";
        assert!(
            native_artifact_reason(pyd).is_some(),
            ".pyd in vendor/pip/ must be refused"
        );
    }

    #[test]
    fn dylib_refused_in_vendor_pip() {
        // A macOS .dylib inside a vendored wheel is host-native: refused.
        let dylib = "vendor/pip/somelib/lib/libfoo.dylib";
        assert!(
            native_artifact_reason(dylib).is_some(),
            ".dylib in vendor/pip/ must be refused"
        );
    }

    #[test]
    fn native_gem_bundle_refused_in_vendor_gem() {
        // A macOS native gem extension (.bundle) is host-native: refused.
        let bundle = "vendor/gem/nokogiri-1.16.0/lib/nokogiri/nokogiri.bundle";
        assert!(
            native_artifact_reason(bundle).is_some(),
            ".bundle in vendor/gem/ must be refused"
        );
    }

    #[test]
    fn host_so_outside_vendor_still_refused() {
        // A .so outside vendor/ is always refused (no sandbox-ABI exception).
        let so = "source/node_modules/native/build/Release/native.so";
        assert!(
            native_artifact_reason(so).is_some(),
            "host .so outside vendor/ must always be refused"
        );
    }

    #[test]
    fn reject_native_passes_vendor_tree_with_sandbox_abi_so() {
        // A vendor tree that contains only pure wheels and a sandbox-ABI .so
        // passes the gate end to end.
        let paths = vec![
            "vendor/pip/requests-2.31.0-py3-none-any.whl",
            "vendor/pip/numpy-1.26.4-cpython-312-wasm32-emscripten.so",
        ];
        assert!(reject_native(paths).is_ok());
    }

    #[test]
    fn reject_native_refuses_manylinux_in_vendor_tree() {
        let paths = vec![
            "vendor/pip/requests-2.31.0-py3-none-any.whl",
            "vendor/pip/numpy-1.26.4-cp312-cp312-manylinux_2_17_x86_64.so",
        ];
        let err = reject_native(paths).unwrap_err();
        assert!(
            matches!(err, AfbError::NativeAddon { .. }),
            "manylinux .so must trip NativeAddon"
        );
    }
}
