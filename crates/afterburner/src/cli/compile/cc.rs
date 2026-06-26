// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! C and C++ native-to-WASM compile backend.
//!
//! Compiles a multi-file C or C++ burn package (all of `source/**`) into a
//! single `wasm32-wasip1` WASI **command** module - a real `main` linked
//! against wasi-libc, so it runs through `EmbedderVm::run_command` exactly
//! like the Rust and Go backends.
//!
//! Invariants:
//! - A wasi-sdk supplies the `clang`/`clang++` that ship the `wasm32`
//!   compiler-rt builtins and the wasi-libc sysroot (a bare system clang is not
//!   enough). It is resolved BUNDLE-FIRST: the toolchain assembled at build time
//!   by `afterburner-wasi` (`wasi_sdk_bundle::resolve`), so `burn run x.c` works
//!   with zero config; `WASI_SDK_PATH` and the standard prefixes are an explicit
//!   override. When none resolves, [`compile_c`]/[`compile_cpp`] return an honest
//!   internal-free "C/C++ compilation is not available" error, never a fake.
//! - C++ exceptions: clang emits LEGACY wasm EH but the embedder runs the NEW
//!   (exnref) proposal, so an EH-enabled C++ module is post-translated to exnref
//!   with `wasm-opt` (as the bundled Python runtime is). With `wasm-opt` present
//!   real try/catch/throw works; without it C++ compiles `-fno-exceptions`
//!   (exception-free code, including `<iostream>`, still runs).
//! - A `Makefile`/`CMakeLists.txt` at the package root, when present, drives
//!   the build (it inherits the toolchain via exported `CC`/`CXX`/`*FLAGS`).
//! - A package (a `source/` tree) compiles every source under it in one
//!   invocation; a bare single file (no `source/` dir) compiles only itself.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// A located wasi-sdk: the C/C++ driver to invoke and the sysroot to pass.
///
/// `clang` is the wasi-sdk's bundled `clang` (which ships the
/// `wasm32-wasi` compiler-rt builtins), `clangxx` its `clang++`, and
/// `sysroot` the wasi-libc sysroot. A system `clang` is only usable when it
/// ALSO has the `wasm32` builtins installed, which most distro packages do
/// not - so we prefer the SDK's own driver.
#[derive(Debug, Clone)]
struct WasiSdk {
    clang: PathBuf,
    clangxx: PathBuf,
    sysroot: PathBuf,
}

/// Discover a wasi-sdk for compiling C/C++ to a `wasm32-wasip1` WASI command
/// module. Returns `None` when none is found (the caller then emits an honest
/// "not available" error - never a fake success).
///
/// Search order (first hit wins):
/// 0. The toolchain bundled with this build (assembled by `afterburner-wasi`'s
///    build script and resolved via `wasi_sdk_bundle::resolve`). This is the
///    zero-config path: `burn run x.c` works with no env vars.
/// 1. `WASI_SDK_PATH` env var (the canonical wasi-sdk convention): expects
///    `$WASI_SDK_PATH/bin/clang` + `$WASI_SDK_PATH/share/wasi-sysroot`. This is
///    an explicit OVERRIDE of the bundled toolchain.
/// 2. `WASI_SYSROOT` env var alongside `CC`/`CXX` (or system `clang`), for
///    setups where the sysroot is split from the driver.
/// 3. Standard install prefixes: `/opt/wasi-sdk`, `/usr/local/wasi-sdk`,
///    `/usr/lib/wasi-sdk`, `~/wasi-sdk`, `~/.wasi-sdk`.
fn find_wasi_sdk() -> Option<WasiSdk> {
    // 0. The bundled toolchain assembled at build time: the zero-config path.
    //    An explicit WASI_SDK_PATH below overrides it (mirrors how
    //    BURN_PYTHON_RUNTIME / BURN_RUBY_RUNTIME override their bundles).
    if std::env::var_os("WASI_SDK_PATH").is_none()
        && let Some(b) = afterburner_wasi::wasi_sdk_bundle::resolve()
    {
        return Some(WasiSdk {
            clang: b.clang,
            clangxx: b.clangxx,
            sysroot: b.sysroot,
        });
    }

    // 1. WASI_SDK_PATH (the canonical layout).
    if let Ok(root) = std::env::var("WASI_SDK_PATH")
        && let Some(sdk) = wasi_sdk_from_root(Path::new(&root))
    {
        return Some(sdk);
    }

    // 2. WASI_SYSROOT + an explicit/inferred driver. This supports a system
    //    clang that happens to carry the wasm32 builtins.
    if let Ok(sysroot) = std::env::var("WASI_SYSROOT") {
        let sysroot = PathBuf::from(sysroot);
        if sysroot.is_dir() {
            let clang = std::env::var("CC").map(PathBuf::from).unwrap_or_else(|_| {
                std::env::var("CLANG")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("clang"))
            });
            let clangxx = std::env::var("CXX")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("clang++"));
            return Some(WasiSdk {
                clang,
                clangxx,
                sysroot,
            });
        }
    }

    // 3. Standard install prefixes.
    let mut roots: Vec<PathBuf> = vec![
        PathBuf::from("/opt/wasi-sdk"),
        PathBuf::from("/usr/local/wasi-sdk"),
        PathBuf::from("/usr/lib/wasi-sdk"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(Path::new(&home).join("wasi-sdk"));
        roots.push(Path::new(&home).join(".wasi-sdk"));
    }
    roots.into_iter().find_map(|r| wasi_sdk_from_root(&r))
}

/// Build a [`WasiSdk`] from a wasi-sdk install root, verifying that both the
/// bundled `clang` and the `wasi-sysroot` exist. Returns `None` otherwise.
fn wasi_sdk_from_root(root: &Path) -> Option<WasiSdk> {
    let clang = root.join("bin/clang");
    let clangxx = root.join("bin/clang++");
    // wasi-sdk >= 20 ships the sysroot here; older layouts used `wasi-sysroot`.
    let sysroot = ["share/wasi-sysroot", "wasi-sysroot"]
        .iter()
        .map(|s| root.join(s))
        .find(|p| p.is_dir())?;
    if clang.is_file() {
        Some(WasiSdk {
            clang,
            clangxx,
            sysroot,
        })
    } else {
        None
    }
}

/// The actionable error when no C/C++ toolchain can be located. The bundled
/// toolchain normally satisfies this, so it rarely fires; when it does, the
/// message stays internal-free (it names no toolchain, no env var, no URL). The
/// substring "C/C++ compilation is not available" is matched by the e2e tests
/// to skip honestly (never silently pass) when compilation cannot run.
fn wasi_sdk_missing_error(lang: &str) -> anyhow::Error {
    anyhow::anyhow!("C/C++ compilation is not available in this build of burn ({lang})")
}

/// Collect all translation units under `pkg_dir/source/` (recursively) whose
/// extension is in `exts`, returned sorted for deterministic command lines.
///
/// Headers are NOT returned (they are pulled in by `#include`); only the
/// listed source extensions are compiled. When `pkg_dir/source/` does not
/// exist the search falls back to `pkg_dir` itself (used by tests that pass a
/// bare directory); the package compile path only calls this once it has
/// confirmed a `source/` tree exists.
fn collect_sources(pkg_dir: &Path, exts: &[&str]) -> Result<Vec<PathBuf>> {
    let root = {
        let s = pkg_dir.join("source");
        if s.is_dir() { s } else { pkg_dir.to_path_buf() }
    };
    let mut out = Vec::new();
    collect_sources_into(&root, exts, &mut out)?;
    out.sort();
    Ok(out)
}

/// Recursive worker for [`collect_sources`].
fn collect_sources_into(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("reading sources in {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_sources_into(&path, exts, out)?;
        } else if ft.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase())
                .is_some_and(|e| exts.contains(&e.as_str()))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// If a `Makefile`/`makefile`/`GNUmakefile` or `CMakeLists.txt` lives at the
/// package root, build via it and return the single produced `.wasm`.
///
/// The build system is responsible for targeting `wasm32-wasip1` (it can read
/// `WASI_SDK_PATH`, `CC`/`CXX`, `CFLAGS` which we export). Returns:
/// - `Ok(Some(bytes))` when a recognized build file ran and produced exactly
///   one `.wasm` under `pkg_dir` (searched recursively, newest wins on ties),
/// - `Ok(None)` when no build file is present (caller does a direct compile),
/// - `Err(_)` when a build file ran but failed or produced no `.wasm`.
fn try_build_system(
    pkg_dir: &Path,
    sdk: &WasiSdk,
    is_cpp: bool,
    cpp_exceptions: bool,
) -> Result<Option<Vec<u8>>> {
    let has_make = ["Makefile", "makefile", "GNUmakefile"]
        .iter()
        .any(|f| pkg_dir.join(f).is_file());
    let has_cmake = pkg_dir.join("CMakeLists.txt").is_file();
    if !has_make && !has_cmake {
        return Ok(None);
    }

    // Export the toolchain so the build file can pick it up.
    let cc = sdk.clang.to_string_lossy().into_owned();
    let cxx = sdk.clangxx.to_string_lossy().into_owned();
    let sysroot = sdk.sysroot.to_string_lossy().into_owned();
    let target_flags = format!("--target=wasm32-wasip1 --sysroot={sysroot}");
    // C++ selects the exceptions-enabled or no-exceptions libc++ multilib (see
    // the direct-compile path), gated on whether the exnref translator is
    // available. `-lunwind` in LDFLAGS resolves the unwinder the EH variant
    // needs and is a harmless no-op for a C link (an unreferenced archive pulls
    // nothing).
    let (cxx_flags, ld_flags) = if cpp_exceptions {
        (
            format!("{target_flags} -fwasm-exceptions"),
            format!("{target_flags} -lunwind"),
        )
    } else {
        (
            format!("{target_flags} -fno-exceptions"),
            target_flags.clone(),
        )
    };

    let run_make = |program: &str| -> Result<std::process::ExitStatus> {
        std::process::Command::new(program)
            .current_dir(pkg_dir)
            .env("WASI_SDK_PATH", sdk_root_of(sdk))
            .env("WASI_SYSROOT", &sysroot)
            .env("CC", &cc)
            .env("CXX", &cxx)
            .env("CFLAGS", &target_flags)
            .env("CXXFLAGS", &cxx_flags)
            .env("LDFLAGS", &ld_flags)
            .status()
            .with_context(|| format!("spawning `{program}`"))
    };

    if has_make {
        let status = run_make("make")?;
        if !status.success() {
            anyhow::bail!(
                "`make` exited with code {} building {}",
                status.code().unwrap_or(-1),
                pkg_dir.display()
            );
        }
    } else {
        // CMake: configure into build/ then build.
        let build_dir = pkg_dir.join("build");
        std::fs::create_dir_all(&build_dir).ok();
        let compiler_flag = if is_cpp {
            format!("-DCMAKE_CXX_COMPILER={cxx}")
        } else {
            format!("-DCMAKE_C_COMPILER={cc}")
        };
        let configure = std::process::Command::new("cmake")
            .current_dir(pkg_dir)
            .args([
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_SYSTEM_NAME=WASI",
                "-DCMAKE_SYSTEM_VERSION=1",
                "-DCMAKE_SYSTEM_PROCESSOR=wasm32",
            ])
            .arg(format!("-DCMAKE_SYSROOT={sysroot}"))
            .arg(format!("-DCMAKE_C_FLAGS={target_flags}"))
            .arg(format!("-DCMAKE_CXX_FLAGS={cxx_flags}"))
            .arg(format!("-DCMAKE_EXE_LINKER_FLAGS={ld_flags}"))
            .arg(&compiler_flag)
            .status()
            .with_context(|| "spawning `cmake` (configure)")?;
        if !configure.success() {
            anyhow::bail!(
                "`cmake` configure exited with code {}",
                configure.code().unwrap_or(-1)
            );
        }
        let build = std::process::Command::new("cmake")
            .current_dir(pkg_dir)
            .args(["--build", "build"])
            .status()
            .with_context(|| "spawning `cmake` (build)")?;
        if !build.success() {
            anyhow::bail!(
                "`cmake --build` exited with code {}",
                build.code().unwrap_or(-1)
            );
        }
    }

    // Locate the produced .wasm (recursively; newest wins).
    let mut wasms = Vec::new();
    collect_sources_into(pkg_dir, &["wasm"], &mut wasms).ok();
    let newest = wasms
        .into_iter()
        .filter_map(|p| {
            let m = std::fs::metadata(&p).ok()?.modified().ok()?;
            Some((m, p))
        })
        .max_by_key(|(m, _)| *m)
        .map(|(_, p)| p);

    match newest {
        Some(p) => {
            Ok(Some(std::fs::read(&p).with_context(|| {
                format!("reading built wasm {}", p.display())
            })?))
        }
        None => anyhow::bail!(
            "the build system in {} ran but produced no .wasm output",
            pkg_dir.display()
        ),
    }
}

/// Recover the wasi-sdk install root from a located [`WasiSdk`] (the parent of
/// `bin/`), for exporting `WASI_SDK_PATH` to a build system.
fn sdk_root_of(sdk: &WasiSdk) -> PathBuf {
    sdk.clang
        .parent() // bin/
        .and_then(|p| p.parent()) // root/
        .map(Path::to_path_buf)
        .unwrap_or_else(|| sdk.clang.clone())
}

/// Locate `wasm-opt` for the C++ exnref translation: PATH first, then the emsdk
/// fallback Binaryen ships at. Returns `None` when neither is present (the C++
/// compile then drops to `-fno-exceptions`). Mirrors the build-side locator in
/// `afterburner-wasi`'s `build.rs` (kept in step; the two run in different
/// crates so a shared fn would couple a build dep to the runtime).
fn find_wasm_opt() -> Option<PathBuf> {
    if std::process::Command::new("wasm-opt")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return Some(PathBuf::from("wasm-opt"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let p = Path::new(&home).join("emsdk/upstream/bin/wasm-opt");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Translate a legacy-EH wasm module to the exnref/try_table proposal in place,
/// the form the embedder's wasmtime config accepts. Uses the same flag set as
/// the bundled Python runtime's translation (see `afterburner-wasi`'s
/// `bundle_fetch.rs`). The output replaces `wasm` via a sibling temp + rename.
fn translate_to_exnref(wasm_opt: &Path, wasm: &Path) -> Result<()> {
    const FLAGS: &[&str] = &[
        "--translate-to-exnref",
        "--enable-exception-handling",
        "--enable-reference-types",
        "--enable-bulk-memory",
        "--enable-simd",
        "--enable-sign-ext",
        "--enable-nontrapping-float-to-int",
        "--enable-mutable-globals",
        "--enable-multivalue",
    ];
    let out = wasm.with_extension("exnref.wasm");
    let status = std::process::Command::new(wasm_opt)
        .args(FLAGS)
        .arg(wasm)
        .arg("-o")
        .arg(&out)
        .status()
        .with_context(|| {
            format!("spawning wasm-opt {wasm_opt:?} for the C++ exnref translation")
        })?;
    if !status.success() {
        let _ = std::fs::remove_file(&out);
        anyhow::bail!(
            "exnref translation (wasm-opt) exited with code {}",
            status.code().unwrap_or(-1)
        );
    }
    std::fs::rename(&out, wasm)
        .with_context(|| format!("replacing {} with its exnref form", wasm.display()))?;
    Ok(())
}

/// Compile ALL C sources under `source/` into a `wasm32-wasip1` WASI **command**
/// module (a real `main`, linked against wasi-libc), so the result runs through
/// `EmbedderVm::run_command`.
///
/// Resolution order:
/// 1. A `Makefile`/`CMakeLists.txt`, when present, drives the build.
/// 2. Otherwise every `source/**/*.c` is compiled and linked in one
///    `clang --target=wasm32-wasip1 --sysroot=<wasi-sdk>` invocation, so
///    cross-file calls and shared headers resolve naturally.
///
/// Requires a wasi-sdk (`WASI_SDK_PATH` or a standard install). When none is
/// found, an honest "wasi-sdk not found" error is returned - never a fake
/// success. (`emcc`'s `STANDALONE_WASM` is a non-WASI ABI that does not run
/// as a WASI command, so it is not used here.)
pub(super) fn compile_c(pkg_dir: &Path, entry: &str) -> Result<Vec<u8>> {
    compile_c_family(pkg_dir, entry, false)
}

/// Compile ALL C++ sources under `source/` into a `wasm32-wasip1` WASI
/// **command** module via the wasi-sdk's `clang++`. Same resolution order and
/// honesty guarantees as [`compile_c`]; `emcc` is the documented fallback for
/// users who have it (Emscripten), but is not invoked when wasi-sdk is present.
pub(super) fn compile_cpp(pkg_dir: &Path, entry: &str) -> Result<Vec<u8>> {
    compile_c_family(pkg_dir, entry, true)
}

/// Shared C/C++ multi-file -> WASI-command compile. `is_cpp` selects the
/// `clang++` driver and the `.cpp/.cxx/.cc` source extensions.
fn compile_c_family(pkg_dir: &Path, entry: &str, is_cpp: bool) -> Result<Vec<u8>> {
    let lang = if is_cpp { "C++" } else { "C" };
    let entry_path = pkg_dir.join(entry);
    if !entry_path.exists() {
        anyhow::bail!(
            "{lang} entry file {:?} does not exist in {}",
            entry,
            pkg_dir.display()
        );
    }

    let Some(sdk) = find_wasi_sdk() else {
        // Honest: no wasi-sdk, so a runnable WASI command cannot be produced.
        return Err(wasi_sdk_missing_error(lang));
    };

    // C++ exception strategy (shared by the build-system and direct paths). The
    // embedder runs the NEW (exnref/try_table) EH proposal; clang emits the
    // LEGACY EH, so an EH-enabled C++ module is post-translated to exnref with
    // `wasm-opt` (the same step the bundled Python runtime uses). With wasm-opt
    // present we compile real try/catch/throw and translate; without it we
    // compile `-fno-exceptions` so exception-free C++ (incl. `<iostream>`) still
    // works and exception-using C++ fails loudly at compile.
    let wasm_opt = if is_cpp { find_wasm_opt() } else { None };
    let cpp_exceptions = is_cpp && wasm_opt.is_some();

    // Prefer a project build file (Makefile / CMakeLists.txt) when present.
    if let Some(mut bytes) = try_build_system(pkg_dir, &sdk, is_cpp, cpp_exceptions)? {
        // A build-system C++ artifact is legacy-EH too; translate it to exnref.
        if let Some(ref wasm_opt) = wasm_opt {
            let tmp = std::env::temp_dir().join(format!("burn-cpp-bs-{}.wasm", std::process::id()));
            std::fs::write(&tmp, &bytes)
                .with_context(|| format!("staging build-system wasm {}", tmp.display()))?;
            let translated = translate_to_exnref(wasm_opt, &tmp).and_then(|()| {
                std::fs::read(&tmp).with_context(|| format!("reading {}", tmp.display()))
            });
            let _ = std::fs::remove_file(&tmp);
            bytes = translated?;
        }
        return Ok(bytes);
    }

    // Source set:
    // - A PACKAGE (has a `source/` dir) compiles ALL `source/**/*.{c,cpp,...}`
    //   in one invocation so cross-file calls and shared headers resolve.
    // - A bare single file (no `source/` dir, e.g. `burn run foo.c`) compiles
    //   exactly the entry, never sweeping sibling files in its directory.
    let exts: &[&str] = if is_cpp {
        &["cpp", "cxx", "cc"]
    } else {
        &["c"]
    };
    let sources = if pkg_dir.join("source").is_dir() {
        let found = collect_sources(pkg_dir, exts)?;
        if found.is_empty() {
            anyhow::bail!(
                "no {lang} sources (*.{}) found under {}/source",
                exts.join(", *."),
                pkg_dir.display()
            );
        }
        found
    } else {
        vec![entry_path.clone()]
    };

    let driver = if is_cpp { &sdk.clangxx } else { &sdk.clang };
    let wasm_out = std::env::temp_dir().join(format!(
        "burn-{}-{}.wasm",
        if is_cpp { "cpp" } else { "c" },
        std::process::id()
    ));

    let sysroot_arg = format!("--sysroot={}", sdk.sysroot.display());
    let mut cmd = std::process::Command::new(driver);
    cmd.arg("--target=wasm32-wasip1")
        .arg(&sysroot_arg)
        .arg("-O2");
    if is_cpp {
        // wasi-sdk ships libc++ as multilib variants; the default one leaves
        // `<iostream>`'s exception symbols (`__cxa_throw`, ...) undefined at
        // link. `-fwasm-exceptions` selects the exceptions-enabled libc++ and
        // (with `-lunwind` after the objects) links real try/catch/throw;
        // `-fno-exceptions` selects the no-exceptions multilib that still links
        // `<iostream>`. Picked by whether the exnref translator is available.
        cmd.arg(if cpp_exceptions {
            "-fwasm-exceptions"
        } else {
            "-fno-exceptions"
        });
    }
    // The package root is an include path so `#include "..."` from a nested
    // source resolves package-relative headers.
    cmd.arg("-I")
        .arg(pkg_dir)
        .arg("-I")
        .arg(pkg_dir.join("source"));
    for src in &sources {
        cmd.arg(src);
    }
    if cpp_exceptions {
        // After the objects so the linker pulls the unwind symbols they need.
        cmd.arg("-lunwind");
    }
    cmd.arg("-o").arg(&wasm_out).current_dir(pkg_dir);

    let status = cmd.status().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            wasi_sdk_missing_error(lang)
        } else {
            // No internal toolchain name or path in the user-facing text.
            anyhow::anyhow!("spawning the {lang} compiler: {e}")
        }
    })?;

    if !status.success() {
        let _ = std::fs::remove_file(&wasm_out);
        anyhow::bail!(
            "{lang} compile exited with code {} ({} source file{} from {})",
            status.code().unwrap_or(-1),
            sources.len(),
            if sources.len() == 1 { "" } else { "s" },
            pkg_dir.display()
        );
    }

    // Translate the legacy-EH C++ module to the exnref form the embedder runs.
    if let Some(ref wasm_opt) = wasm_opt {
        translate_to_exnref(wasm_opt, &wasm_out)?;
    }

    let bytes = std::fs::read(&wasm_out)
        .with_context(|| format!("reading {lang} WASM {}", wasm_out.display()))?;
    let _ = std::fs::remove_file(&wasm_out);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_sources_finds_all_c_recursively_excluding_headers() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source");
        std::fs::create_dir_all(src.join("util")).unwrap();
        std::fs::write(src.join("main.c"), b"int main(){return 0;}").unwrap();
        std::fs::write(src.join("util/helper.c"), b"int h(){return 1;}").unwrap();
        std::fs::write(src.join("util/helper.h"), b"int h(void);").unwrap();
        // A C++ file must NOT be picked up by a C-extension collection.
        std::fs::write(src.join("ignore.cpp"), b"int x(){return 2;}").unwrap();

        let found = collect_sources(dir.path(), &["c"]).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"main.c".to_string()), "got {names:?}");
        assert!(names.contains(&"helper.c".to_string()), "got {names:?}");
        assert!(!names.contains(&"helper.h".to_string()), "headers excluded");
        assert!(!names.contains(&"ignore.cpp".to_string()), "cpp excluded");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn collect_sources_finds_cpp_variants() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.cpp"), b"").unwrap();
        std::fs::write(src.join("b.cxx"), b"").unwrap();
        std::fs::write(src.join("c.cc"), b"").unwrap();
        let found = collect_sources(dir.path(), &["cpp", "cxx", "cc"]).unwrap();
        assert_eq!(found.len(), 3, "all three c++ extensions: {found:?}");
    }

    #[test]
    fn c_compile_missing_entry_errors_clearly() {
        // A non-existent entry must error before any toolchain probe.
        let dir = tempfile::tempdir().unwrap();
        let err = compile_c(dir.path(), "source/main.c").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist"),
            "missing entry must say so: {msg}"
        );
    }

    #[test]
    fn cpp_compile_missing_entry_errors_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let err = compile_cpp(dir.path(), "source/main.cpp").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist"),
            "missing entry must say so: {msg}"
        );
    }

    #[test]
    fn c_compile_without_toolchain_is_honest_not_silent() {
        // When no C/C++ toolchain is available, compiling a present C entry must
        // fail loudly with the internal-free "not available" error - never a
        // fake success. Only assert when the environment genuinely has no
        // toolchain, so the test is correct whether or not one is present.
        if find_wasi_sdk().is_some() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("main.c"), b"int main(void){return 0;}").unwrap();
        let err = compile_c(dir.path(), "source/main.c").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("C/C++ compilation is not available"),
            "must be an honest toolchain-missing error: {msg}"
        );
        assert!(
            !msg.contains("wasi-sdk") && !msg.contains("WASI_SDK_PATH"),
            "the user-facing error must not name the internal toolchain: {msg}"
        );
    }
}
