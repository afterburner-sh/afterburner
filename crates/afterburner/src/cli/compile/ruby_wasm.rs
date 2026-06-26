// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Ruby -> self-contained `wasm32-wasip1` compile path.
//!
//! `burn compile` (language = "ruby") produces a single `.afb` containing a
//! self-contained `wasm32-wasip1` WASM module: the stock `ruby.wasm` interpreter
//! with the package's `source/` tree and the Ruby stdlib pre-embedded in a virtual
//! filesystem via `wasi-vfs pack`. The produced module needs no host preopens to
//! run; `burn run` extracts and executes it via `EmbedderVm::run_command`.
//!
//! VFS layout inside the packed module:
//!   `/src/<entry_rel>`  - the package entry (e.g. `/src/source/main.rb`)
//!   `/src/...`          - all other `source/` files in the package
//!   `/usr/...`          - the Ruby stdlib tree (mounted at the compiled-in load path)
//!   `/gems/<gem>-<ver>/lib/...` - vendored gems (one dir per gem)
//!
//! Entry invocation: `ruby /src/<entry_rel>` (argv[0] = program name, argv[1] = script path).
//!
//! `wasi-vfs` is fetched and cached at `~/.burn/wasi-vfs-v0.6.3/wasi-vfs` on first use
//! (the same lazy-fetch + sha256-verify pattern as `javy` and `wasi-sdk`). Set
//! `WASI_VFS=<path>` to override the binary.

use afterburner_cloud::afterburner_afb::Afb;
use afterburner_cloud::gem_client::GemClient;
use afterburner_cloud::pkg::LocalPackage;
use afterburner_wasi::bundle;
use afterburner_wasi::bundle::ensure_wasi_vfs_bundle;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::bundle_wasm_into_afb;

/// Guest VFS root for the package's source files.
pub const GUEST_SRC_MOUNT: &str = "/src";
/// Guest VFS root for the Ruby stdlib tree (matches ruby.wasm's compiled-in load path).
const GUEST_USR_MOUNT: &str = "/usr";
/// Guest VFS root for vendored gems.
const GUEST_GEM_MOUNT: &str = "/gems";

/// Compile a Ruby package to a self-contained `wasm32-wasip1` WASM module via
/// `wasi-vfs pack`, then bundle the result into a `.afb`.
///
/// Steps:
/// 1. Ensure the `wasi-vfs` CLI is available (fetch + cache if not).
/// 2. Ensure the stock `ruby.wasm` + stdlib is available (same lazy fetch).
/// 3. Stage the package's `source/` files + optional vendored gems into a temp dir.
/// 4. Run `wasi-vfs pack <ruby.wasm> --dir <src>::/src --dir <usr>::/usr [-dir <gems>::/gems] -o <out.wasm>`.
/// 5. Bundle the resulting WASM into a `.afb` with `[runtime] target = "wasm32-wasip1"`.
///
/// The entry path in the VFS is `/src/<entry_rel>` where `entry_rel` is the
/// `[package] entry` value from `afb.toml` (e.g. `source/main.rb`).
pub fn compile_ruby_to_wasm(
    local: LocalPackage,
    _pkg_dir: &Path,
    out_path: &Path,
    wasm_only: bool,
) -> Result<()> {
    let coord = super::super::registry::coord_str(&local);
    let entry_rel = local.manifest.package.entry.clone();

    // Step 1: ensure wasi-vfs CLI.
    let vfs_bin = resolve_wasi_vfs_bin()?;

    // Step 2: ensure ruby.wasm + stdlib.
    let ruby_runtime = resolve_ruby_runtime_for_compile()?;

    // Step 3: resolve gems from [gem] section (if any), then stage.
    let gem_section: BTreeMap<String, String> = local.manifest.gem.clone();

    let gem_files: BTreeMap<String, Vec<u8>> = if gem_section.is_empty() {
        BTreeMap::new()
    } else {
        crate::cli::style::spin("resolving gems", || resolve_gems(&gem_section))
            .context("resolving [gem] dependencies")?
    };

    // Build a source .afb first (for the manifest + manifold, mirrors native path).
    let (source_bytes, _) = crate::cli::style::spin("packing source", || local.build())
        .context("building source .afb")?;
    let afb = Afb::from_bytes(&source_bytes).context("reparsing source .afb (this is a bug)")?;

    // Stage files + run wasi-vfs.
    let wasm_bytes = crate::cli::style::spin("compiling Ruby to wasm", || {
        pack_ruby_wasm(&vfs_bin, &ruby_runtime, &afb, &entry_rel, &gem_files)
    })?;

    // Bundle into .afb.
    bundle_wasm_into_afb(&afb, wasm_bytes, out_path, &coord, wasm_only)
}

/// The resolved ruby.wasm + stdlib paths for compile use.
struct RubyRuntimePaths {
    wasm_path: PathBuf,
    usr_dir: PathBuf,
}

/// Resolve the stock ruby.wasm + usr stdlib dir, fetching if needed.
fn resolve_ruby_runtime_for_compile() -> Result<RubyRuntimePaths> {
    // Honor BURN_RUBY_RUNTIME override (same as the run-time resolver).
    if let Ok(dir) = std::env::var("BURN_RUBY_RUNTIME") {
        let wasm_path = Path::new(&dir).join("ruby.wasm");
        anyhow::ensure!(
            wasm_path.exists(),
            "BURN_RUBY_RUNTIME={dir}: ruby.wasm not found at {}",
            wasm_path.display()
        );
        let usr_dir = std::env::var("BURN_RUBY_USR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Path::new(&dir).join("usr"));
        anyhow::ensure!(
            usr_dir.exists(),
            "ruby stdlib (usr) dir not found at {}; set BURN_RUBY_USR",
            usr_dir.display()
        );
        return Ok(RubyRuntimePaths { wasm_path, usr_dir });
    }

    // Lazy-fetch into ~/.burn (same bundle as burn run uses).
    let dir = bundle::ensure_ruby_bundle()
        .map_err(|e| anyhow::anyhow!("fetching ruby.wasm runtime: {e}"))?;
    let wasm_path = dir.join("ruby.wasm");
    let usr_dir = dir.join("usr");
    anyhow::ensure!(
        wasm_path.exists(),
        "ruby.wasm missing from bundle at {}",
        dir.display()
    );
    anyhow::ensure!(
        usr_dir.exists(),
        "usr stdlib missing from bundle at {}",
        dir.display()
    );
    Ok(RubyRuntimePaths { wasm_path, usr_dir })
}

/// Resolve the wasi-vfs CLI binary path. Honors `WASI_VFS` env override.
fn resolve_wasi_vfs_bin() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("WASI_VFS") {
        let p = PathBuf::from(&path);
        anyhow::ensure!(
            p.exists(),
            "WASI_VFS={path}: binary not found at {}",
            p.display()
        );
        return Ok(p);
    }

    // Check PATH first (developer convenience, mirrors javy).
    if let Ok(found) = which_on_path("wasi-vfs") {
        return Ok(found);
    }

    // Lazy-fetch into ~/.burn.
    let dir = ensure_wasi_vfs_bundle().map_err(|e| anyhow::anyhow!("fetching wasi-vfs: {e}"))?;
    let bin = dir.join(if cfg!(unix) {
        "wasi-vfs"
    } else {
        "wasi-vfs.exe"
    });
    anyhow::ensure!(
        bin.exists(),
        "wasi-vfs binary missing from bundle at {}",
        dir.display()
    );
    Ok(bin)
}

/// Find a binary on `PATH`. Returns `Err` when not found.
fn which_on_path(name: &str) -> Result<PathBuf> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
        #[cfg(windows)]
        {
            let with_exe = dir.join(format!("{name}.exe"));
            if with_exe.exists() {
                return Ok(with_exe);
            }
        }
    }
    anyhow::bail!("{name} not found on PATH")
}

/// Process-unique monotonic temp dir.
fn unique_tmp_dir(prefix: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()))
}

/// Stage the package source + gem files and run `wasi-vfs pack`.
///
/// Returns the raw bytes of the self-contained `wasm32-wasip1` WASM module.
fn pack_ruby_wasm(
    vfs_bin: &Path,
    rt: &RubyRuntimePaths,
    afb: &Afb,
    _entry_rel: &str,
    gem_files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>> {
    let work = unique_tmp_dir("burn-ruby-vfs");
    std::fs::create_dir_all(&work).context("creating ruby-vfs work dir")?;

    let src_dir = work.join("src");
    let gem_dir = work.join("gems");
    let out_wasm = work.join("out.wasm");

    // Stage source files: afb.source keys are "source/main.rb" etc.
    // They go into <work>/src/ so the guest sees /src/source/main.rb etc.
    for (rel, data) in &afb.source {
        let dest = src_dir.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir {}", parent.display()))?;
        }
        std::fs::write(&dest, data).with_context(|| format!("staging {rel}"))?;
    }

    // Stage gems: key format is "vendor/gem/<name>-<ver>/<rel>" (same as vendor map).
    // Stage under <work>/gems/<name>-<ver>/<rel>.
    let has_gems = !gem_files.is_empty();
    if has_gems {
        for (key, data) in gem_files {
            // Strip the "vendor/gem/" prefix if present (it may or may not be there).
            let rel = key.strip_prefix("vendor/gem/").unwrap_or(key);
            let dest = gem_dir.join(rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir gem {}", parent.display()))?;
            }
            std::fs::write(&dest, data).with_context(|| format!("staging gem file {key}"))?;
        }
    }

    // Build the wasi-vfs pack command.
    // --dir HOST_DIR::GUEST_DIR embeds the host directory at the given guest path.
    let mut cmd = std::process::Command::new(vfs_bin);
    cmd.args(["pack", rt.wasm_path.to_str().unwrap_or("")]);

    // Embed source at /src (ruby sees /src/source/main.rb).
    if src_dir.exists() {
        let src_arg = format!("{}::{GUEST_SRC_MOUNT}", src_dir.display());
        cmd.args(["--dir", &src_arg]);
    }

    // Embed the stdlib at /usr.
    let usr_arg = format!("{}::{GUEST_USR_MOUNT}", rt.usr_dir.display());
    cmd.args(["--dir", &usr_arg]);

    // Embed gems at /gems if any.
    if has_gems && gem_dir.exists() {
        let gem_arg = format!("{}::{GUEST_GEM_MOUNT}", gem_dir.display());
        cmd.args(["--dir", &gem_arg]);
    }

    cmd.args(["-o", out_wasm.to_str().unwrap_or("")]);

    let status = cmd.status().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "`wasi-vfs` was not found. Install it from \
                     https://github.com/kateinoigakukun/wasi-vfs/releases/tag/v0.6.3 \
                     or set WASI_VFS=<path>."
            )
        } else {
            anyhow::anyhow!("spawning `wasi-vfs`: {e}")
        }
    })?;

    let wasm_result = if status.success() {
        std::fs::read(&out_wasm)
            .with_context(|| format!("reading packed wasm {}", out_wasm.display()))
    } else {
        let code = status.code().unwrap_or(-1);
        Err(anyhow::anyhow!("`wasi-vfs pack` exited with code {code}"))
    };

    let _ = std::fs::remove_dir_all(&work);
    wasm_result
}

/// Resolve the `[gem]` section deps into a flat file map (gem name-version/relpath -> bytes).
///
/// Uses the same `GemClient::resolve_all` the Ruby source runner uses.
/// Only pure-Ruby gems are accepted (the client rejects native-ext gems).
/// Returns an empty map when `gem_section` is empty.
fn resolve_gems(gem_section: &BTreeMap<String, String>) -> Result<BTreeMap<String, Vec<u8>>> {
    if gem_section.is_empty() {
        return Ok(BTreeMap::new());
    }
    let client = GemClient::public();
    let resolution = client
        .resolve_all(gem_section)
        .map_err(|e| anyhow::anyhow!("gem resolution: {e}"))?;

    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for pkg in &resolution.packages {
        for (rel, data) in &pkg.files {
            // Key: "<name>-<version>/<rel>" - matches the layout pack_ruby_wasm stages
            let key = format!("{}-{}/{}", pkg.name, pkg.version, rel);
            out.insert(key, data.clone());
        }
    }
    Ok(out)
}

/// The guest script path for a Ruby wasm package entry.
///
/// Given `entry_rel` = `"source/main.rb"` returns `"/src/source/main.rb"`.
/// This is the argv[1] passed to the packed WASM when run via `EmbedderVm::run_command`.
pub fn guest_entry_path(entry_rel: &str) -> String {
    format!("{GUEST_SRC_MOUNT}/{}", entry_rel.replace('\\', "/"))
}

/// The gem lib-dir load-path entries for bundled gems inside the VFS.
///
/// For each `<name>-<ver>/lib/` top-level file in `gem_files`, emits
/// `"/gems/<name>-<ver>/lib"` so `require 'gemname'` resolves the gem.
pub fn gem_load_path_dirs(gem_files: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    let mut dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for key in gem_files.keys() {
        // key: "<name>-<ver>/<rel>" (no "vendor/gem/" prefix at this point)
        let rel = key.strip_prefix("vendor/gem/").unwrap_or(key);
        if let Some(slash) = rel.find('/') {
            let gem_dir = &rel[..slash];
            let rest = &rel[slash + 1..];
            if rest.starts_with("lib/") || rest == "lib" {
                dirs.insert(format!("{GUEST_GEM_MOUNT}/{gem_dir}/lib"));
            }
        }
    }
    dirs.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_entry_path_simple() {
        assert_eq!(guest_entry_path("source/main.rb"), "/src/source/main.rb");
    }

    #[test]
    fn guest_entry_path_nested() {
        assert_eq!(
            guest_entry_path("source/sub/app.rb"),
            "/src/source/sub/app.rb"
        );
    }

    #[test]
    fn gem_load_path_dirs_empty() {
        let files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        assert!(gem_load_path_dirs(&files).is_empty());
    }

    #[test]
    fn gem_load_path_dirs_detects_lib() {
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("color-1.0.0/lib/color.rb".to_owned(), b"".to_vec());
        files.insert("color-1.0.0/README.md".to_owned(), b"".to_vec());
        files.insert("widget-2.1.3/lib/widget.rb".to_owned(), b"".to_vec());
        let dirs = gem_load_path_dirs(&files);
        assert_eq!(dirs.len(), 2);
        assert!(dirs.iter().any(|d| d.ends_with("color-1.0.0/lib")));
        assert!(dirs.iter().any(|d| d.ends_with("widget-2.1.3/lib")));
    }

    #[test]
    fn gem_load_path_dirs_with_vendor_prefix() {
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("vendor/gem/foo-1.0.0/lib/foo.rb".to_owned(), b"".to_vec());
        let dirs = gem_load_path_dirs(&files);
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].ends_with("foo-1.0.0/lib"), "got: {:?}", dirs);
    }
}
