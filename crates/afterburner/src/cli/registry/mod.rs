// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn` registry + package-management subcommands. Thin handlers over
//! [`afterburner_cloud`]; all output is styled via [`super::style`].

mod progress;

use super::args::{Cli, ScaffoldArgs};
use super::style;
use afterburner_cloud::afterburner_afb::digest::hex;
use afterburner_cloud::lock::{LOCKFILE_NAME, Lockfile};
use afterburner_cloud::resolve::{Req, resolve, runtime_version};
use afterburner_cloud::scaffold::{ScaffoldOpts, Scaffolded};
use afterburner_cloud::source::RegistrySource;
use afterburner_cloud::{
    CacheInstaller, Coord, InstallSummary, Manifest, RegistryClient, config, install_concurrent,
    pkg, scaffold,
};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn login(token: Option<&str>, registry: Option<&str>) -> Result<()> {
    let base = match config::resolve(registry, None) {
        Ok(r) => r.base_url,
        Err(_) if registry.is_none() => afterburner_cloud::DEFAULT_REGISTRY_URL.to_string(),
        Err(e) => return Err(e.into()),
    };

    let (token_value, username) = match token {
        Some(tok) => {
            let client = RegistryClient::with_token(base.clone(), tok);
            let me = style::spin("verifying token", || client.me())
                .with_context(|| format!("the registry at {base} rejected that token"))?;
            (tok.to_string(), me.username)
        }
        None => {
            eprintln!("{}", style::muted(&format!("logging in to {base}")));
            let username = prompt_line("username: ")?;
            if username.is_empty() {
                anyhow::bail!("username is required");
            }
            let password = read_secret("password: ")?;
            let client = RegistryClient::new(base.clone(), None);
            let resp = style::spin("authenticating", || client.login(&username, &password))?;
            (resp.token, resp.username)
        }
    };

    let path = config::store_token(registry, &base, &token_value, Some(&username))?;
    println!(
        "{}",
        style::ok(&format!(
            "logged in to {} as {}",
            style::value(&base),
            style::accent(&username)
        ))
    );
    println!(
        "  {} {}",
        style::muted("token saved to"),
        style::value(&path.display().to_string())
    );
    Ok(())
}

pub fn logout(registry: Option<&str>) -> Result<()> {
    if config::remove_token(registry)? {
        println!(
            "{}",
            style::ok(&format!("logged out{}", reg_suffix(registry)))
        );
    } else {
        println!(
            "{}",
            style::muted(&format!(
                "no stored token{} to remove",
                reg_suffix(registry)
            ))
        );
    }
    Ok(())
}

pub fn whoami(registry: Option<&str>) -> Result<()> {
    let resolved = config::resolve(registry, None)?;
    let client = RegistryClient::from_resolved(resolved);
    let me = style::spin("checking", || client.me())?;
    println!(
        "{} {}",
        style::accent(&me.username),
        style::muted(&format!("({})", admin_label(me.is_admin)))
    );
    Ok(())
}

pub fn new_package(cli: &Cli, spec: &str, args: &ScaffoldArgs) -> Result<()> {
    let opts = scaffold_opts(cli, args);
    let made = scaffold::run_new(spec, &opts, login_username().as_deref())?;
    report_scaffold(&made);
    Ok(())
}

pub fn init_package(cli: &Cli, path: Option<&Path>, args: &ScaffoldArgs) -> Result<()> {
    let opts = scaffold_opts(cli, args);
    let made = scaffold::run_init(path, &opts, login_username().as_deref())?;
    report_scaffold(&made);
    Ok(())
}

fn scaffold_opts(cli: &Cli, a: &ScaffoldArgs) -> ScaffoldOpts {
    let any_or_list = |v: &str| -> Vec<String> {
        if v == "*" || v.is_empty() {
            Vec::new()
        } else {
            split_list(v)
        }
    };
    ScaffoldOpts {
        namespace: a.namespace.clone(),
        name: a.name.clone(),
        version: a.pkg_version.clone(),
        description: a.description.clone(),
        license: a.license.clone(),
        template: a.template.clone(),
        allow_all: cli.allow_all,
        net: cli.allow_net.as_deref().map(&any_or_list),
        env_keys: cli.allow_env.as_deref().map(split_list),
        // runtime `--allow-fs` is read-write; `--allow-fs-read` is read-only.
        fs_read: cli.allow_fs_read.as_deref().map(&any_or_list),
        fs_write: cli
            .allow_fs
            .as_deref()
            .or(cli.allow_fs_write.as_deref())
            .map(&any_or_list),
        crypto: a.allow_crypto,
        run: a.allow_run || cli.allow_child_process,
        vcs_git: a.vcs.as_deref() == Some("git"),
        force: a.force,
    }
}

fn report_scaffold(s: &Scaffolded) {
    println!(
        "{} {} {}",
        style::ok("created"),
        style::flame(&format!("{}/{}", s.namespace, s.name)),
        style::muted(&format!("({})", s.template))
    );
    println!(
        "  {}",
        style::value("afb.toml  manifold.json  source/main.js  tests/  README.md")
    );
    println!(
        "  {} {}",
        style::muted("capabilities:"),
        style::gold(&s.capabilities.join(", "))
    );
    if s.namespace_is_placeholder {
        println!(
            "  {}",
            style::warn(
                "namespace defaulted to a placeholder. Set --namespace <you> or `burn login`"
            )
        );
    }
    println!("\n{}", style::muted("next:"));
    println!("  {} cd {}", style::bullet(), s.dir.display());
    println!("  {} burn package", style::bullet());
    println!("  {} burn publish", style::bullet());
}

pub fn package(dir: Option<&Path>, out: Option<&Path>) -> Result<()> {
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let local = pkg::LocalPackage::load(dir)?;
    let (bytes, digest) = style::spin("packing", || local.build())?;
    let out = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from(local.output_filename()));
    std::fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;
    println!(
        "{}",
        style::ok(&format!("packaged {}", style::accent(&coord_str(&local))))
    );
    print_digest(bytes.len() as u64, &hex(&digest));
    println!(
        "  {} {}",
        style::muted("→"),
        style::value(&out.display().to_string())
    );
    Ok(())
}

pub fn publish(
    afb: Option<&Path>,
    dir: Option<&Path>,
    registry: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    let bytes = match afb {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => {
            let dir = dir.unwrap_or_else(|| Path::new("."));
            let local = pkg::LocalPackage::load(dir)?;
            style::spin("packing", || local.build())?.0
        }
    };
    let max = afterburner_cloud::afterburner_afb::MAX_AFB_BYTES;
    if bytes.len() > max {
        anyhow::bail!(
            "package is {:.1} MiB, over the registry's {} MiB limit",
            bytes.len() as f64 / 1_048_576.0,
            max / (1024 * 1024)
        );
    }
    let resolved = config::resolve(registry, token)?;
    let client = RegistryClient::from_resolved(resolved);
    let resp = style::spin("uploading", || client.publish(&bytes))?;
    println!(
        "{}",
        style::ok(&format!(
            "published {}",
            style::accent(&format!(
                "{}/{}@{}",
                resp.namespace, resp.name, resp.version
            ))
        ))
    );
    print_digest(resp.size_bytes, &resp.digest);
    Ok(())
}

pub fn yank(pkg: &str, undo: bool, registry: Option<&str>, token: Option<&str>) -> Result<()> {
    let coord = Coord::parse(pkg)?;
    let version = coord
        .version
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("yank needs a version: `namespace/name@version`"))?;
    let resolved = config::resolve(registry, token)?;
    let client = RegistryClient::from_resolved(resolved);
    let label = if undo { "restoring" } else { "yanking" };
    let resp = style::spin(label, || {
        client.yank(&coord.namespace, &coord.name, version, undo)
    })?;
    let verb = if resp.yanked { "yanked" } else { "un-yanked" };
    println!(
        "{}",
        style::ok(&format!(
            "{verb} {}",
            style::accent(&format!(
                "{}/{}@{}",
                resp.namespace, resp.name, resp.version
            ))
        ))
    );
    Ok(())
}

/// `burn install [pkg]` — resolve the full dependency set (PubGrub) and fetch it
/// concurrently into the content-addressed cache, with an animated progress bar.
///
/// With `pkg`, installs that package plus its transitive dependencies. With no
/// `pkg`, installs the current directory's `afb.toml` dependencies and writes a
/// `burn.lock`. `--locked` reuses an existing `burn.lock` without re-resolving.
pub fn install(
    pkg: Option<&str>,
    registry: Option<&str>,
    jobs: Option<usize>,
    locked: bool,
) -> Result<()> {
    let resolved = config::resolve(registry, None)?;
    let client = RegistryClient::from_resolved(resolved);

    let plan = build_install_plan(pkg, &client, locked)?;
    let items = plan.lockfile.install_items();
    if items.is_empty() {
        println!("{}", style::muted("nothing to install"));
        return Ok(());
    }

    let jobs = jobs.unwrap_or_else(default_jobs).clamp(1, items.len());
    let installer = CacheInstaller { client: &client };
    let (prog, renderer) = progress::InstallProgress::new();

    let summary = std::thread::scope(|scope| {
        let handle = renderer.map(|r| scope.spawn(move || r.run()));
        let out = install_concurrent(&items, &installer, jobs, &prog);
        if let Some(h) = handle {
            let _ = h.join();
        }
        out
    })?;

    if let Some(dir) = &plan.write_lock_to {
        let path = dir.join(LOCKFILE_NAME);
        std::fs::write(&path, plan.lockfile.to_toml()?)
            .with_context(|| format!("writing {}", path.display()))?;
    }

    report_install(&plan.lockfile, &summary);
    Ok(())
}

struct InstallPlan {
    lockfile: Lockfile,
    /// `Some(dir)` writes `burn.lock` there after a successful install.
    write_lock_to: Option<PathBuf>,
}

fn build_install_plan(
    pkg: Option<&str>,
    client: &RegistryClient,
    locked: bool,
) -> Result<InstallPlan> {
    let runtime = runtime_version(env!("CARGO_PKG_VERSION"));
    let source = RegistrySource::new(client);

    match pkg {
        Some(spec) => {
            let coord = Coord::parse(spec)?;
            let req = Req::from_cli_version(coord.version.as_deref())?;
            let res = style::spin("resolving", || {
                resolve(&[(coord.qualified(), req)], &source, &runtime)
            })?;
            Ok(InstallPlan {
                lockfile: Lockfile::from_resolution(&res),
                write_lock_to: None,
            })
        }
        None => {
            let dir = PathBuf::from(".");
            if locked {
                let path = dir.join(LOCKFILE_NAME);
                let text = std::fs::read_to_string(&path).map_err(|_| {
                    anyhow::anyhow!(
                        "--locked needs an existing {LOCKFILE_NAME}; run `burn install` first"
                    )
                })?;
                return Ok(InstallPlan {
                    lockfile: Lockfile::parse(&text)?,
                    write_lock_to: None,
                });
            }
            let local = pkg::LocalPackage::load(&dir)?;
            let roots = manifest_roots(&local.manifest)?;
            let res = style::spin("resolving", || resolve(&roots, &source, &runtime))?;
            Ok(InstallPlan {
                lockfile: Lockfile::from_resolution(&res),
                write_lock_to: Some(dir),
            })
        }
    }
}

fn manifest_roots(m: &Manifest) -> Result<Vec<(String, Req)>> {
    m.dependencies
        .iter()
        .map(|(coord, spec)| Ok((coord.clone(), Req::parse(spec)?)))
        .collect()
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 8)
}

fn report_install(lock: &Lockfile, summary: &InstallSummary) {
    let total = lock.packages.len();
    let cached: std::collections::HashSet<&str> =
        summary.cached.iter().map(String::as_str).collect();
    let detail = if !cached.is_empty() {
        style::muted(&format!(" ({} already cached)", cached.len()))
    } else {
        String::new()
    };
    println!(
        "{}",
        style::ok(&format!(
            "installed {total} package{}{detail}",
            if total == 1 { "" } else { "s" }
        ))
    );
    for p in &lock.packages {
        let tag = if cached.contains(p.name.as_str()) {
            style::muted("  cached")
        } else {
            String::new()
        };
        println!(
            "  {} {}{}",
            style::bullet(),
            style::value(&format!("{}@{}", p.name, p.version)),
            tag
        );
    }
    for (coord, w) in &summary.warnings {
        eprintln!("{}", style::warn(&format!("{coord}: {w}")));
    }
}

pub fn add(pkg: &str, dir: Option<&Path>, registry: Option<&str>) -> Result<()> {
    let coord = Coord::parse(pkg)?;
    let resolved = config::resolve(registry, None)?;
    let client = RegistryClient::from_resolved(resolved);

    let digest = match &coord.version {
        Some(v) => {
            style::spin("resolving", || {
                client.get_version(&coord.namespace, &coord.name, v)
            })?
            .digest
        }
        None => {
            let meta = style::spin("resolving", || {
                client.get_package(&coord.namespace, &coord.name)
            })?;
            let latest = meta.latest.clone().ok_or_else(|| {
                anyhow::anyhow!("{} has no published versions", coord.qualified())
            })?;
            meta.digest_for(&latest)
                .ok_or_else(|| anyhow::anyhow!("registry omitted a digest for {latest}"))?
                .to_string()
        }
    };

    let dir = dir.unwrap_or_else(|| Path::new("."));
    let qualified = coord.qualified();
    pkg::add_dependency(dir, &qualified, &digest)?;
    println!(
        "{}",
        style::ok(&format!(
            "added {} {}",
            style::accent(&qualified),
            style::muted(&format!("(sha256:{digest})"))
        ))
    );
    println!(
        "  {} {}",
        style::muted("→"),
        style::value(&dir.join("afb.toml").display().to_string())
    );
    Ok(())
}

pub fn search(query: &str, registry: Option<&str>) -> Result<()> {
    let resolved = config::resolve(registry, None)?;
    let client = RegistryClient::from_resolved(resolved);
    let results = style::spin("searching", || client.search(query))?;
    if results.packages.is_empty() {
        println!("{}", style::muted(&format!("no packages match {query:?}")));
        return Ok(());
    }
    for p in &results.packages {
        let latest = p.latest.as_deref().unwrap_or("-");
        println!(
            "{} {}",
            style::accent(&format!("{}/{}@{}", p.namespace, p.name, latest)),
            style::muted(&format!(
                "({} download{})",
                p.downloads,
                if p.downloads == 1 { "" } else { "s" }
            ))
        );
        if let Some(d) = &p.description {
            println!("    {}", style::muted(d));
        }
    }
    println!(
        "{}",
        style::muted(&format!(
            "{} package(s)",
            results.count.max(results.packages.len())
        ))
    );
    Ok(())
}

pub fn info(pkg: &str, registry: Option<&str>) -> Result<()> {
    let coord = Coord::parse(pkg)?;
    let resolved = config::resolve(registry, None)?;
    let client = RegistryClient::from_resolved(resolved);

    match &coord.version {
        Some(v) => {
            let m = style::spin("fetching", || {
                client.get_version(&coord.namespace, &coord.name, v)
            })?;
            println!(
                "{}",
                style::flame(&format!("{}/{}@{}", m.namespace, m.name, m.version))
            );
            field("digest", &format!("sha256:{}", m.digest));
            field("size", &format!("{} bytes", m.size_bytes));
            if let Some(rt) = &m.runtime_min {
                field("runtime min", rt);
            }
            if m.yanked {
                println!("  {}", style::warn("this version is yanked"));
            }
            if !m.capabilities.is_empty() {
                println!("  {}", style::muted("capabilities:"));
                for c in &m.capabilities {
                    println!("    {} {}", style::bullet(), style::gold(c));
                }
            }
            if let Some(deps) = m.dependencies.as_object().filter(|d| !d.is_empty()) {
                println!("  {}", style::muted("dependencies:"));
                for (k, val) in deps {
                    println!(
                        "    {} = {}",
                        style::accent(k),
                        style::value(val.as_str().unwrap_or(""))
                    );
                }
            }
        }
        None => {
            let m = style::spin("fetching", || {
                client.get_package(&coord.namespace, &coord.name)
            })?;
            println!("{}", style::flame(&format!("{}/{}", m.namespace, m.name)));
            if let Some(d) = &m.description {
                println!("  {}", style::muted(d));
            }
            if let Some(h) = &m.homepage {
                field("homepage", h);
            }
            if let Some(l) = &m.latest {
                field("latest", l);
            }
            field("downloads", &m.downloads.to_string());
            if !m.keywords.is_empty() {
                field("keywords", &m.keywords.join(", "));
            }
            if !m.versions.is_empty() {
                println!("  {}", style::muted("versions:"));
                for v in &m.versions {
                    let short = v.digest.get(..12).unwrap_or(&v.digest);
                    println!(
                        "    {}  {}{}",
                        style::accent(&v.version),
                        style::value(&format!("sha256:{short}…")),
                        if v.yanked {
                            style::warn("  yanked")
                        } else {
                            String::new()
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

pub fn owner(
    _pkg: Option<&str>,
    _list: bool,
    _add: Option<&str>,
    _remove: Option<&str>,
) -> Result<()> {
    anyhow::bail!(
        "`burn owner` is not available yet. The registry's owners API is on the roadmap. \
         (Read-only owner info is shown by `burn info <pkg>`.)"
    )
}

/// `burn test` — run every test file under `<dir>/tests/` through the runtime.
/// Each file is executed as its own `burn run` (clean process per file so
/// `node:test`'s exit-code semantics hold); output is shown only on failure.
pub fn test(cli: &Cli, dir: Option<&Path>) -> Result<()> {
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let tests_dir = dir.join("tests");
    if !tests_dir.is_dir() {
        anyhow::bail!(
            "no tests/ directory in {}: `burn new`/`init` scaffolds one",
            dir.display()
        );
    }
    let mut files = Vec::new();
    collect_test_files(&tests_dir, &mut files)?;
    files.sort();
    if files.is_empty() {
        anyhow::bail!("no test files under {}", tests_dir.display());
    }

    let exe = std::env::current_exe().context("locating the burn executable")?;
    let forwarded = forwarded_flags(cli);
    let (mut total_pass, mut total_fail, mut failed) = (0usize, 0usize, 0usize);

    for file in &files {
        let rel = file.strip_prefix(dir).unwrap_or(file).display().to_string();
        let output = style::spin(&format!("test {rel}"), || {
            std::process::Command::new(&exe)
                .env("BURN_QUIET", "1")
                .arg("run")
                .arg(file)
                .args(&forwarded)
                .current_dir(dir)
                .stdin(std::process::Stdio::null())
                .output()
        })
        .with_context(|| format!("running {rel}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let (pass, fail) = parse_tap_counts(&stdout);
        total_pass += pass;
        total_fail += fail;

        if output.status.success() && fail == 0 {
            let detail = if pass > 0 {
                format!("  ({pass} passed)")
            } else {
                String::new()
            };
            println!(
                "{}",
                style::ok(&format!("{}{}", style::value(&rel), style::muted(&detail)))
            );
        } else {
            failed += 1;
            println!("{}", style::fail(&style::value(&rel)));
            let stderr = String::from_utf8_lossy(&output.stderr);
            for line in stdout.lines().chain(stderr.lines()) {
                println!("    {}", style::muted(line));
            }
        }
    }

    let summary = format!(
        "{} file(s), {total_pass} passed, {total_fail} failed",
        files.len()
    );
    if failed == 0 {
        println!("{}", style::ok(&summary));
        Ok(())
    } else {
        println!("{}", style::fail(&summary));
        anyhow::bail!("{failed} test file(s) failed")
    }
}

fn collect_test_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_test_files(&path, out)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && matches!(ext, "js" | "mjs" | "cjs" | "ts")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn parse_tap_counts(tap: &str) -> (usize, usize) {
    let (mut pass, mut fail) = (0usize, 0usize);
    for line in tap.lines() {
        let l = line.trim();
        if let Some(n) = l.strip_prefix("# pass:") {
            pass = n.trim().parse().unwrap_or(0);
        } else if let Some(n) = l.strip_prefix("# fail:") {
            fail = n.trim().parse().unwrap_or(0);
        }
    }
    (pass, fail)
}

/// Forward the runtime/capability flags from `burn test` to each `burn run`.
fn forwarded_flags(cli: &Cli) -> Vec<String> {
    let mut a = Vec::new();
    if cli.sandbox {
        a.push("--sandbox".into());
    }
    if cli.allow_all {
        a.push("-A".into());
    }
    for (flag, val) in [
        ("--allow-net", &cli.allow_net),
        ("--allow-listen", &cli.allow_listen),
        ("--allow-fs", &cli.allow_fs),
        ("--allow-env", &cli.allow_env),
        ("--allow-fs-read", &cli.allow_fs_read),
        ("--allow-fs-write", &cli.allow_fs_write),
        ("--mode", &cli.mode),
    ] {
        if let Some(v) = val {
            a.push(flag.to_string());
            a.push(v.clone());
        }
    }
    if let Some(f) = cli.fuel {
        a.push("--fuel".into());
        a.push(f.to_string());
    }
    if let Some(t) = cli.timeout_ms {
        a.push("--timeout".into());
        a.push(t.to_string());
    }
    if let Some(m) = cli.memory {
        a.push("--memory".into());
        a.push(m.to_string());
    }
    for ef in &cli.env_file {
        a.push("--env-file".into());
        a.push(ef.display().to_string());
    }
    a
}

fn coord_str(p: &pkg::LocalPackage) -> String {
    format!(
        "{}/{}@{}",
        p.manifest.package.namespace, p.manifest.package.name, p.manifest.package.version
    )
}

fn print_digest(size: u64, digest_hex: &str) {
    println!(
        "  {} {}  {}",
        style::muted("digest"),
        style::value(&format!("sha256:{digest_hex}")),
        style::muted(&format!("({size} bytes)"))
    );
}

fn field(label: &str, val: &str) {
    println!("  {:<12} {}", style::muted(label), style::value(val));
}

fn login_username() -> Option<String> {
    config::resolve(None, None).ok().and_then(|r| r.username)
}

fn reg_suffix(registry: Option<&str>) -> String {
    registry
        .map(|n| format!(" from registry {n}"))
        .unwrap_or_default()
}

fn admin_label(is_admin: bool) -> &'static str {
    if is_admin { "admin" } else { "user" }
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    eprint!("{}", style::muted(prompt));
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(unix)]
fn read_secret(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    eprint!("{}", style::muted(prompt));
    std::io::stderr().flush()?;

    let fd = 0; // STDIN_FILENO
    let mut restore: Option<libc::termios> = None;
    unsafe {
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) == 0 {
            let orig = term;
            term.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(fd, libc::TCSANOW, &term) == 0 {
                restore = Some(orig);
            }
        }
    }
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if let Some(orig) = restore {
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &orig);
        }
        eprintln!();
    }
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(not(unix))]
fn read_secret(prompt: &str) -> Result<String> {
    eprint!("{}", style::muted(&format!("{prompt}(visible) ")));
    prompt_line("")
}
