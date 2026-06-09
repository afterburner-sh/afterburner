// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn` registry + package-management subcommands. Thin handlers over
//! [`afterburner_cloud`]; all output is styled via [`super::style`].

use super::args::{Cli, ScaffoldArgs};
use super::style;
use afterburner_cloud::afterburner_afb::digest::hex;
use afterburner_cloud::scaffold::{ScaffoldOpts, Scaffolded};
use afterburner_cloud::{Coord, RegistryClient, cache, config, pkg, scaffold};
use anyhow::{Context, Result};
use std::path::Path;

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
        style::value("afb.toml  manifold.json  source/main.js  README.md")
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
                "namespace defaulted to a placeholder — set --namespace <you> or `burn login`"
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

pub fn install(pkg: &str, registry: Option<&str>) -> Result<()> {
    let coord = Coord::parse(pkg)?;
    let resolved = config::resolve(registry, None)?;
    let client = RegistryClient::from_resolved(resolved);

    let (version, expected_digest, bytes) = match &coord.version {
        Some(v) => {
            let meta = style::spin("resolving", || {
                client.get_version(&coord.namespace, &coord.name, v)
            })?;
            let bytes = style::spin("downloading", || {
                client.download(&coord.namespace, &coord.name, v)
            })?;
            (meta.version, meta.digest, bytes)
        }
        None => {
            let meta = style::spin("resolving", || {
                client.get_package(&coord.namespace, &coord.name)
            })?;
            let latest = meta.latest.clone().ok_or_else(|| {
                anyhow::anyhow!("{} has no published versions", coord.qualified())
            })?;
            let digest = meta
                .digest_for(&latest)
                .ok_or_else(|| anyhow::anyhow!("registry omitted a digest for {latest}"))?
                .to_string();
            let bytes = style::spin("downloading", || {
                client.download_latest(&coord.namespace, &coord.name)
            })?;
            (latest, digest, bytes)
        }
    };

    let stored = cache::verify_and_store(&expected_digest, &bytes)?;
    println!(
        "{}",
        style::ok(&format!(
            "installed {}",
            style::accent(&format!("{}/{}@{}", coord.namespace, coord.name, version))
        ))
    );
    print_digest(bytes.len() as u64, &expected_digest);
    println!(
        "  {} {}",
        style::muted("cached"),
        style::value(&stored.path.display().to_string())
    );
    if let Some(w) = stored.warning {
        eprintln!("{}", style::warn(&w));
    }
    Ok(())
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
        "`burn owner` is not available yet — the registry's owners API is on the roadmap. \
         (Read-only owner info is shown by `burn info <pkg>`.)"
    )
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
