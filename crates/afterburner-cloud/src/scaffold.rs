// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `burn new` / `burn init` - scaffold a `.afb` package project, cargo-style.
//!
//! Mirrors the registry's own scaffolder (`afterburner-registry new/init`) so
//! the two tools emit identical projects. Capability flags pre-fill
//! `manifold.json` using the same grant vocabulary as the `burn` runtime
//! (`--allow-net`, `--allow-env`, `--allow-fs`, `-A`, …), so a scaffolded
//! package declares least privilege from the start. The `--template` picks the
//! `source/main.js` entry stub (`module` | `udf` | `http` | `llm`).

use crate::error::{CloudError, Result};
use afterburner_afb::manifest::{Format, Package, Runtime};
use afterburner_afb::{Manifest, Manifold};
use afterburner_core::manifold::{EnvAccess, FsAccess, NetAccess};
use std::path::{Path, PathBuf};

/// Placeholder used when no namespace is given and the user isn't logged in.
pub const PLACEHOLDER_NAMESPACE: &str = "your-namespace";

/// The four entry-point templates.
pub const TEMPLATES: [&str; 4] = ["module", "udf", "http", "llm"];

/// Inputs to a scaffold, filled from the CLI flags.
#[derive(Debug, Default, Clone)]
pub struct ScaffoldOpts {
    /// Explicit `--namespace`.
    pub namespace: Option<String>,
    /// Explicit `--name` (may itself be `ns/name`).
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub template: Option<String>,
    pub allow_all: bool,
    /// `--allow-net` present? Inner vec is the host allow-list (empty = any host).
    pub net: Option<Vec<String>>,
    pub env_keys: Option<Vec<String>>,
    pub fs_read: Option<Vec<String>>,
    pub fs_write: Option<Vec<String>>,
    pub crypto: bool,
    pub run: bool,
    pub vcs_git: bool,
    pub force: bool,
    /// Scaffold a TypeScript package (`source/main.ts` + tsconfig).
    /// Shorthand for `lang = Some("typescript")`.
    pub ts: bool,
    /// Explicit source language (e.g. `"rust"`, `"go"`, `"typescript"`).
    /// When `Some`, overrides the `ts` bool.
    /// Validated by the caller; the scaffold writes it verbatim into `afb.toml`.
    pub lang: Option<String>,
}

/// What a scaffold produced (for the CLI to report).
#[derive(Debug, Clone)]
pub struct Scaffolded {
    pub dir: PathBuf,
    pub namespace: String,
    pub name: String,
    pub template: String,
    pub capabilities: Vec<String>,
    /// True when the namespace fell back to the placeholder (CLI should nudge).
    pub namespace_is_placeholder: bool,
    /// The scaffolded entry source path (e.g. `source/main.rs`).
    pub entry: String,
    /// The effective language string stored in afb.toml.
    pub lang: String,
}

/// Build a [`Manifold`] from the capability flags (sealed when none are given).
pub fn manifold_from(o: &ScaffoldOpts) -> Manifold {
    let mut m = Manifold::sealed();
    if o.allow_all {
        m.fs = FsAccess::ReadWrite(Vec::new());
        m.net = NetAccess::OutboundFull(None);
        m.crypto = true;
        m.child_process = true;
        m.env = EnvAccess::Full;
        return m;
    }
    if let Some(hosts) = &o.net {
        m.net = if hosts.is_empty() {
            NetAccess::OutboundHttp(None)
        } else {
            NetAccess::OutboundHttp(Some(hosts.clone()))
        };
        m.http_timeout_ms = Some(30_000);
    }
    if let Some(keys) = &o.env_keys {
        m.env = EnvAccess::AllowList(keys.clone());
    }
    if let Some(paths) = &o.fs_read {
        m.fs = FsAccess::ReadOnly(paths.iter().map(PathBuf::from).collect());
    }
    if let Some(paths) = &o.fs_write {
        m.fs = FsAccess::ReadWrite(paths.iter().map(PathBuf::from).collect());
    }
    if o.crypto {
        m.crypto = true;
    }
    if o.run {
        m.child_process = true;
    }
    m
}

/// A short, human-readable capability summary (for the README + CLI output).
pub fn summarize(m: &Manifold) -> Vec<String> {
    let join = |p: &[PathBuf]| -> String {
        if p.is_empty() {
            "any path".into()
        } else {
            p.iter()
                .map(|x| x.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let mut out = Vec::new();
    match &m.fs {
        FsAccess::None => {}
        FsAccess::ReadOnly(p) => out.push(format!("fs: read {}", join(p))),
        FsAccess::ReadWrite(p) => out.push(format!("fs: read-write {}", join(p))),
    }
    match &m.net {
        NetAccess::None => {}
        NetAccess::OutboundHttp(None) => out.push("net: http → any host".into()),
        NetAccess::OutboundHttp(Some(h)) => out.push(format!("net: http → {}", h.join(", "))),
        NetAccess::OutboundFull(None) => out.push("net: tcp+http → any host".into()),
        NetAccess::OutboundFull(Some(h)) => out.push(format!("net: tcp+http → {}", h.join(", "))),
    }
    if m.crypto {
        out.push("crypto".into());
    }
    if m.child_process {
        out.push("child_process".into());
    }
    match &m.env {
        EnvAccess::None => {}
        EnvAccess::AllowList(k) => out.push(format!("env: {}", k.join(", "))),
        EnvAccess::Full => out.push("env: all".into()),
    }
    if out.is_empty() {
        out.push("sealed (no capabilities)".into());
    }
    out
}

fn main_js(template: &str, namespace: &str, name: &str) -> String {
    let header = format!("// {namespace}/{name}: an Afterburner package.\n\"use strict\";\n\n");
    let body = match template {
        "udf" => {
            "// A UDF: one record in, the transformed record out.\nmodule.exports = function (record) {\n  // transform `record` and return the result\n  return record;\n};\n"
        }
        "http" => {
            "// Fetches a URL. Needs net access (see manifold.json).\nmodule.exports = async function (input) {\n  const res = await fetch((input && input.url) || \"https://example.com\");\n  return { status: res.status, body: await res.text() };\n};\n"
        }
        "llm" => {
            "// Calls an LLM endpoint. Needs net + an API key (see manifold.json).\nmodule.exports = async function (input) {\n  const key = (typeof process !== \"undefined\" && process.env && process.env.API_KEY) || (input && input.apiKey);\n  const res = await fetch(\"https://api.example.com/v1/chat\", {\n    method: \"POST\",\n    headers: { \"content-type\": \"application/json\", authorization: \"Bearer \" + key },\n    body: JSON.stringify({ prompt: input && input.prompt }),\n  });\n  if (!res.ok) throw new Error(\"HTTP \" + res.status);\n  return await res.json();\n};\n"
        }
        _ => {
            "// The default export is the entry point: input in, result out.\nmodule.exports = function (input) {\n  return { hello: (input && input.name) || \"world\" };\n};\n"
        }
    };
    format!("{header}{body}")
}

const TSCONFIG: &str = "{\n  \"compilerOptions\": {\n    \"target\": \"es2022\",\n    \"module\": \"commonjs\",\n    \"strict\": true,\n    \"esModuleInterop\": true,\n    \"skipLibCheck\": true,\n    \"types\": []\n  },\n  \"include\": [\"source/**/*.ts\", \"tests/**/*.ts\"]\n}\n";

// TypeScript entry stubs. `burn package` transpiles these to JS at pack
// time, so the published .afb is always plain JS - TS is purely a
// developer convenience (types + editor support).
fn main_ts(template: &str, namespace: &str, name: &str) -> String {
    let header = format!("// {namespace}/{name}: an Afterburner package (TypeScript).\n\n");
    let body = match template {
        "udf" => {
            "// A UDF: one record in, the transformed record out.\nmodule.exports = function (record: Record<string, unknown>): Record<string, unknown> {\n  return record;\n};\n"
        }
        "http" => {
            "// Fetches a URL. Needs net access (see manifold.json).\nmodule.exports = async function (input: { url?: string }): Promise<{ status: number; body: string }> {\n  const res = await fetch(input?.url ?? \"https://example.com\");\n  return { status: res.status, body: await res.text() };\n};\n"
        }
        "llm" => {
            "// Calls an LLM endpoint. Needs net + an API key (see manifold.json).\nmodule.exports = async function (input: { prompt?: string; apiKey?: string }): Promise<unknown> {\n  const key = (typeof process !== \"undefined\" && process.env && process.env.API_KEY) || input?.apiKey;\n  const res = await fetch(\"https://api.example.com/v1/chat\", {\n    method: \"POST\",\n    headers: { \"content-type\": \"application/json\", authorization: \"Bearer \" + key },\n    body: JSON.stringify({ prompt: input?.prompt }),\n  });\n  if (!res.ok) throw new Error(\"HTTP \" + res.status);\n  return await res.json();\n};\n"
        }
        _ => {
            "// The default export is the entry point: input in, result out.\nmodule.exports = function (input: { name?: string }): { hello: string } {\n  return { hello: input?.name ?? \"world\" };\n};\n"
        }
    };
    format!("{header}{body}")
}

fn test_ts(template: &str, name: &str) -> String {
    let header = "const test = require('node:test');\nconst assert = require('node:assert');\nconst pkg = require('../source/main.ts');\n\n";
    let body = match template {
        "udf" => format!(
            "test('{name} passes a record through', () => {{\n  const record = {{ id: 1, value: 'x' }};\n  assert.deepStrictEqual(pkg(record), record);\n}});\n"
        ),
        "http" | "llm" => format!(
            "test('{name} exports a function', () => {{\n  assert.strictEqual(typeof pkg, 'function');\n}});\n"
        ),
        _ => format!(
            "test('{name} greets', () => {{\n  assert.strictEqual(pkg({{ name: 'world' }}).hello, 'world');\n}});\n"
        ),
    };
    format!("{header}{body}")
}

fn test_js(template: &str, name: &str) -> String {
    let header = "const test = require('node:test');\nconst assert = require('node:assert');\nconst pkg = require('../source/main.js');\n\n";
    let body = match template {
        "udf" => format!(
            "test('{name} passes a record through', () => {{\n  const record = {{ id: 1, value: 'x' }};\n  assert.deepStrictEqual(pkg(record), record);\n}});\n"
        ),
        "http" | "llm" => format!(
            "test('{name} exports a function', () => {{\n  // Keep `burn test` offline; put real network calls in integration tests.\n  assert.strictEqual(typeof pkg, 'function');\n}});\n"
        ),
        _ => format!(
            "test('{name} greets', () => {{\n  assert.strictEqual(pkg({{ name: 'world' }}).hello, 'world');\n}});\n"
        ),
    };
    format!("{header}{body}")
}

/// Resolve the effective language string and whether it is TypeScript.
///
/// Priority: `lang` field > `ts` bool > default `"js"`.
fn resolved_lang(o: &ScaffoldOpts) -> (String, bool) {
    if let Some(ref l) = o.lang {
        let norm = l.trim().to_ascii_lowercase();
        let is_ts = matches!(norm.as_str(), "ts" | "typescript");
        (norm, is_ts)
    } else if o.ts {
        ("typescript".into(), true)
    } else {
        ("js".into(), false)
    }
}

/// Return the default `source/` entry path for a given language string.
fn default_entry_for_lang(lang: &str) -> String {
    match lang {
        "ts" | "typescript" => "source/main.ts".into(),
        "rust" => "source/main.rs".into(),
        "go" | "golang" => "source/main.go".into(),
        "c" => "source/main.c".into(),
        "cpp" | "c++" | "cxx" | "cc" => "source/main.cpp".into(),
        "python" | "py" => "source/main.py".into(),
        "ruby" | "rb" => "source/main.rb".into(),
        _ => "source/main.js".into(),
    }
}

/// Whether a language string names a non-JS/TS (native) language.
fn is_native_lang(lang: &str) -> bool {
    matches!(
        lang,
        "rust"
            | "go"
            | "golang"
            | "c"
            | "cpp"
            | "c++"
            | "cxx"
            | "cc"
            | "python"
            | "py"
            | "ruby"
            | "rb"
    )
}

/// Stub source file for a native language scaffold.
fn native_main_stub(lang: &str, namespace: &str, name: &str) -> String {
    match lang {
        "rust" => format!(
            "// {namespace}/{name}: an Afterburner package (Rust -> wasm32-wasip1).\n\
             fn main() {{\n    // Compute 1+2+...+100\n    let sum: u32 = (1..=100).sum();\n    println!(\"{{sum}}\");\n}}\n"
        ),
        "go" | "golang" => format!(
            "// {namespace}/{name}: an Afterburner package (Go -> wasm32-wasip1).\n\
             package main\n\nfunc main() {{\n\t// Compute 1+2+...+100\n\tsum := 0\n\tfor i := 1; i <= 100; i++ {{\n\t\tsum += i\n\t}}\n\tprintln(sum)\n}}\n"
        ),
        "c" => format!(
            "/* {namespace}/{name}: an Afterburner package (C -> wasm32-wasip1). */\n\
             #include <stdio.h>\nint main(void) {{\n    int sum = 0;\n    for (int i = 1; i <= 100; i++) sum += i;\n    printf(\"%d\\n\", sum);\n    return 0;\n}}\n"
        ),
        "cpp" | "c++" | "cxx" | "cc" => format!(
            "// {namespace}/{name}: an Afterburner package (C++ -> wasm32-wasip1).\n\
             #include <cstdio>\nint main() {{\n    int sum = 0;\n    for (int i = 1; i <= 100; i++) sum += i;\n    std::printf(\"%d\\n\", sum);\n    return 0;\n}}\n"
        ),
        "python" | "py" => format!(
            "# {namespace}/{name}: an Afterburner package (Python -> wasm32-wasip1).\n\
             print(sum(range(1, 101)))\n"
        ),
        "ruby" | "rb" => format!(
            "# {namespace}/{name}: an Afterburner package (Ruby).\n\
             puts (1..100).sum\n"
        ),
        _ => format!("// {namespace}/{name}\n"),
    }
}

/// Optional build file (Cargo.toml or go.mod) for a native scaffold.
/// Returns `(filename, content)` or `None`.
///
/// The Rust `Cargo.toml` declares an empty `[workspace]` table so the package
/// is its own workspace root (it is detached from any enclosing Cargo
/// workspace), uses edition 2024, and points `[[bin]]` at `source/main.rs`.
/// Cargo resolves sibling modules (`mod foo;` -> `source/foo.rs` or
/// `source/foo/mod.rs`) relative to that crate root, so a multi-module
/// `source/` tree compiles with no extra configuration.
fn native_build_file(lang: &str, name: &str) -> Option<(&'static str, String)> {
    match lang {
        "rust" => Some((
            "Cargo.toml",
            format!(
                "[workspace]\n\n[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[[bin]]\nname = \"{name}\"\npath = \"source/main.rs\"\n"
            ),
        )),
        "go" | "golang" => Some(("go.mod", format!("module {name}\n\ngo 1.21\n"))),
        _ => None,
    }
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn write_new_file(path: &Path, contents: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(CloudError::Package(format!(
            "refusing to overwrite {} (use --force)",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(CloudError::Io)?;
    }
    std::fs::write(path, contents).map_err(CloudError::Io)
}

/// Resolve `(namespace, name)` from a positional spec, the flags, an optional
/// directory-name fallback (for `init`), and the logged-in username default.
fn resolve_coords(
    spec: Option<&str>,
    o: &ScaffoldOpts,
    fallback_name: Option<&str>,
    default_ns: Option<&str>,
) -> Result<(String, String, bool)> {
    let split = |s: &str| -> (Option<String>, String) {
        match s.split_once('/') {
            Some((ns, nm)) => (Some(ns.to_string()), nm.to_string()),
            None => (None, s.to_string()),
        }
    };

    // Name source priority: --name, then positional, then directory fallback.
    let (mut coord_ns, name) = if let Some(n) = &o.name {
        split(n)
    } else if let Some(s) = spec {
        split(s)
    } else if let Some(fb) = fallback_name {
        (None, fb.to_string())
    } else {
        return Err(CloudError::Package("a package name is required".into()));
    };

    // Namespace priority: --namespace, then ns from the coordinate, then the
    // logged-in username, then the placeholder.
    let (namespace, is_placeholder) = if let Some(ns) = &o.namespace {
        (ns.clone(), false)
    } else if let Some(ns) = coord_ns.take() {
        (ns, false)
    } else if let Some(ns) = default_ns {
        (ns.to_string(), false)
    } else {
        (PLACEHOLDER_NAMESPACE.to_string(), true)
    };

    Ok((namespace, name, is_placeholder))
}

fn scaffold(
    dir: &Path,
    namespace: &str,
    name: &str,
    is_placeholder: bool,
    o: &ScaffoldOpts,
) -> Result<Scaffolded> {
    if !is_ident(namespace) || !is_ident(name) {
        return Err(CloudError::Package(format!(
            "namespace/name must be lowercase [a-z0-9-_]: got {namespace}/{name}"
        )));
    }

    let template = o.template.clone().unwrap_or_else(|| "module".into());
    if !TEMPLATES.contains(&template.as_str()) {
        return Err(CloudError::Package(format!(
            "unknown --template {template:?} (expected one of: {})",
            TEMPLATES.join(", ")
        )));
    }

    // Resolve the effective language: explicit `lang` > `--ts` shorthand > default `js`.
    let (eff_lang, eff_is_ts) = resolved_lang(o);

    let manifest = Manifest {
        format: Format {
            version: "1.0".into(),
            min_reader: None,
        },
        package: Package {
            name: name.to_string(),
            namespace: namespace.to_string(),
            version: o.version.clone().unwrap_or_else(|| "0.1.0".into()),
            language: eff_lang.clone(),
            entry: default_entry_for_lang(&eff_lang),
            description: o.description.clone(),
            homepage: None,
            license: Some(o.license.clone().unwrap_or_else(|| "Apache-2.0".into())),
            keywords: Vec::new(),
        },
        runtime: Runtime {
            min: "0.1.0".into(),
            target: None,
        },
        dependencies: Default::default(),
        npm: Default::default(),
        signature: None,
        metadata: Default::default(),
        extra: Default::default(),
    };
    let afb_toml = manifest.to_toml_string()?;
    // Validate exactly as the unpacker will, so we never scaffold a package
    // that fails its own `burn package`.
    Manifest::parse(&afb_toml)?;

    let manifold = manifold_from(o);
    let manifold_json = serde_json::to_string_pretty(&manifold)
        .map_err(|e| CloudError::Package(format!("rendering manifold.json: {e}")))?;
    let caps = summarize(&manifold);

    let readme = format!(
        "# {namespace}/{name}\n\nAn Afterburner `.afb` package.\n\n## Capabilities\n\n{}\n\n## Develop\n\n```sh\nburn test           # run tests/ through the runtime\nburn package        # build the .afb locally\nburn publish        # build + upload to the registry\n```\n",
        caps.iter()
            .map(|c| format!("- {c}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    write_new_file(&dir.join("afb.toml"), afb_toml.as_bytes(), o.force)?;
    write_new_file(
        &dir.join("manifold.json"),
        format!("{manifold_json}\n").as_bytes(),
        o.force,
    )?;
    if eff_is_ts {
        write_new_file(
            &dir.join("source/main.ts"),
            main_ts(&template, namespace, name).as_bytes(),
            o.force,
        )?;
        write_new_file(
            &dir.join("tests").join(format!("{name}.test.ts")),
            test_ts(&template, name).as_bytes(),
            o.force,
        )?;
        write_new_file(&dir.join("tsconfig.json"), TSCONFIG.as_bytes(), o.force)?;
    } else if is_native_lang(&eff_lang) {
        // Native languages: scaffold a minimal source file and Cargo.toml / go.mod.
        let entry_path = default_entry_for_lang(&eff_lang);
        let src = native_main_stub(&eff_lang, namespace, name);
        write_new_file(&dir.join(&entry_path), src.as_bytes(), o.force)?;
        if let Some(build_file) = native_build_file(&eff_lang, name) {
            write_new_file(&dir.join(build_file.0), build_file.1.as_bytes(), o.force)?;
        }
    } else {
        write_new_file(
            &dir.join("source/main.js"),
            main_js(&template, namespace, name).as_bytes(),
            o.force,
        )?;
        write_new_file(
            &dir.join("tests").join(format!("{name}.test.js")),
            test_js(&template, name).as_bytes(),
            o.force,
        )?;
    }
    write_new_file(&dir.join("README.md"), readme.as_bytes(), o.force)?;
    if o.vcs_git {
        let _ = write_new_file(&dir.join(".gitignore"), b"*.afb\n", o.force);
    }

    Ok(Scaffolded {
        dir: dir.to_path_buf(),
        namespace: namespace.to_string(),
        name: name.to_string(),
        template,
        capabilities: caps,
        namespace_is_placeholder: is_placeholder,
        entry: default_entry_for_lang(&eff_lang),
        lang: eff_lang,
    })
}

/// `burn new <name|ns/name>` - scaffold a fresh directory `./<name>`.
pub fn run_new(spec: &str, o: &ScaffoldOpts, default_ns: Option<&str>) -> Result<Scaffolded> {
    let (ns, name, placeholder) = resolve_coords(Some(spec), o, None, default_ns)?;
    let dir = PathBuf::from(&name);
    let nonempty = dir
        .read_dir()
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if dir.exists() && nonempty && !o.force {
        return Err(CloudError::Package(format!(
            "directory {} already exists and is not empty (use --force)",
            dir.display()
        )));
    }
    std::fs::create_dir_all(&dir).map_err(CloudError::Io)?;
    scaffold(&dir, &ns, &name, placeholder, o)
}

/// `burn init [path]` - scaffold into an existing directory.
pub fn run_init(
    path: Option<&Path>,
    o: &ScaffoldOpts,
    default_ns: Option<&str>,
) -> Result<Scaffolded> {
    let dir = path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(CloudError::Io)?;
    if dir.join("afb.toml").exists() && !o.force {
        return Err(CloudError::Package(format!(
            "afb.toml already exists in {} (use --force)",
            dir.display()
        )));
    }
    let base = std::fs::canonicalize(&dir)
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()));
    let (ns, name, placeholder) = resolve_coords(None, o, base.as_deref(), default_ns)?;
    scaffold(&dir, &ns, &name, placeholder, o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::LocalPackage;

    fn opts(template: &str) -> ScaffoldOpts {
        ScaffoldOpts {
            name: Some("widget".into()),
            namespace: Some("acme".into()),
            template: Some(template.into()),
            net: if template == "http" || template == "llm" {
                Some(vec!["api.example.com".into()])
            } else {
                None
            },
            env_keys: if template == "llm" {
                Some(vec!["API_KEY".into()])
            } else {
                None
            },
            ..Default::default()
        }
    }

    /// Every template scaffolds a package that round-trips through the real
    /// `.afb` builder + reader - i.e. `burn new … && burn package` works.
    #[test]
    fn every_template_scaffolds_a_buildable_package() {
        for t in TEMPLATES {
            let dir = tempfile::tempdir().unwrap();
            let s = run_init(Some(dir.path()), &opts(t), None).unwrap();
            assert_eq!(s.namespace, "acme");
            assert_eq!(s.name, "widget");
            assert_eq!(s.template, t);

            // Files exist.
            for f in [
                "afb.toml",
                "manifold.json",
                "source/main.js",
                "tests/widget.test.js",
                "README.md",
            ] {
                assert!(dir.path().join(f).exists(), "{t}: missing {f}");
            }

            // Loads, builds, and the bytes parse + verify as a real .afb.
            let pkg = LocalPackage::load(dir.path()).unwrap();
            let (bytes, digest) = pkg.build().unwrap();
            let afb = afterburner_afb::Afb::from_bytes(&bytes).unwrap();
            assert_eq!(afb.digest, digest);
            assert_eq!(afb.qualified_name(), "acme/widget");
            assert!(afb.entry_source().unwrap().contains("module.exports"));
        }
    }

    #[test]
    fn net_and_env_flags_pre_fill_the_manifold() {
        let dir = tempfile::tempdir().unwrap();
        run_init(Some(dir.path()), &opts("llm"), None).unwrap();
        let pkg = LocalPackage::load(dir.path()).unwrap();
        assert!(matches!(pkg.manifold.net, NetAccess::OutboundHttp(Some(_))));
        assert!(matches!(pkg.manifold.env, EnvAccess::AllowList(_)));
    }

    #[test]
    fn sealed_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let o = ScaffoldOpts {
            name: Some("sealed".into()),
            namespace: Some("acme".into()),
            ..Default::default()
        };
        run_init(Some(dir.path()), &o, None).unwrap();
        let pkg = LocalPackage::load(dir.path()).unwrap();
        assert_eq!(pkg.manifold, Manifold::sealed());
    }

    #[test]
    fn allow_all_opens_everything() {
        let o = ScaffoldOpts {
            allow_all: true,
            ..Default::default()
        };
        let m = manifold_from(&o);
        assert!(matches!(m.net, NetAccess::OutboundFull(None)));
        assert!(matches!(m.env, EnvAccess::Full));
        assert!(m.crypto && m.child_process);
    }

    #[test]
    fn rust_scaffold_uses_edition_2024_and_detached_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let o = ScaffoldOpts {
            name: Some("gadget".into()),
            namespace: Some("acme".into()),
            lang: Some("rust".into()),
            ..Default::default()
        };
        let s = run_init(Some(dir.path()), &o, None).unwrap();
        assert_eq!(s.lang, "rust");
        assert_eq!(s.entry, "source/main.rs");
        assert!(dir.path().join("source/main.rs").exists());
        let cargo = std::fs::read_to_string(dir.path().join("Cargo.toml")).unwrap();
        assert!(
            cargo.contains("edition = \"2024\""),
            "rust scaffold must use edition 2024: {cargo}"
        );
        assert!(
            cargo.contains("[workspace]"),
            "rust scaffold must detach into its own workspace: {cargo}"
        );
        assert!(
            cargo.contains("path = \"source/main.rs\""),
            "rust [[bin]] must point at source/main.rs: {cargo}"
        );
        // afb.toml language + entry agree.
        let pkg = LocalPackage::load(dir.path()).unwrap();
        assert_eq!(pkg.manifest.package.language, "rust");
        assert_eq!(pkg.manifest.package.entry, "source/main.rs");
    }

    #[test]
    fn cpp_scaffold_writes_main_cpp_and_records_language() {
        let dir = tempfile::tempdir().unwrap();
        let o = ScaffoldOpts {
            name: Some("widget".into()),
            namespace: Some("acme".into()),
            lang: Some("cpp".into()),
            ..Default::default()
        };
        let s = run_init(Some(dir.path()), &o, None).unwrap();
        assert_eq!(s.lang, "cpp");
        assert_eq!(s.entry, "source/main.cpp");
        let src = std::fs::read_to_string(dir.path().join("source/main.cpp")).unwrap();
        assert!(src.contains("int main"), "C++ stub must have main: {src}");
        assert!(
            src.contains("std::printf"),
            "C++ stub must use the C++ standard library: {src}"
        );
        let pkg = LocalPackage::load(dir.path()).unwrap();
        assert_eq!(pkg.manifest.package.language, "cpp");
        assert_eq!(pkg.manifest.package.entry, "source/main.cpp");
    }

    #[test]
    fn default_namespace_falls_back_to_login_then_placeholder() {
        let o = ScaffoldOpts {
            name: Some("widget".into()),
            ..Default::default()
        };
        let (ns, _, ph) = resolve_coords(None, &o, None, Some("alice")).unwrap();
        assert_eq!(ns, "alice");
        assert!(!ph);

        let (ns2, _, ph2) = resolve_coords(Some("widget"), &o, None, None).unwrap();
        assert_eq!(ns2, PLACEHOLDER_NAMESPACE);
        assert!(ph2);
    }
}
