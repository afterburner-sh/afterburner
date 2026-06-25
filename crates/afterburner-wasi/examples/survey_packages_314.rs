// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Import survey over the full Pyodide 314 built-in package set.
//!
//! For every user-facing package in the 314 lockfile, this harness mounts the
//! package's resolved wheel closure, boots a fresh CPython 3.14 interpreter, runs
//! `import <pkg>` plus a one-line smoke op where one is trivially correct, and
//! records PASS or FAIL with the real guest traceback. It then prints an honest
//! X/N total and a failure table grouped by cause.
//!
//! It drives the exact production boot path ([`run_pyodide_with`]) over the stock
//! 314 artifacts; nothing is mocked. The package set, dependency order, and
//! import name all come from a manifest the companion script emits from the
//! lockfile (`scripts/survey_314_manifest.py`), so the survey covers whatever the
//! lockfile ships with no per-package code here.
//!
//! Per-package isolation: the driver forks itself once per package (`--one
//! <name>`). One package that hard-traps the embedder fails only its own child;
//! the run continues. Parallelism is bounded by `BURN_SURVEY_JOBS` (default: the
//! machine's parallelism) to keep wall-clock down while covering the whole set.
//!
//! Usage:
//!   # 1. build the manifest (downloads + exnref-translates wheels, cached)
//!   python3 scripts/survey_314_manifest.py
//!   # 2. run the survey
//!   cargo run --release -p afterburner-wasi --example survey_packages_314
//!
//! Env:
//!   BURN_SURVEY_MANIFEST  manifest path (default /tmp/burn_survey_314.json)
//!   BURN_SURVEY_JOBS      max concurrent package boots (default: ncpu)
//!   BURN_SURVEY_OUT       write the JSON result set here (for the regression test)
//!   BURN_SURVEY_TIMEOUT   per-package wall-clock budget in seconds (default 240)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use afterburner_wasi::pyodide_runner::{PyRuntime, run_pyodide_with};
use serde::{Deserialize, Serialize};

/// One package entry from the manifest the Python builder emits.
#[derive(Debug, Clone, Deserialize)]
struct PkgEntry {
    name: String,
    import_name: String,
    #[serde(default)]
    smoke: String,
    wheels: Vec<String>,
    #[serde(default)]
    has_so: bool,
    #[serde(default)]
    build_error: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    python_xy: String,
    wasm: String,
    stdlib: String,
    packages: Vec<PkgEntry>,
}

/// The outcome of probing one package.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PkgResult {
    name: String,
    import_name: String,
    pass: bool,
    /// Coarse failure bucket (one of [`CATEGORIES`]); empty on PASS.
    category: String,
    /// The concrete cause: the last guest traceback line or the host error.
    reason: String,
    /// Whether the package's wheel closure ships a native `.so` (carried from
    /// the manifest), so the report can split native-extension from pure-Python.
    #[serde(default)]
    has_so: bool,
}

/// Coarse failure buckets, in the order the report groups them.
const CATEGORIES: &[&str] = &[
    "not-in-manifest",
    "build-error",
    "threading",
    "sdl-display",
    "network",
    "so-load",
    "missing-host-fn",
    "missing-dep-module",
    "timeout",
    "other",
];

fn manifest_path() -> PathBuf {
    std::env::var("BURN_SURVEY_MANIFEST")
        .unwrap_or_else(|_| "/tmp/burn_survey_314.json".to_owned())
        .into()
}

fn load_manifest() -> Manifest {
    let p = manifest_path();
    let bytes = std::fs::read(&p).unwrap_or_else(|e| {
        eprintln!(
            "cannot read survey manifest {}: {e}\n\
             build it first: python3 scripts/survey_314_manifest.py",
            p.display()
        );
        std::process::exit(2);
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        eprintln!("manifest {} is not valid JSON: {e}", p.display());
        std::process::exit(2);
    })
}

fn rt_for(m: &Manifest, entry: &PkgEntry) -> PyRuntime {
    PyRuntime {
        wasm_path: PathBuf::from(&m.wasm),
        stdlib_path: PathBuf::from(&m.stdlib),
        wheels: entry.wheels.iter().map(PathBuf::from).collect(),
        python_xy: m.python_xy.clone(),
    }
}

/// Classify a failure from the captured guest output (stdout+stderr) or the host
/// error string. Keyword-driven; the buckets map to the structural gaps the
/// report calls out. The matching is intentionally specific so a real, fixable
/// host-fn gap does not hide in `other`.
fn classify(text: &str) -> (String, String) {
    let lc = text.to_lowercase();
    // The concrete cause = the most informative line: the final Error line of a
    // Python traceback, else the last non-empty line.
    let reason = last_error_line(text);

    let cat = if lc.contains("no module named '_thread'")
        || lc.contains("no module named '_multiprocessing'")
        || lc.contains("can't start new thread")
        || lc.contains("_thread.lock")
        || lc.contains("threading")
            && (lc.contains("not supported") || lc.contains("no module named"))
    {
        "threading"
    } else if lc.contains("libsdl")
        || lc.contains("no available video device")
        || lc.contains("pygame")
            && (lc.contains("display") || lc.contains("video") || lc.contains("sdl"))
        || lc.contains("x display")
        || lc.contains("no module named 'pyodide_js'")
    {
        "sdl-display"
    } else if lc.contains("urlopen error")
        || lc.contains("name or service not known")
        || lc.contains("connection refused")
        || lc.contains("socket") && (lc.contains("not permitted") || lc.contains("operation not"))
        || lc.contains("network is unreachable")
        || lc.contains("getaddrinfo")
    {
        "network"
    } else if lc.contains("dlopen")
        || lc.contains(".so: ")
        || lc.contains("cannot load")
        || lc.contains("undefined symbol")
        || lc.contains("invalid mode for dlopen")
    {
        "so-load"
    } else if lc.contains("function not implemented")
        || lc.contains("not implemented on wasm")
        || lc.contains("oserror") && (lc.contains("[errno 38]") || lc.contains("[errno 52]"))
        || lc.contains("operationnotsupported")
        || lc.contains("__main_argc_argv trapped")
        || lc.contains("run_main trapped")
        || lc.contains("__wasm_call_ctors")
        || lc.contains("memoryerror")
    {
        "missing-host-fn"
    } else if lc.contains("modulenotfounderror") || lc.contains("no module named") {
        // An import error for a *dependency* module not in the closure (the
        // package itself loaded its loader but a sub-import is missing).
        "missing-dep-module"
    } else {
        "other"
    };
    (cat.to_owned(), reason)
}

/// The most informative line of a captured guest output: the final
/// `SomeError: message` line of a Python traceback if present, else the last
/// non-empty line, trimmed to a sane length.
fn last_error_line(text: &str) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    // Walk from the end for the first line that looks like `Word...Error: ...`
    // or a bare exception line.
    let pick = lines
        .iter()
        .rev()
        .find(|l| {
            let t = l.trim_start();
            (t.contains("Error") || t.contains("Exception") || t.contains("error:"))
                && t.contains(':')
        })
        .or_else(|| lines.last())
        .map(|s| s.trim())
        .unwrap_or("");
    let pick = pick.replace(['\n', '\r'], " ");
    if pick.len() > 240 {
        format!("{}...", &pick[..240])
    } else {
        pick
    }
}

/// Probe one package in this process: boot a fresh interpreter, mount its wheel
/// closure, run `import <name>` + smoke, return the result. This is what each
/// child process runs (`--one <name>`).
fn probe_one(m: &Manifest, entry: &PkgEntry) -> PkgResult {
    let mut res = PkgResult {
        name: entry.name.clone(),
        import_name: entry.import_name.clone(),
        pass: false,
        category: String::new(),
        reason: String::new(),
        has_so: entry.has_so,
    };

    if !entry.build_error.is_empty() {
        res.category = "build-error".to_owned();
        res.reason = entry.build_error.clone();
        return res;
    }
    if entry.wheels.is_empty() {
        res.category = "not-in-manifest".to_owned();
        res.reason = "no wheel closure resolved".to_owned();
        return res;
    }

    // The probe source: import the package and print a sentinel; run the smoke op
    // when one is given. The sentinel distinguishes a clean import (printed) from
    // a silent early exit. Any exception prints a traceback to stderr (captured)
    // and yields a nonzero exit code.
    let smoke = if entry.smoke.is_empty() {
        String::new()
    } else {
        format!("\n{}", entry.smoke)
    };
    let source = format!(
        "import {imp}{smoke}\nprint('SURVEY_OK {imp}')\n",
        imp = entry.import_name,
        smoke = smoke,
    );

    let rt = rt_for(m, entry);
    match run_pyodide_with(&rt, &source) {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            let sentinel = format!("SURVEY_OK {}", entry.import_name);
            if out.exit_code == 0 && text.contains(&sentinel) {
                res.pass = true;
            } else {
                let (cat, reason) = classify(&text);
                res.category = cat;
                res.reason = if reason.is_empty() {
                    format!("exit_code={} no traceback captured", out.exit_code)
                } else {
                    reason
                };
            }
        }
        Err(e) => {
            // Host-side error (trap during boot, instantiate, ctors). Classify
            // from the host message.
            let (cat, reason) = classify(&e.to_string());
            res.category = cat;
            res.reason = reason;
        }
    }
    res
}

/// Run one package as a child process and parse its single result line. The
/// child prints exactly one `SURVEYRESULT <json>` line on stdout; a hard trap
/// that aborts the child (no line) is recorded as a timeout/crash by the driver.
fn run_child(self_exe: &str, name: &str, timeout_s: u64) -> Option<PkgResult> {
    let mut cmd = Command::new(self_exe);
    cmd.arg("--one")
        .arg(name)
        .env("BURN_GUEST_ECHO", "1") // capture the real guest traceback
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Some(PkgResult {
                name: name.to_owned(),
                import_name: name.to_owned(),
                category: "other".to_owned(),
                reason: format!("spawn child failed: {e}"),
                ..Default::default()
            });
        }
    };

    // Bounded wait: poll for completion up to the timeout, then kill.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(PkgResult {
                        name: name.to_owned(),
                        import_name: name.to_owned(),
                        category: "timeout".to_owned(),
                        reason: format!("exceeded {timeout_s}s wall-clock budget"),
                        ..Default::default()
                    });
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                return Some(PkgResult {
                    name: name.to_owned(),
                    import_name: name.to_owned(),
                    category: "other".to_owned(),
                    reason: format!("wait child failed: {e}"),
                    ..Default::default()
                });
            }
        }
    }

    let output = child.wait_with_output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(json) = line.strip_prefix("SURVEYRESULT ")
            && let Ok(r) = serde_json::from_str::<PkgResult>(json)
        {
            return Some(r);
        }
    }
    // No structured line: the child crashed (trap aborted the process). The
    // child mirrors the guest output via BURN_GUEST_ECHO to its stderr; surface
    // the last informative line so the cause is not lost.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let (cat, reason) = classify(&stderr);
    Some(PkgResult {
        name: name.to_owned(),
        import_name: name.to_owned(),
        category: if cat == "other" {
            "missing-host-fn".to_owned()
        } else {
            cat
        },
        reason: if reason.is_empty() {
            format!(
                "child crashed (exit {:?}) with no result line",
                output.status.code()
            )
        } else {
            format!("child crashed: {reason}")
        },
        ..Default::default()
    })
}

fn jobs() -> usize {
    std::env::var("BURN_SURVEY_JOBS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
}

fn timeout_s() -> u64 {
    std::env::var("BURN_SURVEY_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n: &u64| n > 0)
        .unwrap_or(240)
}

/// Print the honest report and write the JSON result set if requested.
fn report(results: &[PkgResult]) {
    let total = results.len();
    let passed = results.iter().filter(|r| r.pass).count();
    let failed = total - passed;

    // Native-extension vs pure-Python split: the structural gaps almost all live
    // in the native-extension set, so the breakdown sizes the real surface.
    let so_total = results.iter().filter(|r| r.has_so).count();
    let so_pass = results.iter().filter(|r| r.has_so && r.pass).count();
    let py_total = total - so_total;
    let py_pass = passed - so_pass;

    println!("\n========================================");
    println!("Pyodide 314 import survey");
    println!("========================================");
    println!("import OK : {passed}/{total}");
    println!("failed    : {failed}/{total}");
    println!("  native-extension (.so): {so_pass}/{so_total} import OK");
    println!("  pure-Python           : {py_pass}/{py_total} import OK");

    if failed > 0 {
        println!("\n---- failures by cause ----");
        for cat in CATEGORIES {
            let group: Vec<&PkgResult> = results
                .iter()
                .filter(|r| !r.pass && r.category == *cat)
                .collect();
            if group.is_empty() {
                continue;
            }
            println!("\n[{}]  ({} package(s))", cat, group.len());
            for r in group {
                println!("  {:<28} {}", r.name, r.reason);
            }
        }
    }

    println!("\n---- known-good (passed) ----");
    let mut good: Vec<&str> = results
        .iter()
        .filter(|r| r.pass)
        .map(|r| r.import_name.as_str())
        .collect();
    good.sort_unstable();
    println!("{}", good.join(" "));

    if let Ok(out) = std::env::var("BURN_SURVEY_OUT") {
        match serde_json::to_vec_pretty(results) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&out, bytes) {
                    eprintln!("could not write {out}: {e}");
                } else {
                    println!("\nresult set written to {out}");
                }
            }
            Err(e) => eprintln!("serialize results: {e}"),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Child mode: probe exactly one package and print a structured result line.
    if let Some(pos) = args.iter().position(|a| a == "--one") {
        let name = args.get(pos + 1).cloned().unwrap_or_default();
        let m = load_manifest();
        let entry = m.packages.iter().find(|p| p.name == name);
        let res = match entry {
            Some(e) => probe_one(&m, e),
            None => PkgResult {
                name: name.clone(),
                import_name: name.clone(),
                category: "not-in-manifest".to_owned(),
                reason: "package not present in manifest".to_owned(),
                ..Default::default()
            },
        };
        // One machine-readable line for the driver; human echo on stderr.
        match serde_json::to_string(&res) {
            Ok(j) => println!("SURVEYRESULT {j}"),
            Err(e) => eprintln!("serialize result: {e}"),
        }
        eprintln!(
            "[{}] {} {}",
            if res.pass { "PASS" } else { "FAIL" },
            res.name,
            if res.pass {
                String::new()
            } else {
                format!("({}) {}", res.category, res.reason)
            },
        );
        return;
    }

    // Driver mode: fork one child per package, bounded concurrency.
    let m = load_manifest();
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| args[0].clone());
    let total = m.packages.len();
    let jobs = jobs();
    let to = timeout_s();
    eprintln!(
        "surveying {total} packages, {jobs} concurrent, {to}s/pkg timeout\n  wasm={}\n  stdlib={}",
        m.wasm, m.stdlib
    );

    let names: Vec<String> = m.packages.iter().map(|p| p.name.clone()).collect();
    let next = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(std::sync::Mutex::new(Vec::<PkgResult>::with_capacity(
        total,
    )));

    std::thread::scope(|scope| {
        for _ in 0..jobs {
            let next = Arc::clone(&next);
            let done = Arc::clone(&done);
            let results = Arc::clone(&results);
            let names = &names;
            let self_exe = self_exe.as_str();
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= names.len() {
                        break;
                    }
                    let name = &names[i];
                    let r = run_child(self_exe, name, to).unwrap_or_else(|| PkgResult {
                        name: name.clone(),
                        import_name: name.clone(),
                        category: "other".to_owned(),
                        reason: "no result from child".to_owned(),
                        ..Default::default()
                    });
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    eprintln!(
                        "[{d}/{total}] {} {}",
                        if r.pass { "PASS" } else { "FAIL" },
                        r.name
                    );
                    results.lock().unwrap().push(r);
                }
            });
        }
    });

    let mut results = Arc::try_unwrap(results)
        .map(|m| m.into_inner().unwrap())
        .unwrap_or_default();
    results.sort_by_key(|r| r.name.to_lowercase());

    // Group counts for a quick machine-readable summary on stderr.
    let mut by_cat: BTreeMap<String, usize> = BTreeMap::new();
    for r in &results {
        if !r.pass {
            *by_cat.entry(r.category.clone()).or_insert(0) += 1;
        }
    }
    report(&results);
    eprintln!("\ncategory counts: {by_cat:?}");
}
