// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Proves the single-binary offline promise for `embed-core` + `embed-ruby`:
//! with both features baked into the `burn` binary, a Python AND a Ruby
//! script both run from an EMPTY runtime home with ZERO network access - no
//! prefetch step, no env var, no separate init phase. The embedded bytes
//! self-materialize into the runtime cache automatically, on first use (see
//! `afterburner_wasi::pyodide_embed::materialize_core` /
//! `afterburner_wasi::ruby_embed::materialize_core`, invoked from
//! `afterburner_wasi::bundle::ensure_pyodide_bundle` /
//! `ensure_ruby_bundle` when the network fetch fails).
//!
//! "No network" is simulated with a Linux network namespace (`unshare --net
//! --map-root-user`): an unprivileged user namespace mapped to root, plus a
//! fresh net namespace carrying only a DOWN loopback interface - no route, no
//! resolver. A connect attempt fails in milliseconds (a DNS/route lookup
//! error, not a black-hole hang), so this is both a realistic "container
//! with no network" simulation and a fast one. Requires unprivileged user
//! namespaces (`CONFIG_USER_NS`); some hardened kernels/containers disable
//! them (`kernel.unprivileged_userns_clone=0`) or lack the `unshare` binary
//! entirely (non-Linux). When unavailable, every test here SKIPS LOUDLY
//! (prints exactly why) instead of silently passing OR failing the suite
//! over an environment gap it did not create.
//!
//! Only compiled when `embed-core` + `embed-ruby` are enabled - the default
//! feature set has nothing embedded to prove offline, so these tests would
//! be vacuous there (the lazy `~/.burn` fetch is covered separately by
//! `polyglot_run_source.rs`'s honest run-or-skip tests).

#![cfg(all(feature = "bin", feature = "embed-core", feature = "embed-ruby"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use afterburner_wasi::bundle::{PYODIDE_VERSION, RUBY_RELEASE};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// `None` when this host can create an isolated net+user namespace; `Some(reason)`
/// otherwise, naming exactly why - so a skip is diagnosable, not a shrug.
fn netns_unavailable() -> Option<String> {
    match Command::new("unshare")
        .args(["--net", "--map-root-user", "--", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(o) if o.status.success() => None,
        Ok(o) => Some(format!(
            "`unshare --net --map-root-user` exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Some(format!("`unshare` is not runnable on this host: {e}")),
    }
}

fn fresh_home(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("burn_embed_offline_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir fresh home");
    dir
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write script");
    path
}

/// Run `burn run <script>` inside a fresh, network-less namespace with
/// `BURN_HOME` pointed at `home`. Wrapped in the `timeout` coreutil as a hard
/// backstop: this test's entire premise is "fails fast, never hangs"; a
/// generous 180s covers a debug-profile Cranelift compile of the embedded
/// wasm (materially slower than the release profile this was verified
/// against) without letting a genuine regression wedge CI.
fn run_offline(home: &Path, script: &Path) -> std::process::Output {
    Command::new("timeout")
        .args(["180", "unshare", "--net", "--map-root-user", "--"])
        .arg(BURN)
        .arg("run")
        .arg(script)
        .env("BURN_HOME", home)
        .env("BURN_QUIET", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn timeout+unshare+burn")
}

#[test]
fn python_runs_offline_from_empty_home_via_embedded_core() {
    if let Some(reason) = netns_unavailable() {
        eprintln!(
            "[embed_offline] SKIP python_runs_offline_from_empty_home_via_embedded_core: \
             cannot isolate network on this host ({reason}); the embed-core offline path is \
             UNVERIFIED by this run (not proven broken - just not checked here)."
        );
        return;
    }
    let home = fresh_home("py");
    let script = write_script(
        &home,
        "hello.py",
        "print('hello from embedded python, ' + str(6 * 7))\n",
    );

    let out = run_offline(&home, &script);
    assert!(
        out.status.success(),
        "burn run hello.py must succeed fully offline; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from embedded python, 42"),
        "stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    // The embedded core materialized into the runtime home under its own
    // steam - BURN_PYTHON_RUNTIME is unset here, so there is no other path
    // that could have produced a working interpreter.
    assert!(
        home.join(format!("pyodide-{PYODIDE_VERSION}/pyodide-exnref.wasm"))
            .exists(),
        "the embedded core must have materialized under BURN_HOME"
    );

    // A wheel the core embed does NOT claim (numpy) fails HONESTLY - a normal
    // Python exception, caught and reported, not a hang or a silent wrong
    // answer. Mirrors pyodide_embed.rs's own documented promise: "print(1+1)
    // works while import numpy offline fails honestly."
    let numpy_script = write_script(
        &home,
        "numpy_check.py",
        "try:\n    import numpy\n    print('numpy imported (unexpected offline)')\n\
         except Exception as e:\n    print('honest failure: ' + type(e).__name__ + ': ' + str(e))\n",
    );
    let numpy_out = run_offline(&home, &numpy_script);
    assert!(
        numpy_out.status.success(),
        "the script itself must run to completion (it catches the import error); stdout={} stderr={}",
        String::from_utf8_lossy(&numpy_out.stdout),
        String::from_utf8_lossy(&numpy_out.stderr)
    );
    let numpy_stdout = String::from_utf8_lossy(&numpy_out.stdout);
    assert!(
        numpy_stdout.contains("honest failure: ModuleNotFoundError"),
        "numpy import must fail with a specific, honest error, not silently succeed: {numpy_stdout}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn ruby_runs_offline_from_empty_home_via_embedded_core() {
    if let Some(reason) = netns_unavailable() {
        eprintln!(
            "[embed_offline] SKIP ruby_runs_offline_from_empty_home_via_embedded_core: \
             cannot isolate network on this host ({reason}); the embed-ruby offline path is \
             UNVERIFIED by this run (not proven broken - just not checked here)."
        );
        return;
    }
    let home = fresh_home("rb");
    let script = write_script(
        &home,
        "hello.rb",
        "puts 'hello from embedded ruby, ' + (6 * 7).to_s\n",
    );

    let out = run_offline(&home, &script);
    assert!(
        out.status.success(),
        "burn run hello.rb must succeed fully offline; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello from embedded ruby, 42"),
        "stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        home.join(format!("ruby-{RUBY_RELEASE}/ruby.wasm")).exists(),
        "the embedded ruby.wasm must have materialized under BURN_HOME"
    );

    let _ = std::fs::remove_dir_all(&home);
}
