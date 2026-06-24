// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! Reproduction probe: `import ctypes` / numpy / pandas / polars on Pyodide 314.
//!
//! Drives the real production boot path ([`run_pyodide_with`]) against the
//! stock Pyodide 314 artifacts in /tmp. Set `BURN_PYODIDE_TRACE=1` to see the
//! host-fn trace (`_mmap_js`, `ffi_*`) leading into the MemoryError.
//!
//! Artifacts (stock; produced by the bring-up pipeline):
//!   /tmp/pyodide-314-exnref.wasm                main wasm (exnref-translated)
//!   /tmp/python_stdlib_314.zip                  3.14 stdlib
//!   /tmp/burn_wheels-314.0.0/numpy-...exnref.whl
//!   /tmp/burn_wheels-314.0.0/polars-...exnref.whl
//!
//! Usage:
//!   cargo run -p afterburner-wasi --example ctypes_probe_314 -- ctypes
//!   cargo run -p afterburner-wasi --example ctypes_probe_314 -- numpy
//!   cargo run -p afterburner-wasi --example ctypes_probe_314 -- pandas
//!   cargo run -p afterburner-wasi --example ctypes_probe_314 -- polars

use std::path::PathBuf;

use afterburner_wasi::pyodide_runner::{PyRuntime, run_pyodide_with};

const WASM: &str = "/tmp/pyodide-314-exnref.wasm";
const STDLIB: &str = "/tmp/python_stdlib_314.zip";
const WHEELS_DIR: &str = "/tmp/burn_wheels-314.0.0";

// 0.28.3 (CPython 3.13) non-regression artifacts.
const WASM_028: &str = "/tmp/pyodide-exnref.wasm";
const STDLIB_028: &str = "/tmp/python_stdlib.zip";

/// Build the 314 runtime descriptor for a named wheel set. `set` selects which
/// stock wheels to mount (ctypes itself needs none). numpy's core `.so` is
/// pre-loaded by the boot path, so numpy is listed first where present. Plain
/// `.whl` and `.exnref.whl` are both accepted: the side-module loader translates
/// legacy-EH `.so` to exnref on load, so a stock plain wheel works.
fn rt(set: &str) -> PyRuntime {
    let names: &[&str] = match set {
        "numpy" => &["numpy-2.4.3-cp314-cp314-pyemscripten_2026_0_wasm32.exnref.whl"],
        "polars" => &[
            "numpy-2.4.3-cp314-cp314-pyemscripten_2026_0_wasm32.exnref.whl",
            "polars-1.33.1-cp314-cp314-pyemscripten_2026_0_wasm32.exnref.whl",
        ],
        "pandas" => &[
            "numpy-2.4.3-cp314-cp314-pyemscripten_2026_0_wasm32.exnref.whl",
            "pandas-3.0.2-cp314-cp314-pyemscripten_2026_0_wasm32.whl",
            // pure-Python deps (version-agnostic py2.py3/py3 wheels in /tmp).
        ],
        _ => &[],
    };
    let mut wheels: Vec<PathBuf> = names
        .iter()
        .map(|n| PathBuf::from(WHEELS_DIR).join(n))
        .filter(|p| p.exists())
        .collect();
    if set == "pandas" {
        // python-dateutil (-> six) and pytz are pure-Python; the /tmp copies are
        // ABI-agnostic and serve 314.
        for p in [
            "/tmp/dateutil_check.whl",
            "/tmp/six_check.whl",
            "/tmp/pytz_check.whl",
        ] {
            let pb = PathBuf::from(p);
            if pb.exists() {
                wheels.push(pb);
            }
        }
    }
    PyRuntime {
        wasm_path: PathBuf::from(WASM),
        stdlib_path: PathBuf::from(STDLIB),
        wheels,
        python_xy: "3.14".to_owned(),
    }
}

fn run(label: &str, set: &str, source: &str) {
    println!("=== {label} (314) ===");
    match run_pyodide_with(&rt(set), source) {
        Ok(out) => {
            println!("exit_code = {}", out.exit_code);
            println!("--- stdout ---\n{}", String::from_utf8_lossy(&out.stdout));
        }
        Err(e) => println!("ERROR: {e}"),
    }
    println!();
}

fn main() {
    let which = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ctypes".to_owned());
    match which.as_str() {
        "ctypes" => run(
            "import ctypes",
            "none",
            "import ctypes; print('ctypes OK', ctypes.sizeof(ctypes.c_int))",
        ),
        "numpy" => run(
            "import numpy",
            "numpy",
            "import numpy as np; print('numpy', np.__version__, int(np.arange(5).sum()))",
        ),
        "pandas" => run(
            "import pandas",
            "pandas",
            "import pandas as pd; print('pandas', int(pd.DataFrame({'a':[1,2,3]})['a'].sum()))",
        ),
        "polars" => run(
            "import polars",
            "polars",
            "import polars as pl; print(pl.DataFrame({'a':[1,2,3]}).sum())",
        ),
        // 0.28.3 (CPython 3.13) non-regression: numpy + pandas import + compute.
        "numpy028" => run028(
            "import numpy (0.28.3)",
            &["/tmp/numpy_check.whl"],
            "import numpy as np; print('numpy', np.__version__, int(np.arange(5).sum()))",
        ),
        "pandas028" => run028(
            "import pandas (0.28.3)",
            &[
                "/tmp/numpy_check.whl",
                "/tmp/pandas_check.whl",
                "/tmp/dateutil_check.whl",
                "/tmp/six_check.whl",
                "/tmp/pytz_check.whl",
            ],
            "import pandas as pd; print('pandas', int(pd.DataFrame({'a':[1,2,3]})['a'].sum()))",
        ),
        other => {
            println!("unknown target {other:?}; use ctypes|numpy|pandas|polars|numpy028|pandas028")
        }
    }
}

/// Run a Python source against the 0.28.3 (CPython 3.13) runtime with the given
/// cp313 wheels. Requires `BURN_PYTHON_STDLIB_VER=3.13` (the default).
fn run028(label: &str, wheels: &[&str], source: &str) {
    let rt = PyRuntime {
        wasm_path: PathBuf::from(WASM_028),
        stdlib_path: PathBuf::from(STDLIB_028),
        wheels: wheels
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect(),
        python_xy: "3.13".to_owned(),
    };
    println!("=== {label} ===");
    match run_pyodide_with(&rt, source) {
        Ok(out) => {
            println!("exit_code = {}", out.exit_code);
            println!("--- stdout ---\n{}", String::from_utf8_lossy(&out.stdout));
        }
        Err(e) => println!("ERROR: {e}"),
    }
    println!();
}
