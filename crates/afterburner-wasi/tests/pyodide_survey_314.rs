// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Regression test over the known-good Pyodide 314 package set.
//!
//! This is the committed guard for the import survey: each package listed in
//! [`KNOWN_GOOD`] imported (and, where a smoke op is given, computed) on the real
//! CPython 3.14 runtime when the survey last ran. The list is the *passing*
//! subset only, so a regression (a package that used to import and now traps)
//! turns this test red. Nothing here asserts a package that genuinely cannot
//! run, so the test never goes red on purpose.
//!
//! ## Survey result (267 / 287 import OK)
//!
//! Of the 287 non-test, package-type entries in the Pyodide 314 lockfile, 267
//! import (165/177 native-extension, 102/110 pure-Python). The 20 known-
//! unsupported packages and the reason each cannot import here (so this list is
//! deliberately *not* in [`KNOWN_GOOD`]):
//!
//! Browser `js` bridge (no JS runtime on this embedder; structural):
//!   requests, urllib3, httpx, openai, pyarrow, blosc2, pytest_httpx,
//!   pyodide-unix-timezones -- all `ModuleNotFoundError: No module named 'js'`.
//!
//! Native traps inside a translated `.so` (per-package native-EH / symbol
//! mismatch; structural):
//!   pymongo, RobotRaconteur.
//!
//! Package-specific native quirks:
//!   Cartopy   -- tempfile rejects MEMFS /tmp after a writability probe.
//!   rebound   -- dlsym for data symbol `reb_version_str` not exposed.
//!   reboundx  -- dlsym for data symbol `rebx_version_str` not exposed.
//!   rasterio  -- GDAL reports no version string (stubbed env).
//!   fiona     -- same GDAL-version-string root as rasterio.
//!   h5py      -- HDF5 C-API surface `set_fields` not exposed by the .so.
//!   casadi    -- unset value during the import-time plugin scan.
//!   matplotlib-inline -- exits during import with no Python-level traceback.
//!
//! Bounded by time, not capability:
//!   coolprop  -- import-time table build exceeds the 300s survey budget.
//!
//! The fuller writeup (the four runtime gaps fixed during the survey and the
//! structural-gap recommendation) is in `docs/PYTHON_PACKAGE_SURVEY_314.md`.
//!
//! The harness that produced [`KNOWN_GOOD`] is
//! `examples/survey_packages_314.rs`; regenerate the list by re-running it
//! (see that file's header) after a runtime change that lifts the count.
//!
//! ## Why `#[ignore]`
//!
//! Like the rest of `pyodide_integration.rs`, these tests:
//!   1. fetch wheels from the CDN and boot CPython (network + minutes of compile),
//!   2. need the stock 314 artifacts (`/tmp/pyodide-314-exnref.wasm`, the 3.14
//!      stdlib, the survey manifest) that CI machines do not carry by default.
//!
//! They skip-with-a-message when those are absent, so a missing artifact is a
//! SKIP, not a failure. Run on demand:
//!
//! ```text
//! python3 scripts/survey_314_manifest.py            # build the manifest first
//! cargo test --release -p afterburner-wasi \
//!   --test pyodide_survey_314 -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use afterburner_wasi::pyodide_runner::{PyRuntime, run_pyodide_with};
use serde::Deserialize;

/// The manifest path the survey builder writes (override with the same env var).
fn manifest_path() -> PathBuf {
    std::env::var("BURN_SURVEY_MANIFEST")
        .unwrap_or_else(|_| "/tmp/burn_survey_314.json".to_owned())
        .into()
}

#[derive(Debug, Clone, Deserialize)]
struct PkgEntry {
    name: String,
    import_name: String,
    #[serde(default)]
    smoke: String,
    wheels: Vec<String>,
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

fn load_manifest() -> Option<Manifest> {
    let p = manifest_path();
    let bytes = std::fs::read(&p).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The known-good set: every package the 314 survey reported as `import OK`.
///
/// Generated from the survey result set (`BURN_SURVEY_OUT`); keep it sorted by
/// the lockfile package name. Each entry is asserted to import (and smoke-op
/// where the manifest provides one) on the live runtime.
///
/// SURVEY-RESULT: filled from a real run of `survey_packages_314`. Do not hand
/// edit to add a package the survey did not pass.
const KNOWN_GOOD: &[&str] = &[
    "affine",
    "aiohappyeyeballs",
    "aiohttp",
    "aiosignal",
    "altair",
    "annotated-doc",
    "annotated-types",
    "anyio",
    "apsw",
    "argon2-cffi",
    "argon2-cffi-bindings",
    "astropy",
    "astropy_iers_data",
    "asttokens",
    "async-timeout",
    "atomicwrites",
    "attrs",
    "audioop-lts",
    "awkward-cpp",
    "b2d",
    "bcrypt",
    "beautifulsoup4",
    "bilby.cython",
    "biopython",
    "bitarray",
    "bitstring",
    "bleach",
    "bokeh",
    "boost-histogram",
    "Bottleneck",
    "brotli",
    "cachetools",
    "cbor-diag",
    "certifi",
    "cffi",
    "cffi_example",
    "cftime",
    "charset-normalizer",
    "clarabel",
    "click",
    "cligj",
    "clingo",
    "cloudpickle",
    "cmyt",
    "cobs",
    "colorspacious",
    "contourpy",
    "coverage",
    "crc32c",
    "crcmod",
    "cryptography",
    "cssselect",
    "cvxpy-base",
    "cycler",
    "cysignals",
    "cytoolz",
    "decorator",
    "demes",
    "deprecated",
    "deprecation",
    "diskcache",
    "distlib",
    "distro",
    "dnspython",
    "docutils",
    "donfig",
    "duckdb",
    "ewah_bool_utils",
    "exceptiongroup",
    "executing",
    "fastapi",
    "fastcan",
    "fonttools",
    "freesasa",
    "frozenlist",
    "fsspec",
    "future",
    "galpy",
    "geopandas",
    "gmpy2",
    "google-crc32c",
    "gsw",
    "h11",
    "h3",
    "highspy",
    "html5lib",
    "httpcore",
    "idna",
    "igraph",
    "imageio",
    "iminuit",
    "iniconfig",
    "ipython",
    "jedi",
    "Jinja2",
    "jiter",
    "joblib",
    "jsonpatch",
    "jsonpointer",
    "jsonschema",
    "jsonschema_specifications",
    "kiwisolver",
    "lakers-python",
    "lazy-object-proxy",
    "lazy_loader",
    "libcst",
    "librt",
    "lightgbm",
    "logbook",
    "lxml",
    "lz4",
    "MarkupSafe",
    "matplotlib",
    "memory-allocator",
    "micropip",
    "ml_dtypes",
    "mmh3",
    "more-itertools",
    "mpmath",
    "msgpack",
    "msgspec",
    "msprime",
    "multidict",
    "munch",
    "mypy",
    "narwhals",
    "ndindex",
    "netcdf4",
    "networkx",
    "newick",
    "nh3",
    "nlopt",
    "nltk",
    "numcodecs",
    "numpy",
    "opencv-python",
    "optlang",
    "orjson",
    "packaging",
    "pandas",
    "parso",
    "patsy",
    "pcodec",
    "peewee",
    "phispy",
    "pi-heif",
    "Pillow",
    "pillow-heif",
    "pkgconfig",
    "platformdirs",
    "pluggy",
    "ply",
    "polars",
    "prompt_toolkit",
    "propcache",
    "protobuf",
    "pure-eval",
    "py",
    "pyclipper",
    "pycparser",
    "pycryptodome",
    "pydantic",
    "pydantic_core",
    "pydoc_data",
    "pyerfa",
    "pygame-ce",
    "Pygments",
    "pyheif",
    "pyiceberg",
    "pyinstrument",
    "PyMuPDF",
    "pynacl",
    "pyodide-http",
    "pyparsing",
    "pyproj",
    "pyroaring",
    "pyrodigal",
    "pyrsistent",
    "pysam",
    "pyshp",
    "pytaglib",
    "pytest",
    "pytest-asyncio",
    "pytest-benchmark",
    "python-calamine",
    "python-dateutil",
    "python-flint",
    "python-flirt",
    "python-sat",
    "python-solvespace",
    "pytz",
    "pywavelets",
    "pyxirr",
    "pyyaml",
    "rateslib",
    "referencing",
    "regex",
    "retrying",
    "rich",
    "rpds-py",
    "ruamel.yaml",
    "safetensors",
    "scikit-image",
    "scikit-learn",
    "scipy",
    "screed",
    "sentencepiece",
    "setuptools",
    "shapely",
    "simplejson",
    "sisl",
    "six",
    "smart-open",
    "sniffio",
    "sortedcontainers",
    "soundfile",
    "sourmash",
    "soxr",
    "sparseqr",
    "sqlalchemy",
    "stack-data",
    "starlette",
    "statsmodels",
    "strictyaml",
    "svgwrite",
    "swiglpk",
    "sympy",
    "tblib",
    "termcolor",
    "texttable",
    "texture2ddecoder",
    "threadpoolctl",
    "tiktoken",
    "tomli",
    "tomli-w",
    "toolz",
    "tqdm",
    "traitlets",
    "traits",
    "tree-sitter",
    "tree-sitter-go",
    "tree-sitter-java",
    "tree-sitter-python",
    "tskit",
    "typing-extensions",
    "typing-inspection",
    "tzdata",
    "ujson",
    "uncertainties",
    "unyt",
    "vega-datasets",
    "vrplib",
    "wcwidth",
    "webencodings",
    "wordcloud",
    "wrapt",
    "xarray",
    "xgboost",
    "xlrd",
    "xxhash",
    "xyzservices",
    "yarl",
    "yt",
    "zarr",
    "zengl",
    "zfpy",
    "zstandard",
];

/// Boot one package by its manifest entry and assert it imports + smokes. Panics
/// (fails the test) on any non-clean outcome, with the guest traceback inlined.
fn assert_imports(m: &Manifest, entry: &PkgEntry) {
    assert!(
        entry.build_error.is_empty(),
        "{}: wheel build failed in the manifest: {}",
        entry.name,
        entry.build_error
    );
    assert!(
        !entry.wheels.is_empty(),
        "{}: no wheel closure in the manifest",
        entry.name
    );

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
    let rt = PyRuntime {
        wasm_path: PathBuf::from(&m.wasm),
        stdlib_path: PathBuf::from(&m.stdlib),
        wheels: entry.wheels.iter().map(PathBuf::from).collect(),
        python_xy: m.python_xy.clone(),
    };
    let out = run_pyodide_with(&rt, &source)
        .unwrap_or_else(|e| panic!("{}: host error booting runtime: {e}", entry.name));
    let text = String::from_utf8_lossy(&out.stdout);
    let sentinel = format!("SURVEY_OK {}", entry.import_name);
    assert!(
        out.exit_code == 0 && text.contains(&sentinel),
        "{} regressed: import/smoke did not complete cleanly \
         (exit_code={}). Guest output:\n{}",
        entry.name,
        out.exit_code,
        text
    );
}

/// Every known-good package still imports on the live 314 runtime.
///
/// Skips (does not fail) when the survey manifest or the wasm runtime is absent,
/// matching the rest of `pyodide_integration.rs`.
#[test]
#[ignore = "fetches wheels + boots CPython 3.14; needs the survey manifest in /tmp"]
fn known_good_packages_still_import() {
    let Some(m) = load_manifest() else {
        eprintln!(
            "[pyodide_survey_314] SKIP: survey manifest {} not found; \
             build it with scripts/survey_314_manifest.py",
            manifest_path().display()
        );
        return;
    };
    if !Path::new(&m.wasm).exists() {
        eprintln!(
            "[pyodide_survey_314] SKIP: runtime wasm {} not found",
            m.wasm
        );
        return;
    }
    if KNOWN_GOOD.is_empty() {
        eprintln!("[pyodide_survey_314] SKIP: KNOWN_GOOD list is empty (survey not yet run)");
        return;
    }

    let by_name: BTreeMap<&str, &PkgEntry> =
        m.packages.iter().map(|p| (p.name.as_str(), p)).collect();

    let mut missing = Vec::new();
    let mut failures = Vec::new();
    for &name in KNOWN_GOOD {
        match by_name.get(name) {
            Some(entry) => {
                // Capture a panic so one regression does not hide the rest: run
                // every known-good package, then report the full set that broke.
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    assert_imports(&m, entry)
                }));
                if let Err(e) = r {
                    let msg = e
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                        .unwrap_or_else(|| "panic".to_owned());
                    failures.push(format!("{name}: {msg}"));
                }
            }
            None => missing.push(name),
        }
    }

    assert!(
        missing.is_empty(),
        "known-good packages absent from the manifest (rebuild it): {missing:?}"
    );
    assert!(
        failures.is_empty(),
        "{} known-good package(s) regressed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
