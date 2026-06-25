#!/usr/bin/env python3
"""Build the package-survey manifest for the Pyodide 314 built-in package set.

For every user-facing package in Pyodide's `pyodide-lock.json` (the non-test
`package`-type entries), resolve its full transitive dependency closure, download
each wheel, translate every side-module `.so` from legacy-EH to exnref (the
engine runs the exnref proposal), and emit a JSON manifest the Rust survey
harness consumes. The harness boots each package in isolation and records a
PASS/FAIL with the real guest traceback.

There is no per-package logic: the wheel set, dependency order, and import name
all come from the lockfile (data), so the survey covers whatever the lockfile
ships. Wheels are cached under WHEEL_DIR so re-runs do not re-download.

Usage:
    scripts/survey_314_manifest.py                 # full set -> MANIFEST
    scripts/survey_314_manifest.py --limit 20      # first 20 (smoke)
    scripts/survey_314_manifest.py --only numpy,pandas,polars
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

PYODIDE_VER = os.environ.get("PYODIDE_VER", "314.0.0")
MAJOR = PYODIDE_VER.split(".")[0]
CDN = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VER}/full"
LOCK = f"/tmp/pyodide-lock-{PYODIDE_VER}.json"
WHEEL_DIR = f"/tmp/burn_wheels-{PYODIDE_VER}"
WASM = os.environ.get("BURN_PROBE_WASM", f"/tmp/pyodide-{MAJOR}-exnref.wasm")
# The bring-up wrote the 314 stdlib as python_stdlib_314.zip; load_pkg.py uses a
# dash variant. Accept either so we reuse whichever already exists.
STDLIB_CANDIDATES = [
    f"/tmp/python_stdlib_{MAJOR}.zip",
    f"/tmp/python_stdlib-{PYODIDE_VER}.zip",
]
MANIFEST = os.environ.get("BURN_SURVEY_MANIFEST", "/tmp/burn_survey_314.json")
AFTERBURNER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

WASM_OPT_FLAGS = [
    "--translate-to-exnref", "--enable-exception-handling",
    "--enable-reference-types", "--enable-bulk-memory", "--enable-simd",
    "--enable-sign-ext", "--enable-nontrapping-float-to-int",
    "--enable-mutable-globals", "--enable-multivalue",
]


def wasm_opt():
    return shutil.which("wasm-opt") or os.path.expanduser(
        "~/emsdk/upstream/bin/wasm-opt"
    )


def load_lock():
    if not os.path.exists(LOCK):
        urllib.request.urlretrieve(f"{CDN}/pyodide-lock.json", LOCK)
    return json.load(open(LOCK))


def python_xy(lock):
    full = lock.get("info", {}).get("python", "3.14.0")
    parts = full.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else "3.14"


def ensure_stdlib():
    for c in STDLIB_CANDIDATES:
        if os.path.exists(c):
            return c
    dst = STDLIB_CANDIDATES[0]
    urllib.request.urlretrieve(f"{CDN}/python_stdlib.zip", dst)
    return dst


def norm(name):
    return name.lower().replace("_", "-")


def resolve_closure(pkgs, root):
    """Post-order DFS over `depends`: deps come before dependents (load order)."""
    by_norm = {norm(p["name"]): p for p in pkgs.values()}
    seen, order = set(), []

    def visit(name):
        p = pkgs.get(name) or by_norm.get(norm(name))
        if not p or p["name"] in seen:
            return
        seen.add(p["name"])
        for dep in p.get("depends", []):
            visit(dep)
        order.append(p)

    visit(root)
    return order


def download(p):
    dst = os.path.join(WHEEL_DIR, p["file_name"])
    if not os.path.exists(dst):
        os.makedirs(WHEEL_DIR, exist_ok=True)
        urllib.request.urlretrieve(f"{CDN}/{p['file_name']}", dst)
    return dst


def exnref_wheel(wheel_path):
    """Repackage a wheel with every `.so` translated legacy-EH -> exnref (cached).

    A pure-Python wheel (no `.so`) is returned unchanged. A `.so` that wasm-opt
    cannot translate raises, and the caller records the package as a build
    failure rather than silently shipping a broken wheel.
    """
    if not wheel_path.endswith(".whl"):
        return wheel_path
    out = wheel_path[:-4] + ".exnref.whl"
    if os.path.exists(out):
        return out
    with zipfile.ZipFile(wheel_path) as zin:
        sos = [n for n in zin.namelist() if n.endswith(".so")]
        if not sos:
            return wheel_path
        work = wheel_path + ".d"
        if os.path.exists(work):
            shutil.rmtree(work)
        zin.extractall(work)
    for so in sos:
        p = os.path.join(work, so)
        subprocess.run([wasm_opt(), *WASM_OPT_FLAGS, p, "-o", p], check=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for r, _, files in os.walk(work):
            for f in sorted(files):
                fp = os.path.join(r, f)
                zo.write(fp, os.path.relpath(fp, work))
    shutil.rmtree(work)
    return out


def wheel_has_so(wheel_path):
    if not wheel_path.endswith(".whl") or not os.path.exists(wheel_path):
        return False
    try:
        with zipfile.ZipFile(wheel_path) as z:
            return any(n.endswith(".so") for n in z.namelist())
    except zipfile.BadZipFile:
        return False


def canonical_import(name, imports):
    """The import name to probe for a package.

    The lockfile's `imports[]` often lists a private C-extension or a console
    script before the public top-level package (e.g. sympy -> ['isympy','sympy'],
    pyyaml -> ['_yaml','yaml']). Prefer, in order: the entry whose normalized form
    equals the package name; the first public (non-underscore) entry; the last
    entry; finally the normalized package name. This picks the module a user
    actually writes `import X` for.
    """
    if not imports:
        return norm(name).replace("-", "_")
    nn = norm(name).replace("-", "_")
    for imp in imports:
        if imp.lower().replace("-", "_") == nn:
            return imp
    public = [imp for imp in imports if not imp.startswith("_")]
    if public:
        return public[-1]
    return imports[-1]


def smoke_for(name, imports):
    """A one-line smoke op for a handful of common libs; otherwise empty.

    Kept deliberately tiny: the survey's contract is `import`, and a smoke op is
    a bonus only where it is trivially correct. Unknown packages get no smoke op
    (the harness then asserts import alone).
    """
    top = canonical_import(name, imports)
    table = {
        "numpy": "import numpy as np; assert int(np.arange(5).sum())==10",
        "pandas": "import pandas as pd; assert int(pd.DataFrame({'a':[1,2,3]})['a'].sum())==6",
        "polars": "import polars as pl; assert pl.DataFrame({'a':[1,2,3]})['a'].sum()==6",
        "sympy": "import sympy; assert str(sympy.sympify('x+x'))=='2*x'",
        "scipy": "import scipy; assert hasattr(scipy,'__version__')",
        "sklearn": "import sklearn; assert hasattr(sklearn,'__version__')",
    }
    return table.get(top, "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only", default="")
    ap.add_argument("--no-build", action="store_true",
                    help="emit manifest only for already-cached wheels")
    args = ap.parse_args()

    lock = load_lock()
    pkgs = lock["packages"]
    py_xy = python_xy(lock)
    stdlib = ensure_stdlib()

    # User-facing set: package-type 'package', excluding the unvendored -tests
    # suites (those are test code for a library, not the library).
    def is_test_pkg(p):
        n = p["name"]
        return n.endswith("-tests") or n.endswith("_tests")

    user = [
        p for p in pkgs.values()
        if p.get("package_type") == "package" and not is_test_pkg(p)
    ]
    user.sort(key=lambda p: p["name"].lower())

    if args.only:
        want = {norm(x) for x in args.only.split(",") if x}
        user = [p for p in user if norm(p["name"]) in want]
    if args.limit:
        user = user[: args.limit]

    entries = []
    n = len(user)
    for i, p in enumerate(user, 1):
        name = p["name"]
        imports = p.get("imports", [])
        print(f"[{i}/{n}] {name} ...", flush=True)
        record = {
            "name": name,
            "import_name": canonical_import(name, imports),
            "imports": imports,
            "smoke": smoke_for(name, imports),
            "wheels": [],
            "has_so": False,
            "build_error": "",
        }
        try:
            closure = resolve_closure(pkgs, name)
            wheels = []
            has_so = False
            for dep in closure:
                raw = download(dep)
                if wheel_has_so(raw):
                    has_so = True
                if args.no_build:
                    # Use a cached exnref wheel if present, else the raw wheel.
                    cand = raw[:-4] + ".exnref.whl"
                    wheels.append(cand if os.path.exists(cand) else raw)
                else:
                    wheels.append(exnref_wheel(raw))
            record["wheels"] = wheels
            record["has_so"] = has_so
        except Exception as e:  # noqa: BLE001 - record build failure honestly
            record["build_error"] = f"{type(e).__name__}: {e}"
            print(f"      BUILD-FAIL: {record['build_error']}", flush=True)
        entries.append(record)

    manifest = {
        "pyodide_version": PYODIDE_VER,
        "python_xy": py_xy,
        "wasm": WASM,
        "stdlib": stdlib,
        "count": len(entries),
        "packages": entries,
    }
    with open(MANIFEST, "w") as f:
        json.dump(manifest, f, indent=1)
    built = sum(1 for e in entries if e["wheels"] and not e["build_error"])
    print(f"\nmanifest: {MANIFEST}")
    print(f"  {built}/{len(entries)} packages have a resolved wheel set")
    print(f"  wasm={WASM}")
    print(f"  stdlib={stdlib}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
