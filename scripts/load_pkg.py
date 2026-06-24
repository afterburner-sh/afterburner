#!/usr/bin/env python3
"""Generic, data-driven Pyodide package loader for the afterburner import probe.

Given a package NAME, resolve its full transitive dependency closure from
Pyodide's `pyodide-lock.json`, download the wheels, and run the afterburner
import probe (`pandas_import_probe`) with `BURN_WHEELS`/`BURN_PY_CODE`. There is
no per-package code anywhere: adding a library is just passing its name. The
runtime loads every side-module `.so` generically via on-demand dlopen.

Usage:
    scripts/load_pkg.py <package> [python-code]
    scripts/load_pkg.py --resolve-only <package>   # print wheel set, no probe run
"""
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile

PYODIDE_VER = "0.28.3"
CDN = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VER}/full"
LOCK = "/tmp/pyodide-lock.json"
WHEEL_DIR = "/tmp/burn_wheels"
PROBE_WASM = "/tmp/pyodide-exnref.wasm"
AFTERBURNER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_lock():
    if not os.path.exists(LOCK):
        urllib.request.urlretrieve(f"{CDN}/pyodide-lock.json", LOCK)
    return json.load(open(LOCK))["packages"]


def resolve_closure(pkgs, root):
    # Post-order DFS over `depends`: dependencies come before their dependents.
    by_norm = {p["name"].lower().replace("_", "-"): p for p in pkgs.values()}
    seen, order = set(), []

    def visit(name):
        p = pkgs.get(name) or by_norm.get(name.lower().replace("_", "-"))
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


WASM_OPT_FLAGS = [
    "--translate-to-exnref", "--enable-exception-handling",
    "--enable-reference-types", "--enable-bulk-memory", "--enable-simd",
    "--enable-sign-ext", "--enable-nontrapping-float-to-int",
    "--enable-mutable-globals", "--enable-multivalue",
]


def _wasm_opt():
    return shutil.which("wasm-opt") or os.path.expanduser("~/emsdk/upstream/bin/wasm-opt")


def exnref_wheel(wheel_path):
    """Repackage a wheel with every .so translated legacy-EH -> exnref (cached).

    Stock wheels ship side-module .so built with legacy try/catch EH; the engine
    runs exnref. `wasm-opt --translate-to-exnref` converts them while preserving
    the side-module structure (dylink.0, GOT imports, element/data segments). A
    pure-Python wheel (no .so) is returned unchanged.
    """
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
        subprocess.run([_wasm_opt(), *WASM_OPT_FLAGS, p, "-o", p], check=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for root, _, files in os.walk(work):
            for f in sorted(files):
                fp = os.path.join(root, f)
                zo.write(fp, os.path.relpath(fp, work))
    shutil.rmtree(work)
    print(f"  exnref: {os.path.basename(wheel_path)} ({len(sos)} .so)")
    return out


def main():
    args = [a for a in sys.argv[1:] if a != "--resolve-only"]
    resolve_only = "--resolve-only" in sys.argv[1:]
    if not args:
        print("usage: load_pkg.py [--resolve-only] <package> [python-code]")
        return 2
    pkg = args[0]
    code = args[1] if len(args) > 1 else f"import {pkg.replace('-', '_')}; print('{pkg} OK')"

    pkgs = load_lock()
    closure = resolve_closure(pkgs, pkg)
    if not closure:
        print(f"{pkg}: not found in lock")
        return 1
    wheels = [exnref_wheel(download(p)) for p in closure]
    print(f"{pkg}: {len(closure)} wheels -> {[p['name'] for p in closure]}")
    if resolve_only:
        print("BURN_WHEELS=" + ",".join(wheels))
        return 0

    code_file = "/tmp/burn_pycode.py"
    open(code_file, "w").write(code)
    env = dict(
        os.environ,
        BURN_WHEELS=",".join(wheels),
        BURN_PY_CODE=code_file,
        BURN_PROBE_WASM=PROBE_WASM,
    )
    return subprocess.run(
        ["cargo", "run", "-q", "-p", "afterburner-wasi", "--example", "pandas_import_probe"],
        cwd=AFTERBURNER,
        env=env,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
