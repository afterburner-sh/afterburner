#!/usr/bin/env python3
"""Turn a survey result set (BURN_SURVEY_OUT JSON) into the two committed
artifacts: the KNOWN_GOOD Rust list (for the regression test) and a Markdown
failure table grouped by cause (for the survey doc).

Usage:
    scripts/survey_314_emit.py /tmp/burn_survey_314_results.json
    scripts/survey_314_emit.py /tmp/burn_survey_314_results.json --rust
    scripts/survey_314_emit.py /tmp/burn_survey_314_results.json --md
"""
import argparse
import json
import sys

CATEGORIES = [
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
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--rust", action="store_true")
    ap.add_argument("--md", action="store_true")
    args = ap.parse_args()
    if not (args.rust or args.md):
        args.rust = args.md = True

    rows = json.load(open(args.results))
    rows.sort(key=lambda r: r["name"].lower())
    good = [r for r in rows if r["pass"]]
    bad = [r for r in rows if not r["pass"]]
    total = len(rows)

    if args.rust:
        print("// ---- KNOWN_GOOD (paste into tests/pyodide_survey_314.rs) ----")
        print(f"// {len(good)}/{total} import OK on the 314 survey")
        for r in good:
            print(f'    "{r["name"]}",')
        print()

    if args.md:
        so_total = sum(1 for r in rows if r.get("has_so"))
        so_pass = sum(1 for r in rows if r.get("has_so") and r["pass"])
        py_total = total - so_total
        py_pass = len(good) - so_pass
        print("---- MARKDOWN SUMMARY ----")
        print(f"import OK: {len(good)}/{total}")
        print(f"  native-extension (.so): {so_pass}/{so_total}")
        print(f"  pure-Python           : {py_pass}/{py_total}")
        print()
        for cat in CATEGORIES:
            grp = [r for r in bad if r["category"] == cat]
            if not grp:
                continue
            print(f"### {cat} ({len(grp)})")
            print()
            print("| Package | Cause |")
            print("|---|---|")
            for r in grp:
                reason = r["reason"].replace("|", "\\|")
                print(f"| `{r['name']}` | {reason} |")
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
