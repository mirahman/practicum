#!/usr/bin/env python3
"""Recheck of the filter experiment. Reads the existing <name>_filter_result.json
and git history only. No scans, no Go tooling. Runs in seconds.

Fixes two problems in the first analysis:
 1. Untouched files inside a CHANGED package were counted as "unrelated". They
    are the files most likely connected to the change (same package, direct
    calls, no import needed). They now get their own bucket, same_package.
 2. "Files scanned" was a non-recursive glob that included test files. Here the
    scan scope is counted as Semgrep saw it: recursive under each scanned
    directory, excluding *_test.go and vendor/.

Usage:
  python scripts/filter_recheck.py --repo <repo path> --json <name>_filter_result.json
"""
import argparse, json, subprocess, sys
from pathlib import PurePosixPath as P


def git(repo, *a):
    r = subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def scannable(f):
    return f.endswith(".go") and not f.endswith("_test.go") and "vendor/" not in f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--json", required=True)
    a = ap.parse_args()
    data = json.load(open(a.json))

    tot = dict(touched=0, same_package=0, related_import=0, other_unrelated=0)
    spur = dict(tot)
    scope_sum = changed_sum = 0
    artifacts = []

    for c in data:
        sha = c["commit"]
        tree = set(git(a.repo, "ls-tree", "-r", "--name-only", sha).split("\n"))
        changed_all = {f for f in git(a.repo, "diff", "--name-only", sha + "~1", sha).split("\n")
                       if f.endswith(".go")}
        changed_scan = {f for f in changed_all if scannable(f) and f in tree}
        dirs = {str(P(f).parent) for f in changed_scan}
        if dirs:
            def under(f):
                return any(d == "." or f.startswith(d + "/") for d in dirs)
            scope_sum += sum(1 for f in tree if scannable(f) and under(f))
            changed_sum += len(changed_scan)

        for d in c.get("detail", []):
            f = d["file"]
            if f in changed_all:
                b = "touched"
            elif str(P(f).parent) in dirs:
                b = "same_package"
            elif d["bucket"] in ("related_1hop", "related_2hop"):
                b = "related_import"
            else:
                b = "other_unrelated"
            tot[b] += 1
            if d["spurious"]:
                spur[b] += 1
                artifacts.append((sha[:10], f, d["line"], b))

    n = sum(tot.values())
    print("=" * 62)
    print("FILTER RECHECK", a.json)
    print("=" * 62)
    for b in tot:
        print(f"  {b:16s} {tot[b]:4d}  ({tot[b]/n*100:5.1f}%)   artifacts: {spur[b]}")
    print(f"  total            {n:4d}")
    print()
    print("  Only other_unrelated is removable on import evidence alone.")
    print(f"  import filter removes: {tot['other_unrelated']} ({tot['other_unrelated']/n*100:.1f}%)")
    print(f"  same_package (kept):   {tot['same_package']} ({tot['same_package']/n*100:.1f}%)")
    print(f"  naive filter removes:  {n-tot['touched']} ({(n-tot['touched'])/n*100:.1f}%)")
    print()
    if changed_sum:
        print(f"  scan scope (recursive, no tests): {scope_sum} Go files")
        print(f"  changed, scannable Go files:      {changed_sum}")
        print(f"  exposure ratio:                   {scope_sum/changed_sum:.1f}x")
    for x in artifacts:
        print("  artifact:", x)


if __name__ == "__main__":
    main()
