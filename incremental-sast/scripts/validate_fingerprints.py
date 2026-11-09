#!/usr/bin/env python3
"""WEEK 1 GATE — run this before building anything else.

Everything downstream joins findings across scans on Semgrep's
match-based fingerprint. If that fingerprint is not stable when the scan
scope changes, every metric in the study is measuring noise.

This script scans one commit at full scope and at diff scope, then asks:

  1. Do findings that appear in BOTH runs carry the same fingerprint?
  2. How many results lack a usable fingerprint entirely?
  3. Of diff-scope findings absent from the full scan, do they look like
     genuine context artifacts, or like join failures?

Question 3 needs your eyes. The script prints candidates; you read the
code and decide. Twenty minutes of manual checking here saves a rewrite
in week 8.

If fingerprints turn out to be scope-sensitive, fall back to the
structural key in normalize._fallback_key and report the coarsening as a
threat to validity.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isast import corpus, normalize, runner  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--lang", choices=["go", "typescript"], required=True)
    ap.add_argument("--config", default="p/default")
    ap.add_argument("--pro", action="store_true")
    ap.add_argument("--workdir", default="/tmp/isast-validate")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    changed = corpus.changed_files(repo, args.commit, args.lang)
    if not changed:
        print("no changed files in that language", file=sys.stderr)
        return 1

    print(f"commit {args.commit[:12]}  changed={len(changed)}")
    snap = corpus.snapshot(repo, args.commit, Path(args.workdir))

    try:
        print("scanning full scope...")
        full_res = runner.run_semgrep(snap, None, config=args.config, pro=args.pro)
        full_rec, full_fb = normalize.normalize(full_res.sarif)

        print("scanning diff scope...")
        diff_res = runner.run_semgrep(snap, changed, config=args.config, pro=args.pro)
        diff_rec, diff_fb = normalize.normalize(diff_res.sarif)

        # Does --pro reach outside named targets? Compare against intrafile.
        print("scanning diff scope (intrafile, for scope-bounding check)...")
        intra_res = runner.run_semgrep(
            snap, changed, config=args.config, pro=False,
            extra_args=("--pro-intrafile",) if args.pro else (),
        )
        intra_rec, _ = normalize.normalize(intra_res.sarif)
    finally:
        corpus.cleanup_snapshot(repo, snap)

    full_fp = {r["fingerprint"] for r in full_rec}
    diff_fp = {r["fingerprint"] for r in diff_rec}
    intra_fp = {r["fingerprint"] for r in intra_rec}

    print("\n=== 1. fingerprint coverage ===")
    print(f"  full: {len(full_rec)} results, {full_fb} without fingerprint")
    print(f"  diff: {len(diff_rec)} results, {diff_fb} without fingerprint")
    if full_fb or diff_fb:
        print("  [!] some results lack fingerprints — fallback key in use")

    print("\n=== 2. cross-scope join ===")
    overlap = full_fp & diff_fp
    print(f"  full={len(full_fp)}  diff={len(diff_fp)}  overlap={len(overlap)}")
    if not overlap and diff_fp and full_fp:
        print("  [!!] ZERO overlap. Fingerprints are probably scope-sensitive.")
        print("       Do not proceed until this is understood.")

    print("\n=== 3. scope bounding (--pro vs intrafile) ===")
    print(f"  diff(--pro)={len(diff_fp)}  diff(intrafile)={len(intra_fp)}")
    if diff_fp != intra_fp:
        print("  Interfile analysis changes diff-scope results.")
        print("  => targets do NOT fully bound the analysis. Record this.")
    else:
        print("  Identical. Targets appear to bound the analysis.")

    print("\n=== 4. spurious candidates (inspect by hand) ===")
    spurious = diff_fp - full_fp
    print(f"  {len(spurious)} findings in diff but not full")
    by_fp = {r["fingerprint"]: r for r in diff_rec}
    for fp in list(spurious)[:10]:
        r = by_fp[fp]
        print(f"    {r['rule_id']}")
        print(f"      {r['file']}:{r['start_line']}")
        print(f"      {r['message'][:110]}")
    if len(spurious) > 10:
        print(f"    ... and {len(spurious) - 10} more")

    print("\nNext: open 5 of the above and confirm the sanitizer or type")
    print("constraint that resolves them lives OUTSIDE the changed files.")
    print("That is what makes them context artifacts rather than join bugs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
