#!/usr/bin/env python3
"""Decision run: Conditions A and B on commits that can actually exhibit the effect.

Answers, in one overnight batch:
  - spurious rate           (RQ1)
  - differencing survival   (RQ2)
  - composition by rule class, which is what the week-1 prevalence
    measurements made the central question

Design choices that make this fit in a night:
  * Commits are SELECTED, not sampled uniformly. A commit touching no
    finding-bearing file produces 0/0 and wastes ~17 minutes. Candidate
    commits are those touching files that carried findings in a reference
    full scan.
  * Full scans are cached by SHA in the database. Re-runs skip work, and
    a commit whose parent was already scanned costs one full scan, not two.
  * Conditions C and D are not run. They do not bear on whether the
    research question survives.

Usage:
  # 1. reference scan to find which files carry findings
  semgrep scan --config=p/golang --pro --include='*.go' \\
      --exclude='vendor/' --exclude='*_test.go' --jobs $(nproc) \\
      --sarif -o /tmp/ref.sarif .

  # 2. pick and run
  python scripts/decision_run.py --repo ~/codes/practicum/corpus/gitea \\
      --ref-sarif /tmp/ref.sarif --n 12 --config p/golang
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isast import corpus, db, normalize, runner  # noqa: E402

TAINT_HINTS = ("taint", "sqli", "injection", "ssrf", "traversal",
               "xss", "command", "redirect")


def rule_class(rule_id: str) -> str:
    r = rule_id.lower()
    return "taint" if any(h in r for h in TAINT_HINTS) else "pattern"


def finding_files(ref_sarif: Path) -> set[str]:
    d = json.loads(ref_sarif.read_text())
    return {
        x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].lstrip("./")
        for r in d.get("runs", [])
        for x in r.get("results", [])
        if x.get("locations")
    }


def pick_commits(repo: Path, hot: set[str], n: int, max_files: int) -> list[str]:
    """Commits touching at least one file that carried a finding."""
    shas = corpus._git(repo, "log", "--format=%H", "--no-merges", "-3000").splitlines()
    picked = []
    for sha in shas:
        try:
            changed = corpus.changed_files(repo, sha, "go")
        except Exception:
            continue
        if not changed or len(changed) > max_files:
            continue
        if any(c in hot for c in changed):
            picked.append(sha)
        if len(picked) >= n:
            break
    return picked


def have_run(conn, repo_name, sha, condition, engine="semgrep") -> bool:
    row = conn.execute(
        "SELECT 1 FROM runs WHERE repo=? AND commit_sha=? AND condition=? AND engine=?",
        (repo_name, sha, condition, engine)).fetchone()
    return row is not None


def scan(conn, repo, repo_name, sha, condition, targets, work, config, mode="pro"):
    """Run one scan condition.

    `targets=None` means whole repository (the oracle). Otherwise `targets`
    is the list of changed files, and the scan is scoped to the DIRECTORIES
    containing them.

    Directory scoping is not a stylistic choice. Semgrep's Pro interfile
    engine rejects a file list outright:
        "Inter-file analysis can only take a single target
         (for multiple files pass a directory)"
    CodeQL fails on file subsets for an unrelated reason (unresolvable
    types). Both engines therefore force package granularity, which is also
    what a CI system would realistically do for a compiled language: Go
    packages are directories.
    """
    engine = "semgrep" if mode == "pro" else "semgrep-ce"
    if have_run(conn, repo_name, sha, condition, engine):
        print(f"    {condition:5s} cached")
        return

    snap = corpus.snapshot(repo, sha, work)
    try:
        args = ("--exclude=vendor/", "--exclude=*_test.go")

        pro = (mode == "pro")

        if targets is None:
            scope = None
            res = runner.run_semgrep(snap, None, config=config, pro=pro,
                                     extra_args=("--include=*.go",) + args)
        elif not pro:
            # CE has no interfile analysis and accepts a file list. This is
            # the FILE-level Condition A the Pro engine rejects.
            files = [t for t in targets
                     if t.endswith(".go") and not t.endswith("_test.go")
                     and "vendor/" not in t and (snap / t).exists()]
            if not files:
                print(f"    {condition:5s} skipped (no scannable files)")
                return
            scope = files
            res = runner.run_semgrep(snap, files, config=config, pro=False,
                                     extra_args=args)
        else:
            # Changed files -> the set of directories (packages) holding them.
            dirs = sorted({str(Path(t).parent) for t in targets
                           if t.endswith(".go")
                           and not t.endswith("_test.go")
                           and "vendor/" not in t
                           and (snap / t).exists()})
            if not dirs:
                print(f"    {condition:5s} skipped (no scannable packages)")
                return
            scope = dirs

            # Interfile mode takes ONE target, so scan each package
            # separately and union the results.
            merged = {"runs": [{"results": []}]}
            elapsed = 0.0
            failed = []
            for d in dirs:
                one = runner.run_semgrep(snap, [d], config=config, pro=True,
                                         extra_args=args)
                elapsed += one.wall_clock_s
                if one.exit_status != 0:
                    failed.append(d)
                    continue
                for run in one.sarif.get("runs", []):
                    merged["runs"][0]["results"].extend(run.get("results", []))
            if failed and len(failed) == len(dirs):
                print(f"    {condition:5s} FAILED all {len(dirs)} packages - not recorded")
                return
            res = runner.ScanResult(sarif=merged, wall_clock_s=elapsed,
                                    exit_status=0, target_count=len(dirs),
                                    stderr=f"failed_pkgs={failed}")

        if res.exit_status != 0:
            print(f"    {condition:5s} FAILED exit={res.exit_status} - not recorded")
            print(f"           {res.stderr[-300:]}")
            return

        recs, fb = normalize.normalize(res.sarif)
        note = f"fallback_keys={fb}"
        if scope:
            note += f"; pkgs={len(scope)}"
        rid = db.record_run(conn, repo=repo_name, commit_sha=sha,
                            condition=condition, engine=engine,
                            target_count=res.target_count,
                            wall_clock_s=res.wall_clock_s,
                            exit_status=res.exit_status, notes=note)
        db.record_findings(conn, rid, recs)
        unit = "files" if mode == "ce" else "pkgs"
        extra = f"  ({len(scope)} {unit})" if scope else ""
        print(f"    {condition:5s} {len(recs):4d} findings  {res.wall_clock_s:6.1f}s{extra}")
    finally:
        corpus.cleanup_snapshot(repo, snap)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--ref-sarif", required=True)
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--max-files", type=int, default=30)
    ap.add_argument("--config", default="p/golang")
    ap.add_argument("--db", default="results.db")
    ap.add_argument("--workdir", default="/tmp/isast-work")
    ap.add_argument("--mode", choices=["pro", "ce"], default="pro")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    repo_name = repo.name
    work = Path(args.workdir).resolve()
    conn = db.connect(args.db)

    if corpus._git(repo, "rev-list", "--count", "HEAD").strip() in ("1", "0"):
        sys.exit("ERROR: shallow clone. Re-clone with full history.")

    hot = finding_files(Path(args.ref_sarif))
    print(f"reference scan carried findings in {len(hot)} files")

    commits = pick_commits(repo, hot, args.n, args.max_files)
    print(f"selected {len(commits)} commits touching finding-bearing files\n")
    if not commits:
        sys.exit("No candidate commits. Widen --max-files or the reference scan.")

    t0 = time.time()
    for k, sha in enumerate(commits, 1):
        parent = corpus._git(repo, "rev-parse", f"{sha}~1")
        changed = corpus.changed_files(repo, sha, "go")
        db.record_changed_files(conn, repo_name, sha, changed)
        print(f"[{k}/{len(commits)}] {sha[:12]}  ({len(changed)} changed)")
        scan(conn, repo, repo_name, parent, "full", None, work, args.config, args.mode)
        scan(conn, repo, repo_name, sha, "full", None, work, args.config, args.mode)
        scan(conn, repo, repo_name, sha, "diff", changed, work, args.config, args.mode)

    print(f"\nscanning done in {(time.time()-t0)/60:.1f} min\n")
    report(conn, repo, repo_name, commits,
           "semgrep" if args.mode == "pro" else "semgrep-ce")


def report(conn, repo, repo_name, commits, engine="semgrep"):
    tot = collections.Counter()
    per_class = collections.Counter()

    for sha in commits:
        parent = corpus._git(repo, "rev-parse", f"{sha}~1")
        full = db.fingerprints(conn, repo_name, sha, "full", engine)
        diff = db.fingerprints(conn, repo_name, sha, "diff", engine)
        base = db.fingerprints(conn, repo_name, parent, "full", engine)
        rows = db.finding_rows(conn, repo_name, sha, "diff", engine)

        spurious = diff - full
        reported = diff - base          # Condition B output
        survivors = spurious & reported

        tot["diff"] += len(diff)
        tot["spurious"] += len(spurious)
        tot["reported"] += len(reported)
        tot["survivors"] += len(survivors)

        for fp in reported:
            r = rows.get(fp)
            if r is None:
                continue
            cls = rule_class(r["rule_id"])
            per_class[(cls, "reported")] += 1
            if fp in spurious:
                per_class[(cls, "spurious")] += 1

    print("=" * 62)
    print(f"DECISION RUN RESULTS  (engine: {engine})")
    print("=" * 62)
    print(f"  commits                  {len(commits)}")
    print(f"  diff-scan findings       {tot['diff']}")
    print(f"  spurious (not in full)   {tot['spurious']}")
    print(f"  reported after diffing   {tot['reported']}")
    print(f"  spurious survivors       {tot['survivors']}   <-- headline")
    if tot["diff"]:
        print(f"  spurious rate            {tot['spurious']/tot['diff']:.1%}")
    if tot["spurious"]:
        print(f"  survival rate            {tot['survivors']/tot['spurious']:.1%}")
    if tot["reported"]:
        print(f"  reported precision       {1-tot['survivors']/tot['reported']:.1%}")

    print("\n  composition of what a developer would see:")
    for cls in ("taint", "pattern"):
        rep = per_class[(cls, "reported")]
        spu = per_class[(cls, "spurious")]
        print(f"    {cls:8s} reported={rep:4d}  of which spurious={spu:4d}")

    print("""
INTERPRETING THIS
  spurious survivors >= ~15   the mechanism is measurable; proceed as proposed
  spurious survivors 1-14     real but rare; reframe RQ1 toward composition
  spurious survivors 0        context truncation is not the noise source;
                              RQ1 becomes "what IS the queue made of", which
                              this same table already begins to answer
  pattern findings surviving differencing at a high rate would itself be a
  finding: the standard architecture failing for a different reason.
""")


if __name__ == "__main__":
    main()