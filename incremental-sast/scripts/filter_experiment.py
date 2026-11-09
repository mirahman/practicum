#!/usr/bin/env python3
"""Filter experiment: is the untouched-file filter safe?

Sections 7.6/7.7 of the decision journal show that 86% (gitea) / 62%
(traefik) of diff-scan findings sit in files the commit did not modify.
The obvious mitigation - drop any finding in an untouched file - risks
hiding a finding the change actually interacts with: a changed function
that calls into unchanged code containing a finding.

This script re-classifies every existing diff-scan finding into three
buckets, using the file-level Go call graph of that commit's snapshot:

    touched    finding is in a file the commit modified
    related    finding is in an untouched file, but reachable from a
               changed file within N call-graph hops (checked at N=1
               and N=2 - both are reported so the choice of depth is
               itself visible rather than assumed)
    unrelated  finding is in an untouched file with no such path

The filter under test removes only "unrelated". "related" is exactly
the case the naive touched/untouched filter would have gotten wrong.

No new SAST scans are run. This reuses the diff-scan findings already
in results.db / results_traefik.db and adds one thing: the call graph,
built once per commit snapshot via isast.callgraph_go (go/ssa + VTA,
written earlier for Condition D and unused until now).

Usage:
    python scripts/filter_experiment.py \\
        --repo ~/codes/practicum/corpus/gitea \\
        --db results_default.db --name gitea

    python scripts/filter_experiment.py \\
        --repo ~/codes/practicum/corpus/traefik \\
        --db results_traefik.db --name traefik

Run once per repository/db pair, then combine the two JSON outputs by
hand or with a two-line pandas script for the aggregate table.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from isast import corpus, db, pkggraph  # noqa: E402




def classify_commit(conn, repo: Path, repo_name: str, sha: str,
                    work: Path) -> dict:
    """Classify each diff-scan finding by package-import reachability
    from the changed packages. Package granularity, not file granularity
    -- consistent with Condition A elsewhere in this project, and with
    what `go list` naturally reports.
    """
    changed_files = corpus.changed_files(repo, sha, "go")
    changed_pkgs = {str(Path(f).parent) for f in changed_files}
    diff_rows = db.finding_rows(conn, repo_name, sha, "diff", "semgrep")
    full_fps = db.fingerprints(conn, repo_name, sha, "full", "semgrep")

    if not diff_rows:
        return {"commit": sha, "changed_pkgs": len(changed_pkgs), "findings": 0}

    snap = corpus.snapshot(repo, sha, work)
    try:
        graph, stats = pkggraph.package_import_graph(snap)
    finally:
        corpus.cleanup_snapshot(repo, snap)

    if not stats.get("ok"):
        return {"commit": sha, "changed_pkgs": len(changed_pkgs),
                "findings": len(diff_rows), "graph_failed": True,
                "error": stats.get("stderr", "")}

    related_1 = pkggraph.hop_closure(changed_pkgs, graph, 1)
    related_2 = pkggraph.hop_closure(changed_pkgs, graph, 2)

    buckets = {"touched": 0, "related_1hop": 0, "related_2hop": 0, "unrelated": 0}
    detail = []
    for fp, r in diff_rows.items():
        f = r["file"]
        pkg = str(Path(f).parent)
        if f in changed_files:
            b = "touched"
        elif pkg in related_1:
            b = "related_1hop"
        elif pkg in related_2:
            b = "related_2hop"
        else:
            b = "unrelated"
        buckets[b] += 1
        detail.append({
            "bucket": b,
            "rule": r["rule_id"],
            "file": f,
            "line": r["start_line"],
            "spurious": fp not in full_fps,
        })

    return {
        "commit": sha, "changed_pkgs": len(changed_pkgs), "findings": len(diff_rows),
        "graph_packages": stats.get("n_packages", 0),
        "graph_edges": stats.get("n_edges", 0),
        "buckets": buckets, "detail": detail,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--name", required=True, help="repo name as stored in the db")
    ap.add_argument("--workdir", default="/tmp/isast-filter-work")
    ap.add_argument("--out", default=None,
                    help="JSON output path; defaults to <name>_filter_result.json")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    conn = db.connect(args.db)
    work = Path(args.workdir)
    out_path = Path(args.out or f"{args.name}_filter_result.json")

    shas = [r[0] for r in conn.execute(
        "SELECT DISTINCT commit_sha FROM runs WHERE condition='diff'")]
    print(f"{len(shas)} commits with diff-scan data in {args.db}")

    results = []
    for i, sha in enumerate(shas, 1):
        print(f"[{i}/{len(shas)}] {sha[:12]}", end="  ", flush=True)
        try:
            r = classify_commit(conn, repo, args.name, sha, work)
        except Exception as e:
            print(f"ERROR: {e}")
            continue
        results.append(r)
        if r.get("graph_failed"):
            print("import-graph FAILED")
            print("    " + (r.get("error", "") or "(no stderr captured)")[-500:].replace("\n", "\n    "))
        elif r["findings"] == 0:
            print("no findings")
        else:
            b = r["buckets"]
            print(f"touched={b['touched']} 1hop={b['related_1hop']} "
                  f"2hop={b['related_2hop']} unrelated={b['unrelated']}")

    json.dump(results, open(out_path, "w"), indent=2)
    print(f"\nwrote {out_path}")
    report(results, args.name)


def report(results: list[dict], name: str):
    tot = {"touched": 0, "related_1hop": 0, "related_2hop": 0, "unrelated": 0}
    spurious_by_bucket = {"touched": 0, "related_1hop": 0, "related_2hop": 0, "unrelated": 0}
    failed = 0
    for r in results:
        if r.get("graph_failed"):
            failed += 1
            continue
        for b, n in r.get("buckets", {}).items():
            tot[b] += n
        for d in r.get("detail", []):
            if d["spurious"]:
                spurious_by_bucket[d["bucket"]] += 1

    grand = sum(tot.values())
    print("\n" + "=" * 64)
    print(f"FILTER EXPERIMENT — {name}")
    print("=" * 64)
    if failed:
        print(f"  [!] import-graph construction failed on {failed} commit(s) — excluded")
    if grand == 0:
        print("  no findings to classify")
        return

    for b in ("touched", "related_1hop", "related_2hop", "unrelated"):
        pct = tot[b] / grand * 100
        print(f"  {b:14s} {tot[b]:4d}  ({pct:5.1f}%)   "
              f"of which spurious: {spurious_by_bucket[b]}")

    naive_removed = tot["related_1hop"] + tot["related_2hop"] + tot["unrelated"]
    safe_removed = tot["unrelated"]
    hidden_related = tot["related_1hop"] + tot["related_2hop"]

    print(f"\n  naive filter (touched-only) would remove:  {naive_removed:4d} "
          f"({naive_removed/grand*100:.1f}%)")
    print(f"  call-graph-aware filter removes:            {safe_removed:4d} "
          f"({safe_removed/grand*100:.1f}%)")
    print(f"  findings the naive filter would have hidden")
    print(f"  that ARE call-graph-reachable from the change: {hidden_related:4d}")

    print("""
READING THIS
  If related_1hop + related_2hop is small relative to unrelated, the
  untouched-file filter is close to safe as-is, and the call-graph check
  buys little. Report the exact fraction rather than asserting safety.

  If it's large, the naive filter would hide findings structurally
  connected to the change, and the call-graph-aware version (touched +
  related kept, only "unrelated" dropped) is the one to recommend.

  Compare 1-hop vs 2-hop: if 2-hop adds much beyond 1-hop, that is itself
  worth reporting — it suggests reachability decays slowly in this
  codebase and a deeper check may be warranted.
""")


if __name__ == "__main__":
    main()
