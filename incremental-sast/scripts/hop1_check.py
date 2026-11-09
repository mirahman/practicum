#!/usr/bin/env python3
"""Cheap follow-up: how does the finding classification change if only
1-hop links count as connected, instead of 2? Reuses the graph already
cached by func_filter.py for one commit -- no rerun of the helper.

Usage:
  python scripts/hop1_check.py --repo <repo> --json <name>_func_result.json \
      --cache /tmp/isast-funcgraph-cache --commit <sha or prefix>
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import func_filter as ff  # noqa: E402
from isast import corpus  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--json", required=True)
    ap.add_argument("--cache", default="/tmp/isast-funcgraph-cache")
    ap.add_argument("--commit", required=True)
    a = ap.parse_args()

    repo = Path(a.repo).resolve()
    sha = ff.git(repo, "rev-parse", a.commit).strip()
    cache_files = list(Path(a.cache).glob(Path(repo).name + "-" + sha[:12] + "*.json"))
    if not cache_files:
        sys.exit("no cached graph for this commit; run func_filter.py on it first")
    g = json.loads(cache_files[0].read_text())

    idx = ff.index_funcs(g)
    chg_lines = ff.changed_lines(repo, sha)
    chg = ff.changed_funcs(idx, chg_lines)

    d1_strict = ff.hops(chg, [g["edges"]], maxhop=1)
    d1_caut = ff.hops(chg, [g["edges"], g["dyn_edges"]], maxhop=1)

    records = json.loads(Path(a.json).read_text())
    records = [r for r in records if r["commit"] == sha]
    print("%d findings for %s\n" % (len(records), sha[:12]))
    print("%-40s %-6s  2-hop -> 1-hop" % ("finding", "line"))
    changed = 0
    for r in records:
        fid = r["function"]
        new_strict = ff.label(fid, d1_strict)
        new_caut = ff.label(fid, d1_caut)
        if new_strict != r["strict"] or new_caut != r["cautious"]:
            changed += 1
            flag = "  <-- ARTIFACT" if r["artifact"] else ""
            print("%-40s %-6d  (%s,%s) -> (%s,%s)%s" % (
                r["file"], r["line"], r["strict"], r["cautious"],
                new_strict, new_caut, flag))
    if not changed:
        print("(no findings changed classification at 1 hop)")
    print("\n%d of %d findings reclassify when hop cap drops from 2 to 1" % (changed, len(records)))


if __name__ == "__main__":
    main()
