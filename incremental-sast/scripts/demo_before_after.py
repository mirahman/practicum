#!/usr/bin/env python3
"""Show one commit's finding queue before and after the function-level filter.

Reads the JSON written by func_filter.py (<name>_func_result.json).

  python scripts/demo_before_after.py --result gitea_func_result.json --commit e21c37703e
  python scripts/demo_before_after.py --result gitea_func_result.json --commit e21c37703e --differenced
"""
import argparse, json
from collections import Counter

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--result", required=True)
    ap.add_argument("--commit", required=True, help="commit sha prefix")
    ap.add_argument("--view", choices=["strict", "cautious"], default="cautious")
    ap.add_argument("--differenced", action="store_true",
                    help="start from the findings left after baseline differencing")
    a = ap.parse_args()
    recs = [r for r in json.load(open(a.result)) if r["commit"].startswith(a.commit)]
    if a.differenced: recs = [r for r in recs if r["reported"]]
    if not recs: raise SystemExit("no findings for that commit")
    kept = [r for r in recs if r[a.view] != "unconnected"]
    gone = [r for r in recs if r[a.view] == "unconnected"]
    start = "baseline-differenced scan" if a.differenced else "diff scan"
    print(f"commit {recs[0]['commit'][:12]}   queue from the {start}   view: {a.view}\n")
    print(f"BEFORE the filter: {len(recs)} findings")
    print(f"AFTER the filter:  {len(kept)} findings  ({len(gone)} removed, {100*len(gone)//len(recs)}%)\n")
    print("Kept, with the reason:")
    for r in sorted(kept, key=lambda r: (r[a.view], r["file"], r["line"])):
        print(f"  {r[a.view]:<17} {r['file']}:{r['line']}  {r['rule'].split('.')[-1]}")
    print("\nRemoved, by rule:")
    for rule, n in Counter(r["rule"].split(".")[-1] for r in gone).most_common():
        print(f"  {n:>3}  {rule}")
    art = [r for r in recs if r["artifact"]]
    for r in art:
        print(f"\nConfirmed scope-truncation artifact: {r['file']}:{r['line']} -> {r[a.view]}"
              + ("  (removed by the filter)" if r[a.view] == "unconnected" else "  (kept)"))

if __name__ == "__main__": main()
