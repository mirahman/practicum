#!/usr/bin/env python3
"""Blind labelling for the function-level filter.

Question: are the findings the filter removes really unconnected to the commit?

  make   read the sample CSV written by func_filter.py --sample N and write
         a blind sheet (verdict hidden, order shuffled) plus a key file.
  score  read the filled-in blind sheet and the key, and report:
           wrongly removed = removed findings you labelled connected
           noise kept      = kept findings you labelled not connected
         each with a 95% Wilson interval.

Usage:
  python scripts/label_blind.py make  --sample gitea_sample.csv --out gitea
  # fill the 'connected? (y/n)' column in gitea_blind.csv, without looking at gitea_key.csv
  python scripts/label_blind.py score --blind gitea_blind.csv --key gitea_key.csv
"""
import argparse, csv, math, random, sys

def wilson(k, n, z=1.96):
    if n == 0: return (float("nan"),) * 2
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)

def make(a):
    rows = list(csv.DictReader(open(a.sample, newline="")))
    view = a.view
    rnd = random.Random(a.seed); rnd.shuffle(rows)
    with open(a.out + "_blind.csv", "w", newline="") as fb, open(a.out + "_key.csv", "w", newline="") as fk:
        wb = csv.writer(fb); wk = csv.writer(fk)
        wb.writerow(["id", "commit", "file", "line", "rule", "code", "connected? (y/n)"])
        wk.writerow(["id", "verdict"])
        for i, r in enumerate(rows, 1):
            v = r[view]
            verdict = "removed" if v == "unconnected" else "kept"
            wb.writerow([i, r["commit"], r["file"], r["line"], r["rule"], r["code"], ""])
            wk.writerow([i, verdict])
    print(f"wrote {a.out}_blind.csv and {a.out}_key.csv ({len(rows)} findings, view={view})")

def score(a):
    key = {r["id"]: r["verdict"] for r in csv.DictReader(open(a.key, newline=""))}
    rem = [0, 0]; kept = [0, 0]; blank = 0
    for r in csv.DictReader(open(a.blind, newline="")):
        lab = r["connected? (y/n)"].strip().lower()
        if lab not in ("y", "n"): blank += 1; continue
        v = key[r["id"]]
        if v == "removed": rem[1] += 1; rem[0] += lab == "y"
        else: kept[1] += 1; kept[0] += lab == "n"
    if blank: print(f"warning: {blank} rows have no y/n label and were skipped")
    for name, (k, n), what in (("wrongly removed", rem, "removed but labelled connected"),
                               ("noise kept", kept, "kept but labelled not connected")):
        lo, hi = wilson(k, n)
        print(f"{name}: {k} of {n} ({what})" + (f", 95% interval {lo:.0%} to {hi:.0%}" if n else ""))

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    m = sp.add_parser("make"); m.add_argument("--sample", required=True); m.add_argument("--out", required=True)
    m.add_argument("--view", choices=["strict", "cautious"], default="cautious"); m.add_argument("--seed", type=int, default=1)
    s = sp.add_parser("score"); s.add_argument("--blind", required=True); s.add_argument("--key", required=True)
    a = ap.parse_args(); (make if a.cmd == "make" else score)(a)
