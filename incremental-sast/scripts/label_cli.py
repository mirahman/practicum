#!/usr/bin/env python3
"""Label a blind sheet in the terminal. Resumable: answers are saved after each one.

  python scripts/label_cli.py --blind gitea_blind.csv --repo $GITEA

Keys:  y = connected,  n = not connected,  s = skip for now,  q = quit (progress is kept)
Rule:  y if a reviewer of this commit would need to look at this finding, because the commit
       changes code the flagged code depends on, or code that depends on the flagged code.
       n if the flagged code behaves the same with or without this commit. Unsure: y.
"""
import argparse, csv, subprocess, textwrap

COL = "connected? (y/n)"

def git(repo, *a):
    r = subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    return r.stdout

def save(path, fields, rows):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blind", required=True); ap.add_argument("--repo", required=True)
    ap.add_argument("--context", type=int, default=15, help="lines of code shown each side")
    a = ap.parse_args()
    with open(a.blind, newline="") as fh:
        rd = csv.DictReader(fh); fields = rd.fieldnames; rows = list(rd)
    todo = [r for r in rows if r[COL].strip().lower() not in ("y", "n")]
    print(f"{len(rows) - len(todo)} done, {len(todo)} to go\n")
    for k, r in enumerate(todo, 1):
        sha, f, line = r["commit"], r["file"], int(r["line"])
        print("=" * 78)
        print(f"[{k}/{len(todo)}]  id {r['id']}   commit {sha}   rule {r['rule']}")
        print("-" * 78)
        print(git(a.repo, "show", "--stat", "--format=%s", sha, "--").strip()[-1800:])
        print("-" * 78)
        hunk = git(a.repo, "diff", "-U0", sha + "~1", sha, "--", f).strip()
        print(f"Changes to {f} in this commit:" if hunk else f"{f} was NOT changed by this commit.")
        if hunk: print(textwrap.indent("\n".join(hunk.splitlines()[:40]), "  "))
        print("-" * 78)
        src = git(a.repo, "show", f"{sha}:{f}").splitlines()
        lo, hi = max(0, line - 1 - a.context), min(len(src), line + a.context)
        print(f"{f}  (flagged line {line} marked >>)")
        for i in range(lo, hi):
            print(f"{'>>' if i + 1 == line else '  '} {i + 1:5d}  {src[i]}")
        while True:
            ans = input("\nconnected? [y/n/s/q] ").strip().lower()
            if ans in ("y", "n", "s", "q"): break
        if ans == "q": break
        if ans in ("y", "n"):
            r[COL] = ans; save(a.blind, fields, rows)
    left = sum(1 for r in rows if r[COL].strip().lower() not in ("y", "n"))
    print(f"\nsaved. {left} rows still unlabelled in {a.blind}")

if __name__ == "__main__": main()
