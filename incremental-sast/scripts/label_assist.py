#!/usr/bin/env python3
"""AI-assisted blind labelling with a human-checked sample.

  export  write a compact text bundle of the findings (no filter verdict) to give to the AI labeller
  apply   merge the AI labels into the blind sheet, leaving a random hold-out blank for you
  agree   after you label the hold-out with label_cli.py, report agreement with the AI labels

  python scripts/label_assist.py export --blind gitea_blind.csv --repo $GITEA --out gitea_bundle.txt
  python scripts/label_assist.py apply  --blind gitea_blind.csv --ai gitea_ai.csv --holdout 20
  python scripts/label_cli.py --blind gitea_blind.csv --repo $GITEA        # label the hold-out rows
  python scripts/label_assist.py agree  --blind gitea_blind.csv --ai gitea_ai.csv

AI file format: one row per finding, header 'id,label,reason' with label y or n.
"""
import argparse, csv, random, subprocess
COL = "connected? (y/n)"

def git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True).stdout

def read(p):
    with open(p, newline="") as fh:
        rd = csv.DictReader(fh); return rd.fieldnames, list(rd)

def write(p, fields, rows):
    with open(p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)

def export(a):
    _, rows = read(a.blind); out = []
    for r in rows:
        sha, f, line = r["commit"], r["file"], int(r["line"])
        msg = git(a.repo, "show", "-s", "--format=%s", sha).strip()
        names = git(a.repo, "show", "--name-only", "--format=", sha).split()
        hunk = git(a.repo, "diff", "-U0", sha + "~1", sha, "--", f).splitlines()
        hunk = [l for l in hunk if not l.startswith(("diff ", "index ", "--- ", "+++ "))][:a.hunklines]
        src = git(a.repo, "show", f"{sha}:{f}").splitlines()
        lo, hi = max(0, line - 1 - a.context), min(len(src), line + a.context)
        out.append(f"##### FINDING {r['id']}  rule={r['rule']}  file={f}  flagged_line={line}")
        out.append(f"commit message: {msg}")
        out.append(f"files changed by commit ({len(names)}): " + ", ".join(names[:25]) + (" ..." if len(names) > 25 else ""))
        out.append("changes to the flagged file: " + ("NONE (file not changed)" if not hunk else ""))
        out += ["    " + l for l in hunk]
        out.append("code around the flagged line:")
        out += [f"{'>>' if i + 1 == line else '  '} {i + 1}: {src[i]}" for i in range(lo, hi)]
        out.append("")
    open(a.out, "w").write("\n".join(out))
    print(f"wrote {a.out}: {len(rows)} findings, {len(out)} lines")

def apply(a):
    fields, rows = read(a.blind); _, ai = read(a.ai)
    lab = {r["id"]: r["label"].strip().lower() for r in ai}
    bad = [i for i, v in lab.items() if v not in ("y", "n")]
    assert not bad, f"labels must be y or n: {bad[:5]}"
    missing = [r["id"] for r in rows if r["id"] not in lab]
    assert not missing, f"no AI label for ids: {missing[:10]}"
    ids = [r["id"] for r in rows]; rnd = random.Random(a.seed)
    hold = set(rnd.sample(ids, min(a.holdout, len(ids))))
    for r in rows: r[COL] = "" if r["id"] in hold else lab[r["id"]]
    write(a.blind, fields, rows)
    open(a.blind + ".holdout", "w").write("\n".join(sorted(hold, key=int)) + "\n")
    print(f"filled {len(rows) - len(hold)} rows with AI labels; {len(hold)} rows left blank for you to label")

def agree(a):
    _, rows = read(a.blind); _, ai = read(a.ai)
    lab = {r["id"]: r["label"].strip().lower() for r in ai}
    hold = [l.strip() for l in open(a.blind + ".holdout") if l.strip()]
    mine = {r["id"]: r[COL].strip().lower() for r in rows}
    done = [i for i in hold if mine.get(i) in ("y", "n")]
    if len(done) < len(hold): print(f"warning: you have labelled {len(done)} of {len(hold)} hold-out rows")
    same = sum(mine[i] == lab[i] for i in done)
    print(f"agreement with the AI labels on the hold-out rows you labelled: {same} of {len(done)}")
    for i in done:
        if mine[i] != lab[i]: print(f"  disagree on id {i}: you {mine[i]}, AI {lab[i]}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    e = sp.add_parser("export"); e.add_argument("--blind", required=True); e.add_argument("--repo", required=True)
    e.add_argument("--out", required=True); e.add_argument("--context", type=int, default=8); e.add_argument("--hunklines", type=int, default=30)
    p = sp.add_parser("apply"); p.add_argument("--blind", required=True); p.add_argument("--ai", required=True)
    p.add_argument("--holdout", type=int, default=20); p.add_argument("--seed", type=int, default=7)
    g = sp.add_parser("agree"); g.add_argument("--blind", required=True); g.add_argument("--ai", required=True)
    a = ap.parse_args(); {"export": export, "apply": apply, "agree": agree}[a.cmd](a)
