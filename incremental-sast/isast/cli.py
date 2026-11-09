"""CLI. Start with `one-commit` — that vertical slice proves the method."""
from __future__ import annotations


import argparse
import json
import sys
from pathlib import Path

from . import corpus, db, normalize, runner, compare


def cmd_sample(args):
    repo = Path(args.repo).resolve()
    shas = corpus.sample_commits(repo, args.lang, n=args.n,
                                 max_files=args.max_files)
    print(json.dumps(shas, indent=2))


def _scan_and_store(conn, *, repo_name, root, commit_sha, condition,
                    targets, config, pro):
    res = runner.run_semgrep(root, targets, config=config, pro=pro)
    records, fallbacks = normalize.normalize(res.sarif)
    run_id = db.record_run(
        conn, repo=repo_name, commit_sha=commit_sha, condition=condition,
        engine="semgrep", target_count=res.target_count,
        wall_clock_s=res.wall_clock_s, exit_status=res.exit_status,
        notes=f"fallback_keys={fallbacks}",
    )
    db.record_findings(conn, run_id, records)
    print(f"  {condition:9s} {len(records):5d} findings  "
          f"{res.wall_clock_s:7.1f}s  targets={res.target_count}"
          + (f"  [!] {fallbacks} fallback keys" if fallbacks else ""))
    return records


def cmd_one_commit(args):
    """End-to-end on a single commit: full + diff at C, full at parent.

    This is the week-1 vertical slice. It produces a real spurious rate
    and a real survival rate before any breadth is added.
    """
    repo = Path(args.repo).resolve()
    repo_name = args.name or repo.name
    conn = db.connect(args.db)
    work = Path(args.workdir).resolve()

    sha = args.commit
    parent = corpus._git(repo, "rev-parse", f"{sha}~1")

    changed = corpus.changed_files(repo, sha, args.lang)
    if not changed:
        print(f"no {args.lang} files changed in {sha[:12]}", file=sys.stderr)
        return 1
    db.record_changed_files(conn, repo_name, sha, changed)
    print(f"commit {sha[:12]}  ({len(changed)} changed {args.lang} files)")

    snap = corpus.snapshot(repo, sha, work)
    try:
        _scan_and_store(conn, repo_name=repo_name, root=snap, commit_sha=sha,
                        condition="full", targets=None,
                        config=args.config, pro=args.pro)
        _scan_and_store(conn, repo_name=repo_name, root=snap, commit_sha=sha,
                        condition="diff", targets=changed,
                        config=args.config, pro=args.pro)
    finally:
        corpus.cleanup_snapshot(repo, snap)

    psnap = corpus.snapshot(repo, parent, work)
    try:
        _scan_and_store(conn, repo_name=repo_name, root=psnap,
                        commit_sha=parent, condition="full", targets=None,
                        config=args.config, pro=args.pro)
    finally:
        corpus.cleanup_snapshot(repo, psnap)

    m = compare.compute(conn, repo_name, sha, parent)
    print("\n--- metrics ---")
    for k, v in m.as_row().items():
        print(f"  {k:20s} {v}")

    classes = compare.spurious_by_rule_class(conn, repo_name, sha)
    if classes:
        print("\n--- spurious by rule class ---")
        for cls, n in sorted(classes.items(), key=lambda x: -x[1]):
            print(f"  {cls:10s} {n}")
    return 0


def cmd_report(args):
    conn = db.connect(args.db)
    rows = conn.execute(
        "SELECT DISTINCT repo, commit_sha FROM runs WHERE condition='diff'"
    ).fetchall()
    out = []
    for r in rows:
        repo_path = Path(args.repo).resolve()
        try:
            parent = corpus._git(repo_path, "rev-parse", f"{r['commit_sha']}~1")
        except Exception:
            continue
        try:
            out.append(compare.compute(conn, r["repo"], r["commit_sha"],
                                       parent).as_row())
        except Exception as e:
            print(f"skip {r['commit_sha'][:12]}: {e}", file=sys.stderr)
    print(json.dumps(out, indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(prog="isast")
    p.add_argument("--db", default="results.db")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sample", help="pick candidate commits")
    s.add_argument("--repo", required=True)
    s.add_argument("--lang", choices=["go", "typescript"], required=True)
    s.add_argument("--n", type=int, default=50)
    s.add_argument("--max-files", type=int, default=25)
    s.set_defaults(func=cmd_sample)

    s = sub.add_parser("one-commit", help="end-to-end on a single commit")
    s.add_argument("--repo", required=True)
    s.add_argument("--commit", required=True)
    s.add_argument("--lang", choices=["go", "typescript"], required=True)
    s.add_argument("--name", default=None)
    s.add_argument("--workdir", default="/tmp/isast-work")
    s.add_argument("--config", default="p/default")
    s.add_argument("--pro", action="store_true")
    s.set_defaults(func=cmd_one_commit)

    s = sub.add_parser("report", help="metrics for everything stored")
    s.add_argument("--repo", required=True)
    s.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
