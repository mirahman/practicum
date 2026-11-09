"""Run Semgrep at a controlled scope and time it.

Scope in Semgrep is controlled by TARGET SELECTION — the paths passed on
the command line. This is coarser than CodeQL's database source set:
Pro interfile analysis may still read context beyond the targets you name.

    >>> VALIDATE THIS BEHAVIOUR IN WEEK 1. <<<

Run the same commit with `diff` targets under --pro and --pro-intrafile.
If results are identical, targets are genuinely bounding the analysis.
If they differ, --pro is reaching outside your named scope and your
independent variable is not what you think it is. Record the answer in
the report; it determines what Condition A actually measures.
"""
from __future__ import annotations


import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScanResult:
    sarif: dict
    wall_clock_s: float
    exit_status: int
    target_count: int
    stderr: str


def run_semgrep(
    root: Path,
    targets: list[str] | None,
    config: str = "p/default",
    pro: bool = True,
    timeout_s: int = 3600,
    extra_args: tuple[str, ...] = (),
) -> ScanResult:
    """Scan `targets` (relative to root). targets=None means whole repo."""
    out_path = root / ".semgrep-out.sarif"

    cmd = [
        "semgrep", "scan",
        "--config", config,
        "--sarif", "--output", str(out_path),
        "--metrics", "off",
        "--disable-version-check",
        *extra_args,
    ]
    if pro:
        cmd.append("--pro")

    scan_targets = targets if targets else ["."]
    cmd += scan_targets

    start = time.perf_counter()
    proc = subprocess.run(
        cmd, cwd=str(root), capture_output=True, text=True, timeout=timeout_s
    )
    elapsed = time.perf_counter() - start

    sarif = {}
    if out_path.exists():
        sarif = json.loads(out_path.read_text())
        out_path.unlink()

    return ScanResult(
        sarif=sarif,
        wall_clock_s=elapsed,
        exit_status=proc.returncode,
        target_count=len(scan_targets),
        stderr=proc.stderr[-4000:],
    )


def expand_scope(changed: list[str], neighbors: dict[str, set[str]],
                 depth: int) -> list[str]:
    """Changed files plus call-graph neighbours out to `depth` hops.

    `neighbors` maps file -> set of files it calls into or is called from
    (see callgraph_go.py). Depth 0 returns the changed set unchanged.
    """
    frontier = set(changed)
    seen = set(changed)
    for _ in range(depth):
        nxt: set[str] = set()
        for f in frontier:
            nxt |= neighbors.get(f, set())
        nxt -= seen
        if not nxt:
            break
        seen |= nxt
        frontier = nxt
    return sorted(seen)


def run_semgrep_resilient(
    root: Path,
    targets: list[str],
    config: str = "p/default",
    pro: bool = True,
    extra_args: tuple[str, ...] = (),
) -> tuple[ScanResult, list[str]]:
    """Scan `targets` together; if the engine crashes, retry file by file.

    The Pro engine can exit non-zero on certain combinations of files within
    a large module. A crashed scan yields an empty SARIF, which is
    indistinguishable from a legitimate zero unless the exit status is
    checked — that failure mode silently produced a table of zeros once, so
    it is handled explicitly here.

    Returns (result, failed_targets). Per-file retry is NOT equivalent to a
    single multi-file scan: the engine cannot relate the changed files to
    each other. Record whenever the fallback fired; it is a deviation from
    the stated Condition A and belongs in threats to validity.
    """
    res = run_semgrep(root, targets, config=config, pro=pro, extra_args=extra_args)
    if res.exit_status == 0:
        return res, []

    merged: dict = {"runs": [{"results": []}]}
    failed: list[str] = []
    elapsed = 0.0
    for t in targets:
        one = run_semgrep(root, [t], config=config, pro=pro, extra_args=extra_args)
        elapsed += one.wall_clock_s
        if one.exit_status != 0:
            failed.append(t)
            continue
        for run in one.sarif.get("runs", []):
            merged["runs"][0]["results"].extend(run.get("results", []))

    return ScanResult(
        sarif=merged,
        wall_clock_s=elapsed,
        exit_status=0 if len(failed) < len(targets) else 2,
        target_count=len(targets),
        stderr=f"multi-file scan failed; per-file fallback used; failed={failed}",
    ), failed