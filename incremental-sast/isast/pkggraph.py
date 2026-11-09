"""Package-level import graph via `go list -json`.

Replaces the SSA/VTA call graph (isast/callgraph_go.py) for the filter
experiment. That approach hit two distinct, unrecoverable x/tools SSA-
builder bugs on real code:

  1. "unexpected expr: *ast.KeyValueExpr" during Package.Build, triggered
     by ssa.InstantiateGenerics on composite literals in generic code.
  2. A second, different panic inside ssautil.AllFunctions ->
     Program.RuntimeTypes on traefik, occurring even after (1) was fixed,
     in a code path with no recovery wrapper.

Two independent SSA-builder crashes on two different production codebases
is a signal to stop working around x/tools internals, not a call to add a
third recovery wrapper. `go list` uses the Go toolchain's own dependency
resolution -- no SSA, no generics instantiation, no type-checking of
function bodies. It cannot crash on the code patterns that broke the
SSA builder, because it never builds SSA at all.

The tradeoff: this is an IMPORT graph, not a verified CALL graph. Package
A "reaching" package B means A imports B, not that A's changed code
actually calls into B. This is coarser, and coarser is the conservative
direction for this experiment: it can only reclassify findings from
"unrelated" to "related" relative to a true call graph, never the reverse.
That bias should be stated plainly wherever this is used in the report.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def package_import_graph(snapshot: Path, timeout_s: int = 300) -> tuple[dict[str, set[str]], dict]:
    """Package directory -> set of package directories it imports.

    Both keys and values are paths relative to `snapshot`, matching the
    directory strings used elsewhere in this project (e.g. changed_files
    plus dirname). Only imports resolving to a directory INSIDE the module
    are kept; stdlib and third-party dependencies are dropped, since the
    experiment only cares about reachability within the codebase itself.

    `-e` makes `go list` tolerant of individual broken packages -- it
    still emits JSON for everything that does resolve, rather than
    aborting the whole call the way `go build` would.
    """
    proc = subprocess.run(
        ["go", "list", "-e", "-json", "-deps=false", "./..."],
        cwd=str(snapshot), capture_output=True, text=True, timeout=timeout_s,
    )
    if not proc.stdout.strip():
        return {}, {"ok": False, "stderr": proc.stderr[-2000:]}

    # `go list -json` streams one JSON object per package with no
    # separators; decode them one at a time.
    decoder = json.JSONDecoder()
    text = proc.stdout
    pos = 0
    pkgs = []
    while pos < len(text):
        chunk = text[pos:].lstrip()
        if not chunk:
            break
        skipped = len(text[pos:]) - len(chunk)
        try:
            obj, consumed = decoder.raw_decode(chunk)
        except json.JSONDecodeError as e:
            return {}, {"ok": False, "stderr": f"JSON parse error: {e}"}
        pkgs.append(obj)
        pos += skipped + consumed

    dir_of_import_path: dict[str, str] = {}
    for p in pkgs:
        d = p.get("Dir")
        ip = p.get("ImportPath")
        if not d or not ip:
            continue
        try:
            rel = os.path.relpath(d, snapshot)
        except ValueError:
            continue
        if rel.startswith(".."):
            continue  # outside the module (shouldn't happen, but be safe)
        dir_of_import_path[ip] = rel

    graph: dict[str, set[str]] = {}
    n_edges = 0
    for p in pkgs:
        ip = p.get("ImportPath")
        src = dir_of_import_path.get(ip)
        if src is None:
            continue
        deps = set()
        for imp in (p.get("Imports") or []) + (p.get("TestImports") or []):
            tgt = dir_of_import_path.get(imp)
            if tgt is not None and tgt != src:
                deps.add(tgt)
        graph[src] = graph.get(src, set()) | deps
        n_edges += len(deps)

    return graph, {"ok": True, "n_packages": len(graph), "n_edges": n_edges}


def hop_closure(seed_dirs: set[str], graph: dict[str, set[str]], depth: int) -> set[str]:
    """Package dirs reachable from `seed_dirs` within `depth` import-hops.

    Follows the "imports" edge outward from the seed: if a changed
    package imports package X, X is 1 hop away, because changed code can
    call into X. Seed itself is excluded from the result.
    """
    frontier = set(seed_dirs)
    seen = set(seed_dirs)
    for _ in range(depth):
        nxt: set[str] = set()
        for d in frontier:
            nxt |= graph.get(d, set())
        nxt -= seen
        if not nxt:
            break
        seen |= nxt
        frontier = nxt
    return seen - seed_dirs
