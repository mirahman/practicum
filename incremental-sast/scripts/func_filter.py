#!/usr/bin/env python3
"""Function-level filter evaluation (single file, needs Go and git on PATH).

The package-level filter removed only about 4 to 5 percent of findings, because
most findings in untouched files sit in the SAME package as the change. This
script checks connection at function level instead:

  changed function   the function containing a line changed by the commit
  linked_1 / _2      a function that references, or is referenced by, a
                     changed function, 1 or 2 steps away
  unconnected        a function with no such link within 2 steps
  no_function        finding is outside any function (package-level code, or a
                     file excluded by build tags). Always kept.

References come from the Go type checker (calls, method calls, functions passed
as values). Calls through an interface cannot be resolved exactly, so two views
are reported: STRICT uses direct references only (removes the most, may drop
connected findings); CAUTIOUS also links an interface call to every method with
that name in the module (removes less, safer). The true safe removal lies
between them.

No new SAST scans. Reads the findings already stored in the results database.

Usage:
  python scripts/func_filter.py --repo ~/codes/practicum/corpus/gitea \\
      --db results_default.db --name gitea [--only e21c3770] [--sample 30]
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from isast import corpus, db  # noqa: E402

HELPER_DIR = Path("/tmp/isast-funcgraph")
GO_MOD = "module funcgraph\n\ngo 1.21\n"
GO_SRC = r'''// funcgraph: function-level reference graph for a Go module (stdlib only).
// Run in a module root. Prints JSON: functions with line ranges, and edges
// from each function to the functions it references.
//
//	edges      direct references resolved with go/types (calls, method calls,
//	           functions passed as values)
//	dyn_edges  calls through an interface, linked by method NAME to every
//	           method with that name in the module (over-approximate on purpose)
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
)

type listPkg struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Export     string
	ImportMap  map[string]string
	Standard   bool
	DepOnly    bool
}

type fn struct {
	ID    string `json:"id"`
	File  string `json:"file"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

type output struct {
	Funcs    []fn           `json:"funcs"`
	Edges    [][2]string    `json:"edges"`
	DynEdges [][2]string    `json:"dyn_edges"`
	Stats    map[string]int `json:"stats"`
}

// moduleImporter resolves only packages inside this module, via load
// (defined in main, closing over the already-checked cache). Anything else
// (stdlib, third-party) is reported as not found; those references are
// simply absent from the graph rather than causing an error.
type moduleImporter struct {
	load func(path string) (*types.Package, error)
}

func (mi moduleImporter) Import(path string) (*types.Package, error) {
	return mi.load(path)
}

func isIfaceMethod(f *types.Func) bool {
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false
	}
	r := sig.Recv()
	return r != nil && types.IsInterface(r.Type())
}

func main() {
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fset := token.NewFileSet()
	fmt.Fprintln(os.Stderr, "funcgraph:", runtime.Version(), "mode: module-only (no external type-checking)")

	cmd := exec.Command("go", "list", "-e", "-json", "./...")
	cmd.Dir = root
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	_ = cmd.Run() // -e keeps going past broken packages; we read whatever came out

	var mods []listPkg
	dec := json.NewDecoder(&stdout)
	for dec.More() {
		var p listPkg
		if err := dec.Decode(&p); err != nil {
			break
		}
		if !p.DepOnly && !p.Standard {
			mods = append(mods, p)
		}
	}

	// Importer for the module's OWN packages only: each is type-checked once
	// and cached here, so cross-package calls within the module still
	// resolve. A package outside the module (stdlib or a dependency) is left
	// unresolved on purpose -- the graph only needs functions the module
	// defines, and skipping external type-checking is what makes this run in
	// minutes instead of hours on a large repository.
	checked := map[string]*types.Package{}
	infoByPkg := map[string]*types.Info{}
	modByPath := map[string]listPkg{}
	for _, p := range mods {
		modByPath[p.ImportPath] = p
	}

	var funcs []fn
	var direct, dynRecs [][2]string
	methodsByName := map[string][]string{}
	typeErrs := 0
	panics := 0

	parsed := map[string][]*ast.File{}
	parseOne := func(p listPkg) []*ast.File {
		if fs, ok := parsed[p.ImportPath]; ok {
			return fs
		}
		var files []*ast.File
		for _, name := range p.GoFiles {
			f, _ := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, parser.SkipObjectResolution)
			if f != nil {
				files = append(files, f)
			}
		}
		parsed[p.ImportPath] = files
		return files
	}

	loading := map[string]bool{}
	var load func(path string) (*types.Package, error)
	load = func(path string) (*types.Package, error) {
		if pkg, ok := checked[path]; ok {
			return pkg, nil
		}
		p, ok := modByPath[path]
		if !ok {
			return nil, fmt.Errorf("%q is outside the module", path)
		}
		if loading[path] {
			return nil, fmt.Errorf("import cycle at %q", path)
		}
		loading[path] = true
		defer delete(loading, path)

		files := parseOne(p)
		info := &types.Info{Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
		conf := types.Config{
			Importer:    moduleImporter{load},
			FakeImportC: true,
			Error:       func(error) { typeErrs++ },
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					panics++
					if panics <= 2 {
						st := string(debug.Stack())
						if len(st) > 2500 {
							st = st[:2500]
						}
						fmt.Fprintf(os.Stderr, "panic while checking %s: %v\n%s\n", path, r, st)
					}
				}
			}()
			pkg, _ := conf.Check(path, fset, files, info)
			checked[path] = pkg
		}()
		infoByPkg[path] = info
		return checked[path], nil
	}

	for _, p := range mods {
		if _, err := load(p.ImportPath); err != nil {
			continue
		}
		files := parsed[p.ImportPath]
		info := infoByPkg[p.ImportPath]
		if info == nil {
			continue
		}
		for _, f := range files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				pos := fset.Position(fd.Pos())
				end := fset.Position(fd.End())
				rel, err := filepath.Rel(root, pos.Filename)
				if err != nil {
					rel = pos.Filename
				}
				rel = filepath.ToSlash(rel)
				id := p.ImportPath + "." + fd.Name.Name
				if o, ok := info.Defs[fd.Name].(*types.Func); ok && o != nil {
					id = o.Origin().FullName()
				}
				if fd.Name.Name == "init" || fd.Name.Name == "_" {
					id = fmt.Sprintf("%s@%s:%d", id, rel, pos.Line)
				}
				funcs = append(funcs, fn{ID: id, File: rel, Start: pos.Line, End: end.Line})
				if fd.Recv != nil {
					methodsByName[fd.Name.Name] = append(methodsByName[fd.Name.Name], id)
				}
				caller := id
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					ident, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					fo, ok := info.Uses[ident].(*types.Func)
					if !ok || fo == nil {
						return true
					}
					if isIfaceMethod(fo) {
						dynRecs = append(dynRecs, [2]string{caller, fo.Name()})
					} else {
						direct = append(direct, [2]string{caller, fo.Origin().FullName()})
					}
					return true
				})
			}
		}
	}

	set := map[string]bool{}
	for _, f := range funcs {
		set[f.ID] = true
	}
	seen := map[[2]string]bool{}
	var edges, dyn [][2]string
	for _, r := range direct {
		if r[0] != r[1] && set[r[1]] && !seen[r] {
			seen[r] = true
			edges = append(edges, r)
		}
	}
	seenDyn := map[[2]string]bool{}
	for _, r := range dynRecs {
		for _, m := range methodsByName[r[1]] {
			e := [2]string{r[0], m}
			if e[0] != e[1] && !seenDyn[e] {
				seenDyn[e] = true
				dyn = append(dyn, e)
			}
		}
	}

	out := output{Funcs: funcs, Edges: edges, DynEdges: dyn, Stats: map[string]int{
		"packages": len(mods), "funcs": len(funcs), "edges": len(edges),
		"dyn_edges": len(dyn), "type_errors": typeErrs, "panics": panics,
	}}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
'''

CATS = ["changed_function", "linked_1", "linked_2", "unconnected", "no_function"]


def git(repo, *a):
    r = subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def ensure_helper():
    HELPER_DIR.mkdir(parents=True, exist_ok=True)
    src, binp = HELPER_DIR / "main.go", HELPER_DIR / "funcgraph"
    if not (src.exists() and src.read_text() == GO_SRC and binp.exists()):
        src.write_text(GO_SRC)
        (HELPER_DIR / "go.mod").write_text(GO_MOD)
        r = subprocess.run(["go", "build", "-o", "funcgraph", "."],
                           cwd=str(HELPER_DIR), capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("helper build failed:\n" + r.stderr[-2000:])
        print("helper (re)built:", binp)
    return binp


def run_helper(binp, snap):
    # No external type-checking (see main.go), so this runs in at most a few
    # minutes even on a large repository, with no dependency on Go version.
    r = subprocess.run([str(binp)], cwd=str(snap), capture_output=True,
                       text=True, timeout=900)
    if not r.stdout.strip():
        raise RuntimeError("helper produced no output.\nSTART OF ERROR:\n"
                           + r.stderr[:1800] + "\n...\nEND OF ERROR:\n" + r.stderr[-600:])
    return json.loads(r.stdout), r.stderr


def changed_lines(repo, sha):
    """file -> set of changed line numbers in the new version."""
    out = git(repo, "diff", "-U0", "--no-color", sha + "~1", sha, "--", "*.go")
    res, cur = collections.defaultdict(set), None
    for line in out.splitlines():
        if line.startswith("+++ "):
            p = line[4:]
            cur = p[2:] if p.startswith("b/") else None
        elif line.startswith("@@") and cur:
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if not m:
                continue
            start = int(m.group(1))
            n = int(m.group(2)) if m.group(2) is not None else 1
            if n == 0:
                res[cur].update((start, start + 1))  # pure deletion
            else:
                res[cur].update(range(start, start + n))
    return res


def index_funcs(graph):
    by_file = collections.defaultdict(list)
    for f in graph["funcs"]:
        by_file[f["file"]].append((f["start"], f["end"], f["id"]))
    return by_file


def enclosing(by_file, file, line):
    best = None
    for s, e, i in by_file.get(file, ()):
        if s <= line <= e and (best is None or e - s < best[1] - best[0]):
            best = (s, e, i)
    return best[2] if best else None


def changed_funcs(by_file, changed):
    out = set()
    for file, lines in changed.items():
        for s, e, i in by_file.get(file, ()):
            if any(s <= ln <= e for ln in lines):
                out.add(i)
    return out


def hops(start, edge_lists, maxhop=2):
    adj = collections.defaultdict(set)
    for edges in edge_lists:
        for a, b in edges:
            adj[a].add(b)
            adj[b].add(a)
    dist = {i: 0 for i in start}
    frontier = set(start)
    for h in range(1, maxhop + 1):
        nxt = set()
        for n in frontier:
            for m in adj.get(n, ()):
                if m not in dist:
                    dist[m] = h
                    nxt.add(m)
        frontier = nxt
    return dist


def label(fid, dist):
    if fid is None:
        return "no_function"
    d = dist.get(fid)
    return {0: "changed_function", 1: "linked_1", 2: "linked_2"}.get(d, "unconnected")


def load_graph(binp, repo, sha, work, cache_dir):
    cp = cache_dir / (Path(repo).name + "-" + sha[:12] + ".json")
    if cp.exists():
        return json.loads(cp.read_text())
    snap = corpus.snapshot(Path(repo), sha, work)
    try:
        g, err = run_helper(binp, snap)
    finally:
        corpus.cleanup_snapshot(Path(repo), snap)
    if "panic" in err:
        print("   helper reported a crash in some package (first lines):")
        print("   " + err[:1500].replace("\n", "\n   "))
    cache_dir.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(g))
    return g


def summarize(records, title):
    n = len(records)
    print("\n" + title + "  (findings: %d)" % n)
    if not n:
        return
    print("  %-18s %14s %14s" % ("", "strict", "cautious"))
    for c in CATS:
        s = sum(1 for r in records if r["strict"] == c)
        k = sum(1 for r in records if r["cautious"] == c)
        print("  %-18s %6d (%5.1f%%) %6d (%5.1f%%)" % (c, s, 100.0 * s / n, k, 100.0 * k / n))
    s = sum(1 for r in records if r["strict"] == "unconnected")
    k = sum(1 for r in records if r["cautious"] == "unconnected")
    print("  removable          %6d (%5.1f%%) %6d (%5.1f%%)" % (s, 100.0 * s / n, k, 100.0 * k / n))
    tf = sum(1 for r in records if not r["in_changed_file"])
    print("  touched-only filter would remove: %d (%.1f%%)" % (tf, 100.0 * tf / n))
    same = sum(1 for r in records if r["in_changed_file"] and r["strict"] != "changed_function")
    print("  in a changed file but not in a changed function: %d" % same)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--only", default=None, help="commit prefix, to test one commit")
    ap.add_argument("--maxhop", type=int, default=1,
                    help="how many call-graph hops from a changed function still "
                         "count as connected (default 1; a spot check on commit "
                         "e21c37703ed0 showed hop=2 keeps the one known artifact "
                         "as connected, hop=1 correctly excludes it, and removes "
                         "3x more of the queue besides)")
    ap.add_argument("--workdir", default="/tmp/isast-func-work")
    ap.add_argument("--cache", default="/tmp/isast-funcgraph-cache")
    ap.add_argument("--out", default=None)
    ap.add_argument("--sample", type=int, default=0, help="write N findings to label by hand")
    a = ap.parse_args()

    repo = Path(a.repo).resolve()
    conn = db.connect(a.db)
    binp = ensure_helper()
    work, cache = Path(a.workdir), Path(a.cache)
    shas = [r[0] for r in conn.execute("SELECT DISTINCT commit_sha FROM runs WHERE condition='diff'")]
    if a.only:
        shas = [s for s in shas if s.startswith(a.only)]
    print("%d commits" % len(shas))

    records, stats = [], []
    for i, sha in enumerate(shas, 1):
        rows = db.finding_rows(conn, a.name, sha, "diff", "semgrep")
        print("[%d/%d] %s  findings=%d" % (i, len(shas), sha[:12], len(rows)), flush=True)
        if not rows:
            continue
        parent = git(repo, "rev-parse", sha + "~1").strip()
        full = db.fingerprints(conn, a.name, sha, "full", "semgrep")
        base = db.fingerprints(conn, a.name, parent, "full", "semgrep")
        try:
            g = load_graph(binp, repo, sha, work, cache)
        except Exception as e:  # keep going, report at the end
            print("   graph FAILED:", str(e)[:200])
            continue
        stats.append((sha[:10], g["stats"]))
        idx = index_funcs(g)
        chg_lines = changed_lines(repo, sha)
        chg = changed_funcs(idx, chg_lines)
        d_strict = hops(chg, [g["edges"]], maxhop=a.maxhop)
        d_caut = hops(chg, [g["edges"], g["dyn_edges"]], maxhop=a.maxhop)
        for fp, r in rows.items():
            fid = enclosing(idx, r["file"], r["start_line"])
            records.append(dict(
                commit=sha, file=r["file"], line=r["start_line"], rule=r["rule_id"],
                function=fid, strict=label(fid, d_strict), cautious=label(fid, d_caut),
                in_changed_file=r["file"] in chg_lines,
                artifact=fp not in full, reported=fp not in base))

    print("\nhelper stats per commit (type_errors / panics show how complete the graph is):")
    for s, st in stats:
        print("  %s funcs=%d edges=%d dyn=%d type_errors=%d panics=%d" % (
            s, st["funcs"], st["edges"], st["dyn_edges"], st["type_errors"], st.get("panics", 0)))

    summarize(records, "ALL diff-scan findings")
    summarize([r for r in records if r["reported"]], "Findings left AFTER baseline differencing")
    for r in records:
        if r["artifact"]:
            print("\nscope-truncation artifact: %s:%s  strict=%s cautious=%s" % (
                r["file"], r["line"], r["strict"], r["cautious"]))

    out = a.out or (a.name + "_func_result.json")
    Path(out).write_text(json.dumps(records, indent=1))
    print("\nwrote", out)

    if a.sample and records:
        random.seed(1)
        rem = [r for r in records if r["cautious"] == "unconnected"]
        kept = [r for r in records if r["cautious"] != "unconnected"]
        pick = random.sample(rem, min(len(rem), a.sample // 2)) + \
            random.sample(kept, min(len(kept), a.sample - a.sample // 2))
        sp = a.name + "_labels.csv"
        with open(sp, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["commit", "file", "line", "rule", "strict", "cautious", "code", "connected? (y/n)"])
            for r in pick:
                src = git(repo, "show", r["commit"] + ":" + r["file"]).splitlines()
                code = src[r["line"] - 1].strip() if 0 < r["line"] <= len(src) else ""
                w.writerow([r["commit"][:10], r["file"], r["line"], r["rule"].split(".")[-1],
                            r["strict"], r["cautious"], code, ""])
        print("wrote", sp, "(label the last column by hand)")


if __name__ == "__main__":
    main()