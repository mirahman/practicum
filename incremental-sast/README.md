# incremental-sast

Measurement harness for context-truncation false positives in diff-scoped
static analysis, over Go and TypeScript corpora.

The "oracle" is not a downloaded tool — it is the comparison in
`isast/compare.py`. A whole-repository scan at each commit serves as ground
truth for scope fidelity; anything a diff-scoped scan reports that the full
scan does not is a context-truncation artifact by construction. That gives
automatic labels at scale, with no manual triage in the primary loop.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install semgrep

# Cross-file analysis needs the Pro binary:
semgrep login
semgrep install-semgrep-pro
```

## Week 1 — do this before writing any more code

```bash
git clone --filter=blob:none https://github.com/OWNER/REPO /tmp/target
SHA=$(python -m isast.cli sample --repo /tmp/target --lang go --n 5 | python -c 'import json,sys;print(json.load(sys.stdin)[0])')

python scripts/validate_fingerprints.py \
    --repo /tmp/target --commit $SHA --lang go --pro
```

This answers three questions that decide whether the study is viable:

1. **Do findings carry stable fingerprints across scans?** Every metric
   joins on Semgrep's `matchBasedId`. If it shifts when scope changes,
   the joins are measuring noise and you need the structural fallback in
   `normalize._fallback_key`.
2. **Does `--pro` respect target selection?** Semgrep scope is controlled
   by the paths you pass, which is coarser than CodeQL's database source
   set. If interfile analysis reads beyond your targets, Condition A is
   not what the proposal claims it is. Record the answer either way.
3. **Are the spurious findings real artifacts?** The script prints
   candidates. Open five by hand and confirm the sanitizer or type
   constraint that resolves them lives outside the changed files.

Twenty minutes here saves a rewrite in week 8.

## End-to-end on one commit

```bash
python -m isast.cli one-commit \
    --repo /tmp/target --commit $SHA --lang go --pro
```

Runs three scans (full at C, diff at C, full at C~1), stores everything in
`results.db`, and prints the metrics — including the headline number, the
share of spurious findings that survive baseline differencing and reach a
developer as "newly introduced".

Get this vertical slice working on one repo and one commit before adding
breadth. It produces a real result immediately.

## Metrics

| Name | Meaning |
|---|---|
| `spurious_rate` | Diff-scope findings absent from the full scan |
| `miss_rate` | Real findings on changed code that diff scope loses |
| `survival_rate` | Spurious findings surviving baseline differencing — **the headline** |
| `reported_precision` | Share of what current practice shows that is not an artifact |

## Go call graph

`isast/callgraph_go.py` writes and drives a small Go helper built on
`go/ssa` and `x/tools/go/callgraph` (VTA). It powers both scope expansion
and summary invalidation.

```bash
python -c "from pathlib import Path; from isast import callgraph_go as cg; cg.write_helper(Path('cmd/callgraph'))"
cd cmd/callgraph && go mod tidy && go build -o callgraph-helper .
```

Keep the completeness statistics it returns. Call-graph quality is the
independent variable for RQ4 — the Go/TypeScript contrast is the study's
central claim, and it only works if completeness is measured rather than
assumed.

## Layout

```
isast/
  corpus.py        git worktree snapshots, commit sampling, file filters
  runner.py        semgrep invocation, scope construction
  normalize.py     SARIF -> flat records, fingerprint extraction
  compare.py       the oracle: four set operations
  callgraph_go.py  Go call graph, invalidation policies
  db.py            SQLite schema
scripts/
  validate_fingerprints.py   week-1 gate
config/
  repos.example.json         corpus selection criteria
```

## Not yet implemented

Condition C (cached-context reuse) is the research contribution and is
deliberately absent — build it after Conditions A and B produce numbers.
Extracting and re-injecting dataflow summaries is not a supported workflow
in either engine. If that proves impractical, the documented fallback is
to approximate cached context by pre-seeding the scan with the baseline's
relevant file set: coarser, but it tests the same hypothesis.

TypeScript call-graph extraction is also unimplemented; plan to derive it
from CodeQL's extracted relations rather than parsing TypeScript yourself.
