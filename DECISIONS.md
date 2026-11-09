
## Week 1 findings

Semgrep 1.157.0, p/golang, --pro
- Scope bounding: confirmed. Pro respects the target file list; a cross-file
  taint flow is NOT found when scoping to the source file alone.
  => Condition A is genuinely a truncated scan.
- Spurious-case reproduction: FAILED on toy. regexp.MatchString validation is
  not modeled as a sanitizer, so the full scan reports the finding too.
  Nothing to spuriously re-report. Source verified with go vet.
- Corruption incident: heredoc tab-completion inserted filenames in place of
  tabs. Two experiments invalidated and rerun. => add a build check before
  scanning any snapshot in the pipeline.




### CodeQL file-level scoping: NOT VIABLE (Go)
A database built from a subset of a Go package fails type resolution
(undefined: sql, http). Sinks are type-based, so the analysis returns zero
results — verified: /tmp/part.csv had 0 rows. The full-vs-part difference
therefore measures extraction failure, not context truncation.
=> Condition A cannot be file-scoped under CodeQL. Package-level scoping is
the candidate replacement; Go packages are compilable units.




### CodeQL package-level scoping (--source-root=<subdir>): ALSO NOT VIABLE
Extraction fails on cross-package imports ("Warning: encountered errors
extracting package pkgtest/sanitizer") because the module root is above the
source-root. Analysis returned 0 rows. Combined with the file-level result,
CodeQL offers no mechanism for genuinely scope-truncated analysis on Go —
its database requires a resolvable build.
Path-filtering full-scan results is NOT equivalent: the analyzer still saw
everything, so it cannot produce context-truncation artifacts by construction.
=> Condition A is implementable only in Semgrep. Since oracle and conditions
must share an engine, Semgrep becomes the primary engine; CodeQL is retained
for cross-checking sanitizer modeling only.




### Fingerprint join: VIABLE
Semgrep 1.157.0 emits matchBasedId/v1 under the SARIF `fingerprints` field
(not `partialFingerprints` — normalize.py patched). 7/7 findings carried
fingerprints on pocketbase@8213ccff; no collapsing under the fallback key.

### Scope bounding: CONFIRMED at repo scale
diff(--pro) == diff(intrafile) == 0 on the same commit. Consistent with the
three-file reproducer: Semgrep respects the target file list.




### Corpus screening: pocketbase REJECTED
456 Go files (below 500 floor); 12 files with http handlers, 5 touching SQL.
p/default full scan: 44 findings, of which 3 taint-class and 19 in ui/ JS.
=> Insufficient taint surface. Context truncation only affects taint findings,
so spurious rate would rest on a denominator of ~3.
New corpus criterion: candidates must yield a usable count of Go taint-class
findings, screened before selection.




### Scan timing (pocketbase, 456 Go files, Semgrep 1.157 --pro)
p/default, 1 job                        4m43
p/default, --jobs $(nproc)              4m06   (13% — Pro interfile phase is
                                                largely sequential; parallelism
                                                is not a useful lever)
p/golang, --include=*.go, no vendor/test, parallel   1m33
=> Standardize on p/golang + Go-only includes. p/default wasted ~70% of runtime
on JS/YAML/Dockerfile targets irrelevant to a Go study (19 of 44 findings were
in ui/).
Budget: ~3 min/commit; halves with contiguous commit sampling (each full scan
serves as the next commit's baseline).





### Week 1 status
RESOLVED:
- Fingerprint join viable (SARIF `fingerprints` field, not partialFingerprints)
- Semgrep target list bounds analysis => Condition A implementable
- CodeQL cannot scope-truncate Go analysis (file or package level) => Semgrep
  becomes primary engine; CodeQL retained only for sanitizer cross-checks
- Ruleset: p/golang + Go-only includes (1m33 vs 4m43 for p/default on 456 files)
- Parallelism is not a lever (13% gain; Pro interfile phase is sequential)
- pocketbase rejected: 456 Go files, 3 taint findings

OPEN — the question that decides the design:
- Does any Go repo yield enough taint-class findings for context truncation to
  be measurable? p/golang on pocketbase gave 7 findings, 0 taint. If gitea and
  traefik look the same, the hypothesis needs reframing: the noise would be
  dominated by pattern-rule findings, which scope truncation cannot affect.




### Timing: gitea (3,087 Go files, 2,042 scanned after vendor/test excludes)
p/golang --pro --jobs $(nproc):  8m17 real, 24m17 user (~3x parallel speedup;
better than pocketbase's 13% — more independent work at this scale).
64 findings.
=> ~17 min/commit for two full scans; ~8.5 min with contiguous sampling.
30 commits on gitea alone ≈ 4-8 hours. Budget is tight but feasible for one
large repo plus one smaller.




### Taint-rule prevalence: THE BINDING CONSTRAINT
gitea (3,087 Go files, 2,042 scanned):
  p/golang:  64 findings, 10 taint (16%)
  p/gosec:   72 findings,  0 taint (0%) - adds pattern rules only
pocketbase: 7 findings (p/golang), 0 taint
=> Context truncation only affects taint-class findings, which are a small
minority of Go SAST output across two independent rule packs.
The mechanism is real (demonstrated in the 2-file reproducer) but rare.
=> RQ1 reframed: measure the COMPOSITION of the diff-scan queue and which
classes survive baseline differencing, rather than assuming context artifacts
dominate. Prediction: pattern findings survive at near-zero rate; if they do
not, the standard architecture fails for a different reason.




### Scan cost asymmetry (gitea, p/golang, --pro)
full scan:  ~750s
diff scan:  ~3s
=> 250x. This is why teams adopt diff-scoped scanning despite its precision
cost, and it bounds what any context-reuse scheme can spend: Condition C must
stay near diff-scan latency to be worth deploying.




### Semgrep Pro interfile accepts ONE target only
"[ERROR] Inter-file analysis can only take a single target (for multiple
files pass a directory)". File-list scoping is impossible with --pro, so
Condition A as written in the proposal is not expressible in either engine
(CodeQL fails for a different reason: unresolvable types).
=> Condition A is redefined as DIRECTORY/PACKAGE-scoped: analyze the packages
containing changed files. This is also what a CI system would realistically
do for a compiled language, and it converges with the CodeQL constraint.
Earlier "targets bound the analysis" result stands but was measured with a
single file, which is the only form interfile mode accepts.




### Condition A redefined: PACKAGE-scoped (verified working)
Semgrep Pro interfile rejects a file list; directory targets work
(modules/public/ -> exit 0, 6 files, 1 finding). CodeQL fails on file
subsets for an unrelated reason (unresolvable types). Both engines
independently force package granularity, which is also what a CI system
would realistically do for Go. Condition A now scans the set of packages
containing changed files, one package per invocation, results unioned.
Also fixed: a non-zero exit previously recorded as "0 findings", which made
a crashed scan indistinguishable from a real null result. Failed scans are
now refused rather than stored.


### VERIFIED CONTEXT ARTIFACT (real code, cross-package)
gitea routers/web/base.go:76 - open-redirect
  source + sink: routers/web/base.go (avatarPath -> http.Redirect)
  sanitiser:     modules/util/path.go:72 PathJoinRelX - DIFFERENT PACKAGE
  CE (single-function taint, no interfile): REPORTS it
  Pro (interfile):                          RESOLVES it
First instance of the hypothesised mechanism confirmed outside a toy. n=1 of
60 findings, so it establishes existence, not prevalence.
Note the reverse asymmetry: Pro found 5 taint findings CE missed. The weaker
engine trades false positives for false negatives in both directions.


### Diff-scoped scanning can cost MORE than a full scan
gitea, p/default, --pro, package-scoped:
  commit 2d3ad4a5 (12 pkgs): full 900s, diff 1091s  -> diff is SLOWER
  commit bcd913a4 ( 4 pkgs): full 858s, diff  319s  -> diff is 2.7x faster
Per-package invocation pays fixed setup repeatedly. With p/golang the same
commits were 170x cheaper at one package. The economics of diff-scoped
scanning depend jointly on ruleset size and package fan-out, and invert
entirely for broad rulesets on wide commits.



### Refinement: the vulnerable file was NOT modified
commit e21c37703ed0 ("centralize repository-scoped authorization", 26 files)
  changed dirs include routers/web, but NOT modules/util
  git show e21c37703ed0 -- routers/web/base.go  ->  EMPTY

base.go was pulled into scope only because a sibling file in routers/web
changed. The sanitiser package modules/util was never scanned. The tool
therefore reported a pre-existing, already-safe redirect in a file the
developer did not touch, as a newly introduced finding.
This is the strongest form of the mechanism: the artifact is attached to
untouched code and is an artifact of package-granular scoping, not of the
change itself.



### HEADLINE: package-granular scoping analyses 19.3x more code than changed
gitea, 12 commits, p/default, --pro:
  files changed:  135
  files scanned:  2,609  (19.3x exposure)
  diff-scan findings: 237, of which 203 (86%) in files never modified
  context-truncation artifacts: 1 (0.4%)

The exposure ratio is forced, not chosen: Semgrep Pro interfile rejects file
lists and CodeQL cannot build a database from a file subset, so package
granularity is the only implementable scope for a compiled language.
Package size bounds exposure but does not predict finding count - two commits
touching 320 and 513 package files produced only 6 and 9 findings, while one
touching 105 produced 24. Exposure sets the ceiling; whether those packages
contain finding-prone code sets the actual count.


### Second repository: traefik (selected for structural contrast)
Screening: 769 Go files, 191 with http.ResponseWriter, 42 findings under
p/default of which 23 taint-class (55% taint, vs gitea's ~40%).

Package structure:
  gitea    381 pkgs, median 3.0, mean 8.1, max 259
  traefik  156 pkgs, median 2.0, mean 4.9, max  62

PREDICTION (recorded before the run): traefik's exposure ratio will be
materially below gitea's 19.3x, because it lacks gitea's long tail of large
packages. If exposure drives the untouched-file rate, the 86% should fall too.
A confirmed prediction makes the finding a function of package structure
rather than a constant; a failed one means something else drives exposure.





### PREDICTION CONFIRMED on traefik (second repository)
                        gitea      traefik
  mean package size      8.1         4.9
  max package size       259          62
  exposure ratio        19.3x        5.9x
  untouched findings     86%         62%
  reported after diff      5           0
  spurious                 1           0
  cost inversions       2 of 12     3 of 10

Exposure and the untouched-file rate both fell with package size, as
predicted and recorded before the run. Package structure determines how much
unrelated code a diff-scoped scan analyses and therefore how much unrelated
output a developer sees. Even in a well-factored codebase, 62% of reported
findings concern untouched files.
Cost inversion generalises and worsens with package fan-out: traefik commit
0331801c (10 pkgs) took 841s diff vs 210s full - 4x SLOWER than scanning
everything.




### CORRECTION: the "Scan cost asymmetry ... 250x" entry above is invalid
That diff-scan timing (~3s) was measured before discovering Semgrep Pro
rejects a file-list target ("Inter-file analysis can only take a single
target"). The scan almost certainly exited non-zero and produced an empty
SARIF, which was recorded at the time as a fast successful result. The
exit-status check added afterward (see silent-failure fix) would have
caught this. Do not cite the 250x figure. Real diff-scan costs are the
package-scoped, exit-checked timings under "Diff-scoped scanning can cost
MORE than a full scan" and the later decision-run outputs.




### Filter experiment: import-aware filtering is safer than naive, and correct on the known artifact
gitea:    naive removes 85.7% (203), import-aware removes 73.4% (174);
          29 findings the naive filter would wrongly hide (import-related).
traefik:  naive removes 61.9% (26), import-aware removes 26.2% (11);
          15 findings the naive filter would wrongly hide.
The one verified artifact (base.go:76, commit e21c37703ed0) classifies as
UNRELATED under the import graph - correctly removed by the safer filter,
consistent with the earlier finding that this commit's changed packages
have no import path to modules/util.
Method note: reachability is via package IMPORTS (go list), not verified
call edges - deliberately conservative (can only move findings toward
"related", never hide a true connection), after two unrecoverable x/tools
SSA-builder crashes ruled out the call-graph approach.


## Added Nov 9, 2026 (written after the fact, summarizing work done after the entries above)

These entries were written after the work, from the results and scripts in incremental-sast/. They are not contemporaneous records.

### Function-level filter replaces the package-import filter
The import-aware filter removed only 4.2% (gitea) and 4.8% (traefik) of findings, because files in one package call each other with no import. Replaced by a function-level filter: keep a finding if its enclosing function holds a line changed by the commit, or is linked to such a function by a call resolved with go/types. External dependencies are not resolved (too slow on gitea). Calls through an interface are linked to every method of that name (cautious view); a strict view uses direct calls only.
=> Function-level removes 70.9% (gitea) and 57.1% (traefik) in the cautious view.

### Hop limit 1
On the commit with the verified artifact (e21c37703ed0), a 2-hop limit still counted base.go:76 as connected; 1 hop removed it and removed three times more of that commit's queue. The corpus run used 1 hop. The limit was set from one commit and not swept.

### RQ4 (caching, call-graph expansion) not built
Artifacts are 0.4% of findings (1 of 237 gitea, 0 of 42 traefik), below the proposal's own bar for building a fix.

### Blind-labelled check of the filter
All 42 traefik findings and 60 gitea findings (30 removed, 30 kept) were labelled connected or not, with the filter's verdict hidden. Labels were made mostly by an AI assistant; the author labelled a random hold-out of 20 per repository. Borderline labels default to not connected; a second reading flips them. Agreement: gitea 19 of 20; traefik 18 of 20 (not independent, because the author cross-verified those rows with the assistant).
=> Removed but connected: 1 of 30 and 0 of 24 (default); 4 of 30 and 1 of 24 (borderline counted connected).
Decision: report both readings, report the hold-out agreement, and disclose the AI assistance.

### Recall check on three reverted gitea security fixes
Reverted d5e6f273f, 671a2f5dc and 0c67849e6 to simulate commits that introduce the bug. Semgrep Pro 1.136.0 with p/default flagged none in the vulnerable files (scans of the changed files only). Early runs reported 0 findings in 0.2 s because the Pro binary was missing; exit status 2 showed the failure, and semgrep install-semgrep-pro fixed it.
=> The study does not show real-vulnerability detection.

### Demonstration
Review-queue page (scripts/demo_report.py), one tab per repository: gitea e21c37703ed0 (56 findings, 24 kept, 1 after differencing, 0 after both) and traefik 0331801c7232 (12, 6, 0, 0).

### Corrections and file counts (added Nov 9, 2026)
CORRECTION to the exposure ratios above (19.3x gitea, 5.9x traefik; 135 and 45 files changed, 2,609 and 265 scanned): the first count was non-recursive and included test files. The recursive count that excludes test files gives 15.8x on gitea (111 changed, 1,758 scanned) and 10.9x on traefik (29 changed, 317 scanned). The direction of the prediction is unchanged. The untouched-file rates (86%, 62%) are computed from the findings and are not affected. The final report uses the corrected ratios.
Commit e21c37703ed0 changed 27 files in total, 26 of them Go files. The "26 files" in earlier entries and in the report counts Go files only.
