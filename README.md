# Scope, Not Context: Why Per-Commit Static Analysis Is Noisy in Go

CS 6727 Cyber Security Practicum, Georgia Tech, Fall 2026. Mizanur Rahman.

Teams often turn off per-commit security scans because the alerts are too noisy. The usual explanation is lost context: a scan of changed files cannot see a sanitizer in another file. This project tests that explanation on two Go projects, Gitea and Traefik, with Semgrep Pro.

## What we found

- Lost context is real but rare: 1 of 237 findings on Gitea, 0 of 42 on Traefik.
- The bigger cause is scope. Engines scan whole packages, not files. A scoped scan reads 11 to 16 times more code than the commit changed, and 62 to 86 percent of its findings are in files nobody edited.
- A function-level filter keeps a finding only if it is in a changed function or one call away from one. It removes 57 to 73 percent of findings.
- In a blind-labeled sample, 1 of 54 to 5 of 54 removed findings looked connected to the change. Most kept findings are still unrelated, so the filter is safe in our sample but not precise.
- This study does not show that per-commit scanning finds real vulnerabilities. The engine reported nothing on three reverted Gitea security fixes.

The full write-up is the final report. The decision journal records how the study changed along the way.

## What is in this repository

| Path | What it is |
|---|---|
| `DECISIONS.md` | Decision journal. Entries in the order the work was done, plus a retrospective entry written on Nov 9, 2026. |
| `incremental-sast/isast/` | The measurement pipeline: commit snapshots, scoped Semgrep runs, SARIF parsing, the scan comparison, SQLite storage. |
| `incremental-sast/scripts/` | Experiments: decision runs, the package-level and function-level filters, blind labeling tools, and the demo page. |
| `incremental-sast/results_*.db` | Stored scan results for each run. |
| `incremental-sast/*_func_result.json` | Per-finding filter verdicts for Gitea and Traefik. |
| `incremental-sast/*_blind.csv`, `*_key.csv`, `*_ai.csv` | Blind-labeling sheets, the hidden filter verdicts, and the AI labels. |
| `reproducer/` | Small hand-built examples used to check the scope effect before the corpus runs. |

`incremental-sast/README.md` holds the early harness notes from week 1. Some of its plans changed later. `DECISIONS.md` says how.

The Gitea and Traefik source trees are not included. Clone them yourself (see below).

## Requirements

- Python 3.9 or later. The pipeline uses only the standard library. `pip install -r incremental-sast/requirements.txt` adds the analysis extras.
- Semgrep with the Pro engine: `pip install semgrep`, then `semgrep login` and `semgrep install-semgrep-pro`. Results in the report use Semgrep 1.136.0 with `p/default`.
- Go 1.21 or later, for the function-level filter.
- Full clones of the corpora. Partial clones (`--filter=blob:none`) caused silent empty scans in this study.

```
git clone https://github.com/go-gitea/gitea corpus/gitea
git clone https://github.com/traefik/traefik corpus/traefik
```

## Run it

All commands run from `incremental-sast/`. Every script has `--help`.

One commit, end to end (full scan at the commit, scoped scan at the commit, full scan at the parent):

```
python3 -m isast.cli --db results.db one-commit --repo ../corpus/gitea --commit <sha> --lang go --pro
```

Function-level filter over stored results (no new scans):

```
python3 scripts/func_filter.py --repo ../corpus/gitea --db results_default.db --name gitea
```

Blind labeling: `label_blind.py make` writes a sheet with the filter verdict hidden, `label_assist.py` handles AI labels with a human hold-out, and `label_blind.py score` reports counts with 95 percent Wilson intervals.

Demo page, one tab per project:

```
python3 scripts/demo_report.py --out demo.html --tab Gitea,gitea_func_result.json,e21c37703e,../corpus/gitea --tab Traefik,traefik_func_result.json,0331801c72,../corpus/traefik
```

It should print `Gitea: full 56, filter 24, differenced 1, both 0` and `Traefik: full 12, filter 6, differenced 0, both 0`.

## Limits

Two repositories, one language, one ruleset. The full scan is a check for lost scope, not proof that a finding is a real bug. The filter has not been run in a live CI pipeline. See the report's Limitations and Threats to Validity sections.

## AI use

Claude was used for debugging, drafting, labeling and parts of the code, including the function-level filter, the labeling tools and the demo page. The author ran, checked and accepted all code and results. Details are in the report's AI Usage Acknowledgement.
