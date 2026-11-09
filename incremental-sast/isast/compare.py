"""The oracle comparison. Four set operations produce the headline results.

Definitions (all at one commit C, with parent P):

  full      = findings from whole-repo scan at C          [ground truth]
  diff      = findings from changed-files-only scan at C   [Condition A]
  baseline  = findings from whole-repo scan at P           [for differencing]

  spurious  = diff - full
      Findings the truncated scan reports that whole-program analysis
      resolves away. Context-truncation artifacts by construction.

  missed    = {f in full : f.file in changed_files} - diff
      Real findings on changed code that the truncated scan loses.

  reported  = diff - baseline                              [Condition B output]
      What current industry practice actually shows a developer.

  survivors = spurious & reported
      >>> THE HEADLINE. Spurious findings that survive baseline
      differencing and reach the developer as "newly introduced". <<<
"""
from __future__ import annotations


from dataclasses import dataclass, asdict

from . import db


@dataclass
class CommitMetrics:
    repo: str
    commit_sha: str
    engine: str
    n_full: int
    n_diff: int
    n_baseline: int
    n_spurious: int
    n_missed: int
    n_reported: int
    n_survivors: int

    @property
    def spurious_rate(self) -> float:
        return self.n_spurious / self.n_diff if self.n_diff else 0.0

    @property
    def miss_rate(self) -> float:
        denom = self.n_missed + (self.n_diff - self.n_spurious)
        return self.n_missed / denom if denom else 0.0

    @property
    def survival_rate(self) -> float:
        """Of spurious findings, the fraction that reach the developer."""
        return self.n_survivors / self.n_spurious if self.n_spurious else 0.0

    @property
    def reported_precision(self) -> float:
        """Of what Condition B shows, the fraction that is NOT an artifact."""
        if not self.n_reported:
            return 1.0
        return 1.0 - (self.n_survivors / self.n_reported)

    def as_row(self) -> dict:
        d = asdict(self)
        d.update(
            spurious_rate=round(self.spurious_rate, 4),
            miss_rate=round(self.miss_rate, 4),
            survival_rate=round(self.survival_rate, 4),
            reported_precision=round(self.reported_precision, 4),
        )
        return d


def compute(conn, repo: str, commit_sha: str, parent_sha: str,
            engine: str = "semgrep",
            diff_condition: str = "diff") -> CommitMetrics:
    full = db.fingerprints(conn, repo, commit_sha, "full", engine)
    diff = db.fingerprints(conn, repo, commit_sha, diff_condition, engine)
    baseline = db.fingerprints(conn, repo, parent_sha, "full", engine)

    changed = db.changed_files(conn, repo, commit_sha)
    full_rows = db.finding_rows(conn, repo, commit_sha, "full", engine)

    spurious = diff - full
    full_on_changed = {fp for fp, r in full_rows.items() if r["file"] in changed}
    missed = full_on_changed - diff
    reported = diff - baseline
    survivors = spurious & reported

    return CommitMetrics(
        repo=repo, commit_sha=commit_sha, engine=engine,
        n_full=len(full), n_diff=len(diff), n_baseline=len(baseline),
        n_spurious=len(spurious), n_missed=len(missed),
        n_reported=len(reported), n_survivors=len(survivors),
    )


def spurious_by_rule_class(conn, repo, commit_sha, engine="semgrep",
                           diff_condition="diff") -> dict[str, int]:
    """Which rule classes produce context artifacts. Expect taint >> pattern."""
    from .normalize import iter_rule_classes

    full = db.fingerprints(conn, repo, commit_sha, "full", engine)
    diff_rows = db.finding_rows(conn, repo, commit_sha, diff_condition, engine)

    spurious_rows = [dict(r) for fp, r in diff_rows.items() if fp not in full]
    counts: dict[str, int] = {}
    for _rid, cls in iter_rule_classes(spurious_rows):
        counts[cls] = counts.get(cls, 0) + 1
    return counts
