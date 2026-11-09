"""SQLite storage. Flat schema on purpose — every metric is a query."""
from __future__ import annotations


import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY,
    repo          TEXT NOT NULL,
    commit_sha    TEXT NOT NULL,
    condition     TEXT NOT NULL,   -- full | diff | expand1 | expand2 | cached
    engine        TEXT NOT NULL,   -- semgrep | codeql
    target_count  INTEGER,
    wall_clock_s  REAL,
    exit_status   INTEGER,
    notes         TEXT,
    UNIQUE (repo, commit_sha, condition, engine)
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    file         TEXT NOT NULL,
    start_line   INTEGER,
    end_line     INTEGER,
    severity     TEXT,
    message      TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp  ON findings(fingerprint);

-- Files changed by each sampled commit; needed for the miss-rate metric.
CREATE TABLE IF NOT EXISTS changed_files (
    repo        TEXT NOT NULL,
    commit_sha  TEXT NOT NULL,
    file        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_changed ON changed_files(repo, commit_sha);
"""


def connect(path: str | Path = "results.db") -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def record_run(conn, *, repo, commit_sha, condition, engine,
               target_count, wall_clock_s, exit_status, notes="") -> int:
    cur = conn.execute(
        """INSERT OR REPLACE INTO runs
           (repo, commit_sha, condition, engine, target_count,
            wall_clock_s, exit_status, notes)
           VALUES (?,?,?,?,?,?,?,?)""",
        (repo, commit_sha, condition, engine, target_count,
         wall_clock_s, exit_status, notes),
    )
    conn.commit()
    return cur.lastrowid


def record_findings(conn, run_id: int, findings: list[dict]) -> None:
    conn.executemany(
        """INSERT INTO findings
           (run_id, fingerprint, rule_id, file, start_line, end_line, severity, message)
           VALUES (:run_id, :fingerprint, :rule_id, :file,
                   :start_line, :end_line, :severity, :message)""",
        [{**f, "run_id": run_id} for f in findings],
    )
    conn.commit()


def record_changed_files(conn, repo: str, commit_sha: str, files: list[str]) -> None:
    conn.execute("DELETE FROM changed_files WHERE repo=? AND commit_sha=?",
                 (repo, commit_sha))
    conn.executemany(
        "INSERT INTO changed_files (repo, commit_sha, file) VALUES (?,?,?)",
        [(repo, commit_sha, f) for f in files],
    )
    conn.commit()


def fingerprints(conn, repo: str, commit_sha: str,
                 condition: str, engine: str) -> set[str]:
    rows = conn.execute(
        """SELECT f.fingerprint FROM findings f
           JOIN runs r ON r.id = f.run_id
           WHERE r.repo=? AND r.commit_sha=? AND r.condition=? AND r.engine=?""",
        (repo, commit_sha, condition, engine),
    ).fetchall()
    return {r["fingerprint"] for r in rows}


def finding_rows(conn, repo, commit_sha, condition, engine) -> dict[str, sqlite3.Row]:
    rows = conn.execute(
        """SELECT f.* FROM findings f
           JOIN runs r ON r.id = f.run_id
           WHERE r.repo=? AND r.commit_sha=? AND r.condition=? AND r.engine=?""",
        (repo, commit_sha, condition, engine),
    ).fetchall()
    return {r["fingerprint"]: r for r in rows}


def changed_files(conn, repo: str, commit_sha: str) -> set[str]:
    rows = conn.execute(
        "SELECT file FROM changed_files WHERE repo=? AND commit_sha=?",
        (repo, commit_sha),
    ).fetchall()
    return {r["file"] for r in rows}
