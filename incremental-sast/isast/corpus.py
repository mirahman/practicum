"""Git operations: snapshot a commit into a worktree, list changed files."""
from __future__ import annotations


import subprocess
from pathlib import Path

# Extensions we care about, by language. Anything else is ignored when
# building the diff target list.
LANG_EXTS = {
    "go": {".go"},
    "typescript": {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"},
}

# Paths that are noise for this study. Test and vendor code inflates
# finding counts without exercising request-to-sink taint flows.
EXCLUDE_MARKERS = (
    "/vendor/", "/node_modules/", "/testdata/", "/third_party/",
    "/dist/", "/build/", "/.git/",
)


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def is_excluded(path: str) -> bool:
    p = "/" + path
    return any(m in p for m in EXCLUDE_MARKERS)


def changed_files(repo: Path, commit_sha: str, lang: str) -> list[str]:
    """Files touched by commit_sha, filtered to the language and excluding noise."""
    raw = _git(repo, "diff", "--name-only", f"{commit_sha}~1", commit_sha)
    exts = LANG_EXTS[lang]
    files = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or is_excluded(line):
            continue
        if Path(line).suffix in exts:
            files.append(line)
    return files


def sample_commits(repo: Path, lang: str, n: int = 50,
                   max_files: int = 25, since: str | None = None) -> list[str]:
    """Commits touching source files in the target language.

    max_files filters out mega-commits (dependency bumps, mass refactors)
    whose diff scope is close to the whole repo — those make the
    diff-vs-full comparison degenerate.
    """
    args = ["log", "--format=%H", "--no-merges"]
    if since:
        args += [f"--since={since}"]
    shas = _git(repo, *args).splitlines()

    picked = []
    for sha in shas:
        try:
            files = changed_files(repo, sha, lang)
        except subprocess.CalledProcessError:
            continue  # root commit or shallow boundary
        if files and len(files) <= max_files:
            picked.append(sha)
        if len(picked) >= n:
            break
    return picked


def snapshot(repo: Path, commit_sha: str, dest: Path) -> Path:
    """Materialize commit_sha in its own worktree so scans see a clean tree."""
    dest = dest / commit_sha[:12]
    # Existence is not enough: a failed attempt can leave an empty directory,
    # which is then scanned as though it were the snapshot and yields zero
    # findings. Require actual source before reusing.
    if dest.exists() and any(dest.rglob("*.go")):
        return dest
    if dest.exists():
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "add", "--detach",
         str(dest), commit_sha],
        capture_output=True, text=True, check=True,
    )
    if not any(dest.rglob("*.go")):
        raise RuntimeError(
            f"snapshot {dest} contains no .go files after worktree add; "
            "refusing to scan an empty tree")
    return dest


def cleanup_snapshot(repo: Path, dest: Path) -> None:
    subprocess.run(
        ["git", "-C", str(repo), "worktree", "remove", "--force", str(dest)],
        capture_output=True, text=True,
    )
