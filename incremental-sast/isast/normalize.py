"""SARIF -> flat finding records.

The join key across scans is Semgrep's match-based fingerprint, which is
designed to survive line movement. Everything downstream depends on it
being (a) present and (b) stable across scope changes.

`scripts/validate_fingerprints.py` tests exactly that. Run it before you
build anything else.
"""
from __future__ import annotations


from typing import Iterator

FINGERPRINT_KEYS = (
    "matchBasedId/v1",
    "matchBasedId",
)


def _fingerprint(result: dict) -> str | None:
    """Semgrep 1.157 emits match ids under the standard SARIF `fingerprints`
    field; older versions used `partialFingerprints`. Check both."""
    for field in ("fingerprints", "partialFingerprints"):
        fp = result.get(field) or {}
        for k in FINGERPRINT_KEYS:
            if k in fp:
                return fp[k]
        if fp:
            return next(iter(fp.values()))
    return None


def _fallback_key(result: dict) -> str:
    """Structural key for engines/results without a usable fingerprint.

    Deliberately excludes line numbers, which shift between scans.
    Coarser than the real fingerprint: two matches of the same rule in
    the same file collapse together. Report how often this path is taken.
    """
    import hashlib
    loc = result["locations"][0]["physicalLocation"]
    msg = (result.get("message", {}) or {}).get("text", "")
    snippet = (loc.get("region", {}) or {}).get("snippet", {}).get("text", "")
    digest = hashlib.sha1((msg + "\x00" + snippet).encode()).hexdigest()[:16]
    return f"{result.get('ruleId')}::{loc['artifactLocation']['uri']}::{digest}"


def normalize(sarif: dict) -> tuple[list[dict], int]:
    """Returns (records, n_fallback_keys_used)."""
    records: list[dict] = []
    fallbacks = 0

    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            locs = res.get("locations") or []
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            region = phys.get("region", {}) or {}

            fp = _fingerprint(res)
            if fp is None:
                fp = _fallback_key(res)
                fallbacks += 1

            records.append({
                "fingerprint": fp,
                "rule_id": res.get("ruleId", ""),
                "file": _clean_uri(art.get("uri", "")),
                "start_line": region.get("startLine"),
                "end_line": region.get("endLine"),
                "severity": res.get("level", ""),
                "message": (res.get("message", {}) or {}).get("text", "")[:500],
            })

    return records, fallbacks


def _clean_uri(uri: str) -> str:
    for prefix in ("file://", "./"):
        if uri.startswith(prefix):
            uri = uri[len(prefix):]
    return uri.lstrip("/")


def iter_rule_classes(records: list[dict]) -> Iterator[tuple[str, str]]:
    """Crude rule -> class mapping for the per-rule-class breakdown.

    Taint-based rules are the ones expected to degrade under truncation;
    pattern-based ones should not. Refine this mapping against the actual
    rule IDs your config produces.
    """
    TAINT_HINTS = ("sqli", "injection", "ssrf", "path-traversal",
                   "xss", "deserial", "command-injection", "taint")
    PATTERN_HINTS = ("hardcoded", "secret", "weak-", "insecure-hash",
                     "crypto", "tls", "permissions")
    for r in records:
        rid = r["rule_id"].lower()
        if any(h in rid for h in TAINT_HINTS):
            cls = "taint"
        elif any(h in rid for h in PATTERN_HINTS):
            cls = "pattern"
        else:
            cls = "other"
        yield r["rule_id"], cls