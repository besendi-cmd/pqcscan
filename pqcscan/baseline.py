"""Baselines: record today's findings so CI only fails on findings introduced later."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .scanner import Finding, ScanResult

BASELINE_VERSION = 1


def assign_fingerprints(findings: list[Finding]) -> None:
    """Fingerprint = rule + file + normalised code, ignoring line numbers so edits elsewhere in a file don't break it.

    Identical lines in the same file get an occurrence index (in line order) to stay distinct.
    """
    seen: dict[str, int] = {}
    for f in sorted(findings, key=lambda f: (f.path, f.line, f.column, f.rule_id)):
        key = "\0".join((f.rule_id, f.path, f.algorithm, re.sub(r"\s+", " ", f.snippet).strip()))
        index = seen.get(key, 0)
        seen[key] = index + 1
        f.fingerprint = hashlib.sha256(f"{key}\0{index}".encode("utf-8", "surrogatepass")).hexdigest()[:32]


def write_baseline(result: ScanResult, path: str | Path) -> int:
    entries = sorted(
        ({"fingerprint": f.fingerprint, "rule_id": f.rule_id, "path": f.path, "algorithm": f.algorithm,
          "snippet": f.snippet} for f in result.findings),
        key=lambda e: (e["path"], e["rule_id"], e["fingerprint"]),
    )
    data = {
        "tool": "pqcscan",
        "baseline_version": BASELINE_VERSION,
        "pqcscan_version": __version__,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": entries,
    }
    Path(path).write_text(json.dumps(data, indent=2) + "\n")
    return len(entries)


def load_baseline(path: str | Path) -> set[str]:
    data = json.loads(Path(path).read_text())
    if data.get("tool") != "pqcscan" or "findings" not in data:
        raise ValueError(f"{path} is not a pqcscan baseline")
    return {e["fingerprint"] for e in data["findings"]}


def apply_baseline(result: ScanResult, fingerprints: set[str]) -> None:
    """Drop findings already in the baseline; count baseline entries that are now fixed."""
    current = {f.fingerprint for f in result.findings}
    result.baseline_suppressed = sum(1 for f in result.findings if f.fingerprint in fingerprints)
    result.baseline_resolved = len(fingerprints - current)
    result.findings = [f for f in result.findings if f.fingerprint not in fingerprints]
