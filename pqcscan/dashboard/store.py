from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ..rules import SEVERITIES

SCHEMA = """
CREATE TABLE IF NOT EXISTS repos (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES repos(id),
    created TEXT NOT NULL,
    commit_sha TEXT,
    branch TEXT,
    files_scanned INTEGER NOT NULL,
    critical INTEGER NOT NULL,
    high INTEGER NOT NULL,
    medium INTEGER NOT NULL,
    low INTEGER NOT NULL,
    quantum_vulnerable INTEGER NOT NULL,
    inventory TEXT NOT NULL,
    report TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_repo ON scans(repo_id, id);
"""

SUMMARY_COLUMNS = ("id", "created", "commit_sha", "branch", "files_scanned", *reversed(SEVERITIES),
                   "quantum_vulnerable")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_quantum_vulnerable(finding: dict) -> bool:
    return finding["threat"] != "classical"


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self._db() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def add_scan(self, repo: str, commit: str | None, branch: str | None, report: dict,
                 created: str | None = None) -> int:
        findings = report["findings"]
        counts = {s: 0 for s in SEVERITIES}
        inventory: dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] += 1
            inventory[f["algorithm"]] = inventory.get(f["algorithm"], 0) + 1
        quantum = sum(1 for f in findings if is_quantum_vulnerable(f))
        created = created or _now()
        with self._db() as db:
            db.execute("INSERT OR IGNORE INTO repos (name, created) VALUES (?, ?)", (repo, created))
            (repo_id,) = db.execute("SELECT id FROM repos WHERE name = ?", (repo,)).fetchone()
            cur = db.execute(
                "INSERT INTO scans (repo_id, created, commit_sha, branch, files_scanned, critical, high, medium, low,"
                " quantum_vulnerable, inventory, report) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (repo_id, created, commit, branch, int(report.get("files_scanned", 0)), counts["critical"],
                 counts["high"], counts["medium"], counts["low"], quantum, json.dumps(inventory),
                 json.dumps(report)),
            )
            return cur.lastrowid

    def latest(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                "SELECT repos.name, " + ", ".join(f"scans.{c}" for c in SUMMARY_COLUMNS) + ", scans.inventory"
                " FROM repos JOIN scans ON scans.id = (SELECT MAX(id) FROM scans WHERE repo_id = repos.id)"
                " ORDER BY scans.quantum_vulnerable DESC, scans.critical DESC, repos.name"
            ).fetchall()
        return [{**dict(r), "inventory": json.loads(r["inventory"])} for r in rows]

    def repo(self, name: str) -> dict | None:
        with self._db() as db:
            row = db.execute("SELECT id FROM repos WHERE name = ?", (name,)).fetchone()
            if row is None:
                return None
            history = db.execute(
                "SELECT " + ", ".join(SUMMARY_COLUMNS) + " FROM scans WHERE repo_id = ? ORDER BY id DESC",
                (row["id"],),
            ).fetchall()
            report = db.execute("SELECT report FROM scans WHERE id = ?", (history[0]["id"],)).fetchone()
        return {"name": name, "history": [dict(h) for h in history], "report": json.loads(report["report"])}

    def trend(self) -> list[tuple[str, int]]:
        """Org-wide quantum-vulnerable usages at the end of each day that had a scan."""
        with self._db() as db:
            rows = db.execute("SELECT repo_id, created, quantum_vulnerable FROM scans ORDER BY created, id").fetchall()
        latest: dict[int, int] = {}
        series: dict[str, int] = {}
        for r in rows:
            latest[r["repo_id"]] = r["quantum_vulnerable"]
            series[r["created"][:10]] = sum(latest.values())
        return list(series.items())
