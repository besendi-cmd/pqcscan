from __future__ import annotations

import hmac
import json
import re
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..rules import SEVERITIES
from .store import Store, is_quantum_vulnerable

REPO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
MAX_BODY_BYTES = 50_000_000
FINDING_FIELDS = {"rule_id": str, "title": str, "severity": str, "algorithm": str, "threat": str, "path": str,
                  "line": int, "snippet": str, "recommendation": str}


def _validate(payload) -> tuple[str, str | None, str | None, dict]:
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    repo = payload.get("repo")
    if not isinstance(repo, str) or not REPO_NAME.fullmatch(repo) or ".." in repo:
        raise ValueError("repo must be a name like 'org/service' (letters, digits, . _ / -)")
    meta = []
    for key in ("commit", "branch"):
        value = payload.get(key)
        if value is not None and (not isinstance(value, str) or len(value) > 200):
            raise ValueError(f"{key} must be a string of at most 200 characters")
        meta.append(value)
    report = payload.get("report")
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("report must be a pqcscan JSON report")
    for f in report["findings"]:
        if not isinstance(f, dict) or any(not isinstance(f.get(k), t) for k, t in FINDING_FIELDS.items()):
            raise ValueError("each finding needs " + ", ".join(FINDING_FIELDS))
        if f["severity"] not in SEVERITIES:
            raise ValueError(f"unknown severity {f['severity']!r}")
    files = report.get("files_scanned", 0)
    if not isinstance(files, int) or isinstance(files, bool) or files < 0:
        raise ValueError("files_scanned must be a non-negative integer")
    inventory = report.get("inventory", {})
    if not isinstance(inventory, dict) or any(
        not isinstance(k, str) or not isinstance(v, int) or isinstance(v, bool) for k, v in inventory.items()
    ):
        raise ValueError("inventory must map algorithm names to counts")
    return repo, meta[0], meta[1], report


def _chart(series: list[tuple[str, int]], width: int = 640, height: int = 140) -> dict | None:
    if not series:
        return None
    top = max(v for _, v in series) or 1
    step = width / max(len(series) - 1, 1)
    points = [(round(i * step, 1), round(height - v / top * (height - 10) - 5, 1)) for i, (_, v) in enumerate(series)]
    if len(points) == 1:
        points.append((width, points[0][1]))
    return {"width": width, "height": height, "top": top, "points": " ".join(f"{x},{y}" for x, y in points),
            "first": series[0][0], "last": series[-1][0], "current": series[-1][1]}


def _status(scan: dict) -> str:
    return "ready" if scan["quantum_vulnerable"] == 0 else "at-risk"


def create_app(db_path: str | Path, token: str | None) -> FastAPI:
    store = Store(db_path)
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    templates.env.globals.update(severities=list(reversed(SEVERITIES)), status=_status)
    app = FastAPI(title="pqcscan dashboard", docs_url=None, redoc_url=None, openapi_url=None)

    def overview_data() -> dict:
        repos = store.latest()
        inventory: dict[str, int] = {}
        for r in repos:
            for algorithm, n in r["inventory"].items():
                inventory[algorithm] = inventory.get(algorithm, 0) + n
        ready = sum(1 for r in repos if _status(r) == "ready")
        return {
            "repos": repos,
            "totals": {
                "repos": len(repos),
                "ready": ready,
                "readiness": round(100 * ready / len(repos)) if repos else 0,
                "quantum_vulnerable": sum(r["quantum_vulnerable"] for r in repos),
                **{s: sum(r[s] for r in repos) for s in SEVERITIES},
            },
            "inventory": dict(sorted(inventory.items(), key=lambda kv: (-kv[1], kv[0]))),
        }

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.post("/api/v1/scans", status_code=201)
    async def upload_scan(request: Request):
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        if not token or scheme.lower() != "bearer" or not hmac.compare_digest(value.encode(), token.encode()):
            raise HTTPException(401, "invalid or missing upload token")
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            raise HTTPException(413, "report too large")
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise HTTPException(413, "report too large")
            chunks.append(chunk)
        body = b"".join(chunks)
        try:
            repo, commit, branch, report = _validate(json.loads(body))
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        scan_id = store.add_scan(repo, commit, branch, report)
        return {"id": scan_id, "repo": repo, "url": str(request.url_for("repo_page", name=repo))}

    @app.get("/api/v1/summary")
    def summary():
        data = overview_data()
        data["trend"] = store.trend()
        return data

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html", {**overview_data(), "chart": _chart(store.trend())})

    @app.get("/repos/{name:path}", response_class=HTMLResponse, name="repo_page")
    def repo_page(request: Request, name: str):
        repo = store.repo(name)
        if repo is None:
            raise HTTPException(404, "repository not found")
        latest = repo["history"][0]
        findings = sorted(repo["report"]["findings"],
                          key=lambda f: (-SEVERITIES.index(f["severity"]), f["path"], f["line"]))
        series = [(h["created"][:10], h["quantum_vulnerable"]) for h in reversed(repo["history"])]
        return templates.TemplateResponse(request, "repo.html", {
            "repo": repo, "latest": latest, "findings": findings, "chart": _chart(list(dict(series).items())),
            "quantum": is_quantum_vulnerable, "inventory": dict(sorted(repo["inventory"].items(), key=lambda kv: (-kv[1], kv[0]))),
        })

    return app
