import json
from pathlib import Path
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

from pqcscan import upload as upload_module
from pqcscan.cli import main
from pqcscan.dashboard import app as app_module
from pqcscan.dashboard.app import create_app
from pqcscan.report import to_json
from pqcscan.scanner import scan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"
TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path / "dash.db", TOKEN))


def _payload(repo="acme/payments", findings=None, commit="abc1234def", branch="main"):
    report = json.loads(to_json(scan(EXAMPLES)))
    if findings is not None:
        report["findings"] = findings
    return {"repo": repo, "commit": commit, "branch": branch, "report": report}


def test_upload_requires_token(client):
    assert client.post("/api/v1/scans", json=_payload()).status_code == 401
    assert client.post("/api/v1/scans", json=_payload(), headers={"Authorization": "Bearer nope"}).status_code == 401


def test_upload_disabled_without_server_token(tmp_path):
    client = TestClient(create_app(tmp_path / "dash.db", None))
    assert client.post("/api/v1/scans", json=_payload(), headers={"Authorization": "Bearer "}).status_code == 401


@pytest.mark.parametrize("payload", [
    [], {"repo": "../etc", "report": {"findings": []}}, {"repo": "a b", "report": {"findings": []}},
    {"repo": "ok", "report": {}}, {"repo": "ok", "report": {"findings": [{"severity": "high"}]}},
    {"repo": "ok", "commit": 5, "report": {"findings": []}},
    {"repo": "ok", "report": {"findings": [], "inventory": None}},
    {"repo": "ok", "report": {"findings": [], "inventory": {"RSA": "3"}}},
    {"repo": "ok", "report": {"findings": [], "files_scanned": "many"}},
    {"repo": "ok", "report": {"findings": [], "files_scanned": -1}},
])
def test_upload_rejects_invalid_payloads(client, payload):
    assert client.post("/api/v1/scans", json=payload, headers=AUTH).status_code == 422


def test_overview_tracks_progress(client):
    first = _payload()
    r = client.post("/api/v1/scans", json=first, headers=AUTH)
    assert r.status_code == 201
    assert r.json()["url"].endswith("/repos/acme/payments")
    client.post("/api/v1/scans", json=_payload("acme/web", findings=[]), headers=AUTH)

    summary = client.get("/api/v1/summary").json()
    total = len(first["report"]["findings"])
    quantum = sum(1 for f in first["report"]["findings"] if f["threat"] != "classical")
    assert summary["totals"]["repos"] == 2
    assert summary["totals"]["ready"] == 1
    assert summary["totals"]["readiness"] == 50
    assert summary["totals"]["quantum_vulnerable"] == quantum
    assert sum(summary["totals"][s] for s in ("critical", "high", "medium", "low")) == total
    assert summary["inventory"]["RSA"] >= 1

    fixed = [f for f in first["report"]["findings"] if f["threat"] == "classical"]
    client.post("/api/v1/scans", json=_payload(findings=fixed), headers=AUTH)
    summary = client.get("/api/v1/summary").json()
    assert summary["totals"]["readiness"] == 100
    assert summary["totals"]["quantum_vulnerable"] == 0
    assert summary["trend"][-1][1] == 0


def test_html_pages(client):
    page = client.get("/")
    assert page.status_code == 200 and "No scans yet" in page.text
    findings = _payload()["report"]["findings"]
    findings[0]["snippet"] = "<script>alert(1)</script>"
    client.post("/api/v1/scans", json=_payload(findings=findings), headers=AUTH)
    page = client.get("/")
    assert "acme/payments" in page.text and "at risk" in page.text and "<polyline" in page.text
    repo = client.get("/repos/acme/payments")
    assert repo.status_code == 200
    assert "<script>alert(1)</script>" not in repo.text and "&lt;script&gt;" in repo.text
    assert "abc1234" in repo.text and "ML-KEM" in repo.text
    assert client.get("/repos/acme/missing").status_code == 404


def test_cli_upload_round_trip(client, monkeypatch, capsys):
    class Response:
        def __init__(self, r):
            self.r = r

        def read(self):
            return self.r.content

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout):
        assert request.full_url == "http://dash.test/api/v1/scans"
        r = client.post("/api/v1/scans", content=request.data, headers=dict(request.header_items()))
        if r.status_code >= 400:
            raise HTTPError(request.full_url, r.status_code, "error", {}, None)
        return Response(r)

    monkeypatch.setattr(upload_module, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_SHA", "feedface")
    monkeypatch.delenv("GITHUB_HEAD_REF", raising=False)
    monkeypatch.setenv("GITHUB_REF_NAME", "release")

    monkeypatch.delenv("PQCSCAN_TOKEN", raising=False)
    assert main(["scan", str(EXAMPLES), "--upload", "http://dash.test/", "--repo-name", "acme/api"]) == 2

    monkeypatch.setenv("PQCSCAN_TOKEN", "wrong")
    assert main(["scan", str(EXAMPLES), "--upload", "http://dash.test/", "--repo-name", "acme/api"]) == 2
    assert "HTTP 401" in capsys.readouterr().err

    monkeypatch.setenv("PQCSCAN_TOKEN", TOKEN)
    assert main(["scan", str(EXAMPLES), "--upload", "http://dash.test/", "--repo-name", "acme/api"]) == 0
    assert "/repos/acme/api" in capsys.readouterr().err
    latest = client.get("/api/v1/summary").json()["repos"][0]
    assert latest["name"] == "acme/api" and latest["commit_sha"] == "feedface" and latest["branch"] == "release"
    assert latest["critical"] > 0


def test_cli_upload_sends_findings_hidden_by_baseline(client, monkeypatch, tmp_path):
    sent = {}

    def fake_urlopen(request, timeout):
        sent.update(json.loads(request.data))
        raise HTTPError(request.full_url, 500, "error", {}, None)

    monkeypatch.setattr(upload_module, "urlopen", fake_urlopen)
    monkeypatch.setenv("PQCSCAN_TOKEN", TOKEN)
    b = tmp_path / "b.json"
    main(["scan", str(EXAMPLES), "--write-baseline", str(b), "-o", str(tmp_path / "out.txt")])
    main(["scan", str(EXAMPLES), "--baseline", str(b), "--upload", "http://dash.test"])
    assert len(sent["report"]["findings"]) > 0


def test_detect_repo_from_git_remote(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", "git@github.com:acme/vault.git"], check=True)
    assert upload_module.detect_repo(tmp_path) == "acme/vault"
    assert upload_module.detect_repo(tmp_path / "missing") == "missing"

    for remote in ("https://gitlab.example.com/division-a/team/service.git", "ssh://git@host:22/division-a/team/service/"):
        subprocess.run(["git", "-C", str(tmp_path), "remote", "set-url", "origin", remote], check=True)
        assert upload_module.detect_repo(tmp_path) == "division-a/team/service"


def test_upload_rejects_oversized_body(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_BODY_BYTES", 100)
    assert client.post("/api/v1/scans", json=_payload(), headers=AUTH).status_code == 413
    body = json.dumps(_payload()).encode()
    r = client.post("/api/v1/scans", content=iter([body[:80], body[80:]]), headers=AUTH)
    assert r.status_code == 413


def test_cli_upload_ignores_min_severity(monkeypatch, tmp_path):
    sent = {}

    def fake_urlopen(request, timeout):
        sent.update(json.loads(request.data))
        raise HTTPError(request.full_url, 500, "error", {}, None)

    monkeypatch.setattr(upload_module, "urlopen", fake_urlopen)
    monkeypatch.setenv("PQCSCAN_TOKEN", TOKEN)
    main(["scan", str(EXAMPLES), "--min-severity", "critical", "--upload", "http://dash.test"])
    assert {f["severity"] for f in sent["report"]["findings"]} > {"critical"}


def test_single_file_upload_is_refused(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(upload_module, "urlopen", lambda *a, **k: pytest.fail("must not upload"))
    monkeypatch.setenv("PQCSCAN_TOKEN", TOKEN)
    (tmp_path / "keys.py").write_text("key = rsa.generate_private_key(65537, 2048)\n")
    assert main(["scan", str(tmp_path / "keys.py"), "--upload", "http://dash.test"]) == 2
    assert "repository directory" in capsys.readouterr().err


def test_upload_does_not_follow_redirects():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append((self.path, self.headers.get("Authorization")))
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_POST

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(upload_module.UploadError, match="HTTP 302"):
            upload_module.upload(scan(EXAMPLES), f"http://127.0.0.1:{server.server_port}", TOKEN, repo="acme/api")
    finally:
        server.shutdown()
    assert [path for path, _ in seen] == ["/api/v1/scans"]


def test_repo_page_lists_algorithms_without_report_inventory(client):
    payload = _payload(repo="acme/bare")
    del payload["report"]["inventory"]
    assert client.post("/api/v1/scans", json=payload, headers=AUTH).status_code == 201
    algorithm = payload["report"]["findings"][0]["algorithm"]
    assert algorithm in client.get("/repos/acme/bare").text.split("Algorithms in use", 1)[1]
