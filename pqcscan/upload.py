from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .report import to_json
from .scanner import ScanResult


class UploadError(Exception):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = build_opener(_NoRedirect)


def urlopen(request: Request, timeout: float):
    """Open without following redirects, so the bearer token never reaches another URL."""
    return _opener.open(request, timeout=timeout)


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def detect_repo(root: Path) -> str:
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    remote = _git(root, "config", "--get", "remote.origin.url")
    if remote:
        path = urlparse(remote).path if "://" in remote else remote.rpartition(":")[2]
        path = path.strip("/")
        path = path[:-4] if path.endswith(".git") else path
        if "/" in path:
            return path
    return root.resolve().name


def detect_commit(root: Path) -> tuple[str | None, str | None]:
    commit = os.environ.get("GITHUB_SHA") or _git(root, "rev-parse", "HEAD")
    branch = (os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME")
              or _git(root, "rev-parse", "--abbrev-ref", "HEAD"))
    return commit, branch


def upload(result: ScanResult, url: str, token: str, repo: str | None = None) -> dict:
    root = Path(result.root)
    commit, branch = detect_commit(root)
    payload = {
        "repo": repo or detect_repo(root),
        "commit": commit,
        "branch": branch,
        "report": json.loads(to_json(result)),
    }
    request = Request(
        url.rstrip("/") + "/api/v1/scans",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read())
    except HTTPError as e:
        raise UploadError(f"dashboard returned HTTP {e.code}: {e.read().decode(errors='replace')[:300]}") from e
    except (URLError, OSError, ValueError) as e:
        raise UploadError(f"cannot reach dashboard at {url}: {e}") from e
