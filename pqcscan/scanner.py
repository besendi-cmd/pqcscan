from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .rules import ALL_RULES, FILE_RULES, RULES, SEVERITIES, Rule

LANGUAGES = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c",
    ".cs": "csharp",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
}
MANIFESTS = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "setup.cfg",
    "package.json", "Cargo.toml", "Gemfile", "composer.json", "go.mod",
}
KEY_EXTENSIONS = {".pem", ".crt", ".cer", ".key", ".pub"}
DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".nox",
    ".mypy_cache", ".pytest_cache", "dist", "build", "target", "vendor", "site-packages", ".idea", ".vscode",
}
DEFAULT_EXCLUDED_DIR_GLOBS = ["*.egg-info", "*.dist-info"]
DEFAULT_EXCLUDED_FILES = [
    "*.md", "*.rst", "*.adoc", "*.min.js", "*.map", "*.lock", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "*.sarif",
]
IGNORE_FILE = ".pqcscanignore"
SUPPRESS = re.compile(r"pqcscan:\s*ignore")
PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.S)
MAX_FILE_BYTES = 2_000_000


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    algorithm: str
    category: str
    threat: str
    path: str
    line: int
    column: int
    snippet: str
    recommendation: str
    fingerprint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    baseline_suppressed: int | None = None
    baseline_resolved: int | None = None

    def by_severity(self) -> dict[str, int]:
        counts = {s: 0 for s in reversed(SEVERITIES)}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def inventory(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.algorithm] = counts.get(f.algorithm, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def at_or_above(self, severity: str) -> list[Finding]:
        floor = SEVERITIES.index(severity)
        return [f for f in self.findings if SEVERITIES.index(f.severity) >= floor]


def language_for(path: Path) -> str:
    if path.name in MANIFESTS or path.name.startswith("requirements") and path.suffix == ".txt":
        return "manifest"
    return LANGUAGES.get(path.suffix.lower(), "other")


def _finding(rule: Rule, algorithm: str, rel: str, line: int, column: int, snippet: str) -> Finding:
    return Finding(rule.id, rule.title, rule.severity, algorithm, rule.category, rule.threat, rel, line, column,
                   snippet.strip()[:200], rule.recommendation)


def scan_text(text: str, rel: str, language: str) -> list[Finding]:
    """Line-by-line rule matching; keeps the most severe (then most specific) finding per family on each line."""
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if SUPPRESS.search(line):
            continue
        best: dict[str, tuple[Rule, re.Match]] = {}
        for rule in RULES:
            m = rule.search(language, line)
            if not m:
                continue
            current = best.get(rule.family)
            if current is None or SEVERITIES.index(rule.severity) > SEVERITIES.index(current[0].severity):
                best[rule.family] = (rule, m)
        for rule, m in best.values():
            findings.append(_finding(rule, rule.algorithm_for(m), rel, lineno, m.start() + 1, line))
    return findings


def describe_key(key) -> str | None:
    from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519  # pqcscan: ignore (type checks only)

    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC-{key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, x25519.X25519PublicKey):
        return "X25519"
    if isinstance(key, x448.X448PublicKey):
        return "X448"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA-{key.key_size}"
    if isinstance(key, dh.DHPublicKey):
        return f"DH-{key.key_size}"
    return None


_LABEL_ALGORITHMS = {"RSA": "RSA", "EC": "EC", "DSA": "DSA", "OPENSSH": "SSH key"}


def inspect_pem(label: str, block: str) -> tuple[str, str | None] | None:
    """Return (rule_id, algorithm) for a PEM block, or None if it is not quantum-vulnerable key material."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    data = block.encode()
    if label in ("CERTIFICATE", "TRUSTED CERTIFICATE"):
        try:
            return "PQC101", describe_key(x509.load_pem_x509_certificate(data).public_key())
        except Exception:
            return None
    if "PRIVATE KEY" in label:
        fallback = _LABEL_ALGORITHMS.get(label.split()[0], "unknown (encrypted)")
        if "ENCRYPTED" in label or "ENCRYPTED" in block[:200]:
            return "PQC100", fallback
        try:
            if label == "OPENSSH PRIVATE KEY":
                key = serialization.load_ssh_private_key(data, password=None)
            else:
                key = serialization.load_pem_private_key(data, password=None)
            return "PQC100", describe_key(key.public_key())
        except Exception:
            return ("PQC100", fallback) if label.split()[0] in _LABEL_ALGORITHMS else None
    if "PUBLIC KEY" in label:
        try:
            return "PQC102", describe_key(serialization.load_pem_public_key(data))
        except Exception:
            return None
    return None


def scan_pem_blocks(text: str, rel: str) -> list[Finding]:
    findings = []
    for m in PEM_BLOCK.finditer(text):
        result = inspect_pem(m.group(1), m.group(0))
        if not result or not result[1]:
            continue
        rule = FILE_RULES[result[0]]
        line = text.count("\n", 0, m.start()) + 1
        findings.append(_finding(rule, result[1], rel, line, 1, f"-----BEGIN {m.group(1)}-----"))
    return findings


def _load_ignore(root: Path) -> list[str]:
    path = root / IGNORE_FILE
    if not path.is_file():
        return []
    lines = (l.strip() for l in path.read_text(errors="replace").splitlines())
    return [l.rstrip("/") for l in lines if l and not l.startswith("#")]


def _excluded(rel: str, name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) or rel.startswith(p + "/") for p in patterns)


def iter_files(root: Path, excludes: list[str]):
    if root.is_file():
        yield root, root.name
        return
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in DEFAULT_EXCLUDED_DIRS
            and not any(fnmatch.fnmatch(d, g) for g in DEFAULT_EXCLUDED_DIR_GLOBS)
            and not _excluded((base / d).relative_to(root).as_posix(), d, excludes)
        )
        for name in sorted(filenames):
            path = base / name
            rel = path.relative_to(root).as_posix()
            if not _excluded(rel, name, DEFAULT_EXCLUDED_FILES + excludes):
                yield path, rel


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan(root: str | os.PathLike, excludes: list[str] | None = None, min_severity: str = "low") -> ScanResult:
    root_path = Path(root).resolve()
    patterns = list(excludes or []) + (_load_ignore(root_path) if root_path.is_dir() else [])
    result = ScanResult(root=str(root_path))
    for path, rel in iter_files(root_path, patterns):
        text = read_text(path)
        if text is None:
            continue
        result.files_scanned += 1
        if "-----BEGIN " in text:
            result.findings.extend(scan_pem_blocks(text, rel))
        if path.suffix.lower() not in KEY_EXTENSIONS or path.suffix.lower() == ".pub":
            result.findings.extend(scan_text(text, rel, language_for(path)))
    result.findings = [f for f in result.at_or_above(min_severity)]
    from .baseline import assign_fingerprints

    assign_fingerprints(result.findings)
    result.findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.path, f.line, f.rule_id))
    return result


__all__ = ["ALL_RULES", "Finding", "ScanResult", "scan", "scan_text", "language_for"]
