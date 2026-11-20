from __future__ import annotations

import json

from . import __version__
from .rules import ALL_RULES
from .scanner import ScanResult

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
INFO_URI = "https://csrc.nist.gov/projects/post-quantum-cryptography"


def to_text(result: ScanResult, color: bool = False) -> str:
    def sev(s: str) -> str:
        label = f"{s.upper():<8}"
        return f"{COLORS[s]}{label}{RESET}" if color else label

    out = [f"pqcscan {__version__}: scanned {result.files_scanned} files, found {len(result.findings)} issues", ""]
    for f in result.findings:
        out.append(f"{sev(f.severity)}  {f.rule_id}  {f.path}:{f.line}:{f.column}  {f.title} [{f.algorithm}]")
        out.append(f"          {f.snippet}")
        out.append(f"          fix: {f.recommendation}")
        out.append("")
    if not result.findings:
        out.append("No quantum-vulnerable cryptography found.")
        return "\n".join(out)
    out.append("Summary: " + " | ".join(f"{s} {n}" for s, n in result.by_severity().items()))
    out.append("Cryptographic inventory:")
    for algorithm, n in result.inventory().items():
        out.append(f"  {algorithm:<28} {n}")
    return "\n".join(out)


def to_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "tool": "pqcscan",
            "version": __version__,
            "root": result.root,
            "files_scanned": result.files_scanned,
            "summary": result.by_severity(),
            "inventory": result.inventory(),
            "findings": [f.to_dict() for f in result.findings],
        },
        indent=2,
    )


def to_sarif(result: ScanResult) -> str:
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for rule_id in used:
        r = ALL_RULES[rule_id]
        rules.append({
            "id": r.id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": f"{r.title}. Threat: {r.threat}."},
            "help": {"text": r.recommendation},
            "helpUri": INFO_URI,
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {
                "security-severity": SECURITY_SEVERITY[r.severity],
                "tags": ["security", "cryptography", "post-quantum", r.category],
            },
        })
    results = [
        {
            "ruleId": f.rule_id,
            "ruleIndex": used.index(f.rule_id),
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title} [{f.algorithm}]. {f.recommendation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
            "properties": {"algorithm": f.algorithm, "severity": f.severity},
        }
        for f in result.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "pqcscan", "version": __version__, "informationUri": INFO_URI, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


FORMATS = {"text": to_text, "json": to_json, "sarif": to_sarif}
