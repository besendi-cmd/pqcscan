"""CycloneDX 1.6 cryptographic bill of materials (CBOM) export."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .rules import ALL_RULES, SEVERITIES
from .scanner import Finding, ScanResult

# rule id -> (CycloneDX primitive, crypto functions)
PRIMITIVES = {
    "PQC001": ("pke", ["encrypt", "decrypt"]),
    "PQC002": ("signature", ["sign", "verify"]),
    "PQC003": ("pke", ["keygen"]),
    "PQC004": ("key-agree", ["keygen", "keyderive"]),
    "PQC005": ("key-agree", ["keygen", "keyderive"]),
    "PQC006": ("signature", ["sign", "verify"]),
    "PQC007": ("signature", ["sign", "verify"]),
    "PQC008": ("signature", ["sign", "verify"]),
    "PQC009": ("other", ["keygen"]),
    "PQC010": ("signature", ["sign", "verify"]),
    "PQC011": ("block-cipher", ["encrypt", "decrypt"]),
    "PQC012": ("hash", ["digest"]),
    "PQC013": ("block-cipher", ["encrypt", "decrypt"]),
}
KEY_MATERIAL = {"PQC100": "private-key", "PQC102": "public-key"}
CERTIFICATE = "PQC101"
DEPENDENCY = "PQC014"

# Approximate classical security (bits) for common parameters; quantum level is 0 for Shor-breakable algorithms.
CLASSICAL_BITS = {"RSA-1024": 80, "RSA-2048": 112, "RSA-3072": 128, "RSA-4096": 152, "AES-128": 128, "MD5": 0, "SHA-1": 0}  # pqcscan: ignore


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _key_algorithm(algorithm: str) -> tuple[str, str]:
    """Primitive and family for an algorithm reported from parsed key material."""
    if algorithm.startswith(("X25519", "X448", "DH")):
        return "key-agree", algorithm
    if algorithm.startswith(("Ed", "DSA")):
        return "signature", algorithm
    if algorithm.startswith("EC"):
        return "other", algorithm
    return "pke", algorithm


def _occurrence(f: Finding) -> dict:
    return {"location": f.path, "line": f.line, "offset": f.column, "additionalContext": f"{f.rule_id}: {f.title}"}


def _worst(severities) -> str:
    return max(severities, key=SEVERITIES.index)


class _Builder:
    def __init__(self):
        self.components: dict[str, dict] = {}
        self.meta: dict[str, dict] = {}

    def _add(self, ref: str, component: dict, f: Finding) -> None:
        if ref not in self.components:
            component["bom-ref"] = ref
            component.setdefault("evidence", {"occurrences": []})
            self.components[ref] = component
            self.meta[ref] = {"severities": [], "rules": set(), "fixes": []}
        self.components[ref]["evidence"]["occurrences"].append(_occurrence(f))
        meta = self.meta[ref]
        meta["severities"].append(f.severity)
        meta["rules"].add(f.rule_id)
        if f.recommendation not in meta["fixes"]:
            meta["fixes"].append(f.recommendation)

    def algorithm(self, name: str, primitive: str, functions: list[str], f: Finding) -> str:
        ref = f"crypto/algorithm/{_slug(name)}@{primitive}"
        props: dict = {"primitive": primitive, "cryptoFunctions": list(functions)}
        if "-" in name and name.split("-", 1)[1]:
            props["parameterSetIdentifier"] = name.split("-", 1)[1]
        if name in CLASSICAL_BITS:
            props["classicalSecurityLevel"] = CLASSICAL_BITS[name]
        props["nistQuantumSecurityLevel"] = 1 if name == "AES-128" else 0  # pqcscan: ignore
        self._add(ref, {
            "type": "cryptographic-asset",
            "name": name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
        }, f)
        existing = self.components[ref]["cryptoProperties"]["algorithmProperties"]["cryptoFunctions"]
        existing.extend(fn for fn in functions if fn not in existing)
        return ref

    def add(self, f: Finding) -> None:
        if f.rule_id in PRIMITIVES:
            primitive, functions = PRIMITIVES[f.rule_id]
            self.algorithm(f.algorithm, primitive, functions, f)
        elif f.rule_id in KEY_MATERIAL or f.rule_id == CERTIFICATE:
            primitive, name = _key_algorithm(f.algorithm)
            algorithm_ref = self.algorithm(name, primitive, ["keygen"], f)
            if f.rule_id == CERTIFICATE:
                ref = f"crypto/certificate/{_slug(f.path)}-{f.line}"
                component = {
                    "type": "cryptographic-asset",
                    "name": f"certificate {f.path}:{f.line}",
                    "cryptoProperties": {
                        "assetType": "certificate",
                        "certificateProperties": {"subjectPublicKeyRef": algorithm_ref, "certificateFormat": "X.509"},
                    },
                }
            else:
                ref = f"crypto/key/{_slug(f.path)}-{f.line}"
                size = re.search(r"-(\d+)$", f.algorithm)
                material = {"type": KEY_MATERIAL[f.rule_id], "algorithmRef": algorithm_ref}
                if size:
                    material["size"] = int(size.group(1))
                component = {
                    "type": "cryptographic-asset",
                    "name": f"{KEY_MATERIAL[f.rule_id]} {f.path}:{f.line}",
                    "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": material},
                }
            self._add(ref, component, f)
        elif f.rule_id == DEPENDENCY:
            name = f.algorithm.removeprefix("library: ")
            self._add(f"library/{_slug(name)}", {"type": "library", "name": name}, f)

    def finish(self) -> list[dict]:
        out = []
        for ref, component in self.components.items():
            meta = self.meta[ref]
            component["properties"] = [
                {"name": "pqcscan:severity", "value": _worst(meta["severities"])},
                {"name": "pqcscan:rules", "value": ",".join(sorted(meta["rules"]))},
                {"name": "pqcscan:quantumThreat", "value": ALL_RULES[sorted(meta["rules"])[0]].threat},
                *({"name": "pqcscan:recommendation", "value": fix} for fix in meta["fixes"]),
            ]
            out.append(component)
        return sorted(out, key=lambda c: c["bom-ref"])


def to_cbom(result: ScanResult, serial: str | None = None, timestamp: str | None = None) -> str:
    builder = _Builder()
    for f in result.findings:
        builder.add(f)
    components = builder.finish()
    app_ref = "application"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "pqcscan", "version": __version__}]},
            "component": {"type": "application", "bom-ref": app_ref, "name": Path(result.root).name or result.root},
        },
        "components": components,
        "dependencies": [{"ref": app_ref, "dependsOn": [c["bom-ref"] for c in components]}],
    }
    return json.dumps(bom, indent=2)
