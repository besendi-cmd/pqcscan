import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from pqcscan.cbom import to_cbom
from pqcscan.cli import main
from pqcscan.scanner import scan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


def _validate(text: str) -> None:
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    assert error is None, error


def test_cbom_validates_against_cyclonedx_1_6_schema():
    _validate(to_cbom(scan(EXAMPLES)))


def test_cbom_contents():
    bom = json.loads(to_cbom(scan(EXAMPLES)))
    components = {c["bom-ref"]: c for c in bom["components"]}
    rsa_pke = components["crypto/algorithm/rsa@pke"]
    props = rsa_pke["cryptoProperties"]["algorithmProperties"]
    assert props["nistQuantumSecurityLevel"] == 0
    assert {"encrypt", "decrypt", "keygen"} <= set(props["cryptoFunctions"])
    assert {o["location"] for o in rsa_pke["evidence"]["occurrences"]} >= {"auth.js", "crypto_utils.py"}
    assert {"library/rsa", "library/ecdsa"} <= set(components)
    assert components["crypto/algorithm/aes-128@block-cipher"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 1
    assert bom["dependencies"][0]["dependsOn"] == sorted(components)


def test_cbom_key_material(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "id.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    text = to_cbom(scan(tmp_path))
    _validate(text)
    components = {c["bom-ref"]: c for c in json.loads(text)["components"]}
    material = components["crypto/key/id-key-1"]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert material == {"type": "private-key", "algorithmRef": "crypto/algorithm/rsa-2048@pke", "size": 2048}
    assert components["crypto/algorithm/rsa-2048@pke"]["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 112


def test_cli_cbom_output(tmp_path, capsys):
    out = tmp_path / "cbom.json"
    assert main(["scan", str(EXAMPLES), "--cbom", str(out)]) == 0
    _validate(out.read_text())
    capsys.readouterr()
    assert main(["scan", str(EXAMPLES), "--format", "cbom"]) == 0
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"
