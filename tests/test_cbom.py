import json
from pathlib import Path

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
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
    (ref,) = [r for r in components if r.startswith("crypto/key/id-key-1-")]
    material = components[ref]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert material == {"type": "private-key", "algorithmRef": "crypto/algorithm/rsa-2048@pke", "size": 2048}
    assert components["crypto/algorithm/rsa-2048@pke"]["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 112


def test_cli_cbom_output(tmp_path, capsys):
    out = tmp_path / "cbom.json"
    assert main(["scan", str(EXAMPLES), "--cbom", str(out)]) == 0
    _validate(out.read_text())
    capsys.readouterr()
    assert main(["scan", str(EXAMPLES), "--format", "cbom"]) == 0
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"


def _pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def test_cbom_key_refs_do_not_collide(tmp_path):
    (tmp_path / "keys").mkdir()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for name in ("keys/id_rsa.pem", "keys/id-rsa.pem", "keys-id-RSA.pem"):
        (tmp_path / name).write_bytes(_pem(key))
    text = to_cbom(scan(tmp_path))
    _validate(text)
    keys = [c for c in json.loads(text)["components"] if c["bom-ref"].startswith("crypto/key/")]
    assert len(keys) == 3


def test_cbom_stream_and_block_ciphers(tmp_path):
    (tmp_path / "a.py").write_text('c1 = "rc4"\nc2 = "arcfour"\nc3 = "3des"\n')
    text = to_cbom(scan(tmp_path))
    _validate(text)
    components = {c["bom-ref"]: c for c in json.loads(text)["components"]}
    assert components["crypto/algorithm/rc4@stream-cipher"]["cryptoProperties"]["algorithmProperties"]["primitive"] == "stream-cipher"
    assert "crypto/algorithm/des-3des@block-cipher" in components


def test_cbom_certificate_references_public_key(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    (tmp_path / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    text = to_cbom(scan(tmp_path))
    _validate(text)
    components = {c["bom-ref"]: c for c in json.loads(text)["components"]}
    certs = [c for c in components.values() if c["cryptoProperties"]["assetType"] == "certificate"]
    assert len(certs) == 1
    target = components[certs[0]["cryptoProperties"]["certificateProperties"]["subjectPublicKeyRef"]]
    material = target["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert material["type"] == "public-key"
    assert components[material["algorithmRef"]]["cryptoProperties"]["assetType"] == "algorithm"


def test_cbom_handles_non_utf8_paths(tmp_path):
    import os
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        (tmp_path / os.fsdecode(b"key-\xff.pem")).write_bytes(_pem(key))
    except (OSError, UnicodeError):
        import pytest
        pytest.skip("filesystem does not allow non-UTF-8 names")
    text = to_cbom(scan(tmp_path))
    assert any(c["bom-ref"].startswith("crypto/key/") for c in json.loads(text)["components"])
