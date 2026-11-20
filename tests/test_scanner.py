import json
import shutil
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pqcscan.cli import main
from pqcscan.report import to_sarif
from pqcscan.scanner import scan, scan_text

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


def ids(findings):
    return {f.rule_id for f in findings}


@pytest.mark.parametrize(
    "language, line, rule_id",
    [
        ("python", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "PQC003"),
        ("python", "ct = pub.encrypt(m, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))", "PQC001"),
        ("python", "priv.exchange(ec.ECDH(), peer)", "PQC004"),
        ("python", "k = Ed25519PrivateKey.generate()", "PQC007"),
        ("python", "hashlib.md5(b'x')", "PQC012"),
        ("javascript", "crypto.publicEncrypt(pub, buf)", "PQC001"),
        ("javascript", "jwt.sign(p, k, { algorithm: 'ES256' })", "PQC006"),
        ("javascript", "crypto.createDiffieHellman(2048)", "PQC005"),
        ("go", "k, _ := rsa.GenerateKey(rand.Reader, 2048)", "PQC003"),
        ("go", "sig, _ := ed25519.Sign(priv, msg)", "PQC007"),
        ("go", "k, _ := ecdh.X25519().GenerateKey(rand.Reader)", "PQC004"),
        ("java", 'Signature.getInstance("SHA256withECDSA")', "PQC006"),
        ("java", 'KeyPairGenerator.getInstance("DSA")', "PQC008"),
        ("c", "RSA_generate_key_ex(rsa, 2048, e, NULL);", "PQC003"),
        ("csharp", "using var ecdh = ECDiffieHellman.Create();", "PQC004"),
        ("rust", "use ed25519_dalek::SigningKey;", "PQC007"),
        ("other", "ssl_ecdh_curve secp384r1;", "PQC009"),
        ("other", "cipher: aes-128-cbc", "PQC011"),
        ("other", "ssh-rsa AAAAB3NzaC1yc2E user@host", "PQC010"),
        ("manifest", "rsa==4.9", "PQC014"),
        ("manifest", '    "elliptic": "^6.5.4",', "PQC014"),
    ],
)
def test_detects(language, line, rule_id):
    assert rule_id in ids(scan_text(line, "f", language))


@pytest.mark.parametrize(
    "language, line",
    [
        ("python", "aes = algorithms.AES(key_256)"),
        ("python", "h = hashlib.sha256(data)"),
        ("python", "import rsa_helpers"),
        ("javascript", "const kem = mlkem.ml_kem768.keygen()"),
        ("go", 'import "crypto/mlkem"'),
        ("csharp", "using var ecdh = ECDiffieHellman.Create();"),
        ("manifest", "requests==2.32.0"),
        ("go", "k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)"),
    ],
)
def test_no_false_positive(language, line):
    found = ids(scan_text(line, "f", language))
    if "ECDiffieHellman" in line:
        assert "PQC005" not in found
    elif "ecdsa" in line:
        assert "PQC008" not in found
    else:
        assert not found


def test_one_finding_per_family_keeps_most_severe():
    findings = scan_text("ct = rsa.encrypt(msg, pub)  # rsa.newkeys(2048)", "f", "python")
    assert [f.rule_id for f in findings] == ["PQC001"]


def test_inline_suppression():
    assert scan_text("hashlib.md5(x)  # pqcscan: ignore", "f", "python") == []


def test_example_app():
    result = scan(EXAMPLES)
    found = ids(result.findings)
    assert {"PQC001", "PQC002", "PQC003", "PQC004", "PQC006", "PQC009", "PQC010", "PQC011", "PQC012", "PQC013", "PQC014"} <= found
    assert not any(f.path == "crypto_utils.py" and "sha1" in f.snippet for f in result.findings)
    assert result.findings[0].severity == "critical"


def _self_signed(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_key_material(tmp_path):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ec_key = ec.generate_private_key(ec.SECP384R1())
    (tmp_path / "server.key").write_bytes(rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / "server.crt").write_bytes(_self_signed(ec_key).public_bytes(serialization.Encoding.PEM))
    (tmp_path / "signer.pem").write_bytes(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    found = {(f.rule_id, f.algorithm) for f in scan(tmp_path).findings}
    assert found == {("PQC100", "RSA-3072"), ("PQC101", "EC-secp384r1"), ("PQC102", "Ed25519")}


def test_excludes_and_ignore_file(tmp_path):
    shutil.copytree(EXAMPLES, tmp_path / "app")
    assert scan(tmp_path, excludes=["app"]).findings == []
    (tmp_path / ".pqcscanignore").write_text("# comment\napp/\n")
    assert scan(tmp_path).findings == []


def test_skips_build_metadata(tmp_path):
    (tmp_path / "pkg.egg-info").mkdir()
    (tmp_path / "pkg.egg-info" / "PKG-INFO").write_text("Curve: P-256, cipher aes-128-cbc\n")
    assert scan(tmp_path).findings == []


def test_sarif_is_valid_shape():
    sarif = json.loads(to_sarif(scan(EXAMPLES)))
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert sarif["version"] == "2.1.0"
    assert all(r["ruleId"] == rule_ids[r["ruleIndex"]] for r in run["results"])
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])


def test_cli_fail_on_and_reports(tmp_path, capsys):
    sarif, js = tmp_path / "out.sarif", tmp_path / "out.json"
    assert main(["scan", str(EXAMPLES), "--fail-on", "critical", "--sarif", str(sarif), "--json", str(js)]) == 1
    assert "Cryptographic inventory" in capsys.readouterr().out
    assert json.loads(js.read_text())["summary"]["critical"] >= 1
    assert json.loads(sarif.read_text())["runs"][0]["results"]
    (tmp_path / "clean.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    assert main(["scan", str(tmp_path / "clean.py"), "--fail-on", "low"]) == 0
