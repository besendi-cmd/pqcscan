import json
import shutil
from pathlib import Path

import pytest

from pqcscan.baseline import apply_baseline, load_baseline, write_baseline
from pqcscan.cli import main
from pqcscan.scanner import scan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


@pytest.fixture
def app(tmp_path):
    shutil.copytree(EXAMPLES, tmp_path / "app")
    return tmp_path / "app"


def test_fingerprints_unique_and_stable_across_line_shifts(app):
    before = scan(app)
    fps = [f.fingerprint for f in before.findings]
    assert len(fps) == len(set(fps)) and all(fps)
    js = app / "auth.js"
    js.write_text("// new header line\n\n" + js.read_text())
    assert {f.fingerprint for f in scan(app).findings} == set(fps)


def test_duplicate_lines_get_distinct_fingerprints(tmp_path):
    (tmp_path / "a.py").write_text("hashlib.md5(x)\nhashlib.md5(x)\n")
    fps = [f.fingerprint for f in scan(tmp_path).findings]
    assert len(fps) == 2 and fps[0] != fps[1]


def test_baseline_reports_only_new_and_counts_fixed(app, tmp_path):
    baseline = tmp_path / "baseline.json"
    total = write_baseline(scan(app), baseline)
    assert total == len(load_baseline(baseline))

    (app / "new.go").write_text('import "crypto/ecdsa"\n')
    (app / "requirements.txt").write_text("flask==3.0.3\n")  # fixes the two dependency findings
    result = scan(app)
    apply_baseline(result, load_baseline(baseline))
    assert [(f.path, f.rule_id) for f in result.findings] == [("new.go", "PQC006")]
    assert result.baseline_resolved == 2
    assert result.baseline_suppressed == total - 2


def test_cli_baseline_gates_ci(app, tmp_path, capsys):
    baseline = tmp_path / "b.json"
    assert main(["scan", str(app), "--write-baseline", str(baseline), "--fail-on", "none"]) == 0
    assert main(["scan", str(app), "--baseline", str(baseline), "--fail-on", "low"]) == 0
    assert "No new quantum-vulnerable cryptography found." in capsys.readouterr().out

    (app / "x.py").write_text("k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    out_json = tmp_path / "r.json"
    assert main(["scan", str(app), "--baseline", str(baseline), "--fail-on", "high", "--json", str(out_json)]) == 1
    report = json.loads(out_json.read_text())
    assert [f["path"] for f in report["findings"]] == ["x.py"]
    assert report["baseline"]["resolved"] == 0


def test_cli_rejects_bad_baseline(app, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["scan", str(app), "--baseline", str(bad)]) == 2
    assert main(["scan", str(app), "--baseline", str(tmp_path / "missing.json")]) == 2


def test_sarif_has_partial_fingerprints(app):
    from pqcscan.report import to_sarif

    results = json.loads(to_sarif(scan(app)))["runs"][0]["results"]
    assert all(r["partialFingerprints"]["pqcscan/v1"] for r in results)


def test_baseline_file_in_scan_root_is_not_scanned_and_has_no_snippets(tmp_path):
    (tmp_path / "app.py").write_text('API_KEY = "s3cr3t"; key = rsa.generate_private_key(65537, 2048)\n')
    baseline = tmp_path / ".pqcscan-baseline.json"
    assert main(["scan", str(tmp_path), "--write-baseline", str(baseline), "-o", str(tmp_path.parent / "o.txt")]) == 0
    assert "s3cr3t" not in baseline.read_text()
    assert main(["scan", str(tmp_path), "--baseline", str(baseline), "--fail-on", "low",
                 "-o", str(tmp_path.parent / "o.txt")]) == 0


def test_same_file_for_baseline_and_write_baseline_compares_first(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("key = rsa.generate_private_key(65537, 2048)\n")
    b = tmp_path / "b.json"
    out = str(tmp_path / "o.txt")
    main(["scan", str(src), "--write-baseline", str(b), "-o", out])
    (src / "b.py").write_text("k = ec.generate_private_key(ec.SECP256R1())\n")
    assert main(["scan", str(src), "--baseline", str(b), "--write-baseline", str(b), "--fail-on", "low", "-o", out]) == 1
    assert len(load_baseline(b)) == 2


def test_cbom_keeps_baselined_assets(tmp_path):
    (tmp_path / "a.py").write_text("key = rsa.generate_private_key(65537, 2048)\n")
    b = tmp_path.parent / "cbom-b.json"
    cbom = tmp_path.parent / "cbom.json"
    out = str(tmp_path.parent / "o.txt")
    main(["scan", str(tmp_path), "--write-baseline", str(b), "-o", out])
    main(["scan", str(tmp_path), "--baseline", str(b), "--cbom", str(cbom), "-o", out])
    assert any(c["bom-ref"].startswith("crypto/algorithm/rsa") for c in json.loads(cbom.read_text())["components"])


def test_nested_file_named_like_baseline_is_still_scanned(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "crypto.py").write_text("key = rsa.generate_private_key(65537, 2048)\n")
    baseline = tmp_path / "crypto.py"
    out = str(tmp_path.parent / "o.txt")
    assert main(["scan", str(tmp_path), "--write-baseline", str(baseline), "-o", out]) == 0
    assert len(load_baseline(baseline)) == 1
