import json

from leakscan.cli import main
from leakscan.engine import Scanner
from leakscan.walker import scan_path


def fake_aws_key() -> str:
    return "AKIA" + "QYZ3TWM5PXLK7B2D"


def test_scan_path_finds_secret_in_nested_file(tmp_path):
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "config.py").write_text('KEY = "' + fake_aws_key() + '"\n')
    findings = scan_path(tmp_path, Scanner())
    assert len(findings) == 1
    assert findings[0].file.endswith("config.py")


def test_skips_ignored_directories(tmp_path):
    d = tmp_path / "node_modules"
    d.mkdir()
    (d / "x.js").write_text('KEY = "' + fake_aws_key() + '"\n')
    assert scan_path(tmp_path, Scanner()) == []


def test_skips_binary_files(tmp_path):
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01" + fake_aws_key().encode())
    assert scan_path(tmp_path, Scanner()) == []


def test_skips_files_over_size_limit(tmp_path):
    (tmp_path / "big.txt").write_text('KEY = "' + fake_aws_key() + '"\n')
    assert scan_path(tmp_path, Scanner(), max_size=10) == []


def test_cli_returns_one_and_json_when_secret_found(tmp_path, capsys):
    (tmp_path / "a.py").write_text('k = "' + fake_aws_key() + '"\n')
    code = main(["scan", str(tmp_path), "--format", "json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 1
    assert out[0]["rule_id"] == "aws-access-key-id"


def test_cli_returns_zero_when_clean(tmp_path):
    (tmp_path / "a.py").write_text("print('hi')\n")
    assert main(["scan", str(tmp_path)]) == 0