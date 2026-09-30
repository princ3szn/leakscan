import subprocess

import pytest

from leakscan.engine import Scanner
from leakscan.gitscan import GitError, scan_history
from leakscan.walker import scan_path


def git(repo, *args):
    subprocess.run(
        [
            "git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
            "-c", "commit.gpgsign=false", "-C", str(repo), *args,
        ],
        check=True,
        capture_output=True,
    )


def fake_aws_key() -> str:
    return "AKIA" + "IOSFODNN7EXAMPLE"


def test_finds_secret_deleted_in_later_commit(tmp_path):
    git(tmp_path, "init")
    target = tmp_path / "config.py"
    target.write_text('KEY = "' + fake_aws_key() + '"\n')
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "add config")
    target.write_text("KEY = None\n")
    git(tmp_path, "commit", "-am", "remove key")

    # The working tree is clean, but the history still holds the secret.
    assert scan_path(tmp_path, Scanner()) == []

    findings = scan_history(tmp_path, Scanner())
    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-key-id"
    assert findings[0].file == "config.py"
    assert findings[0].line == 1
    assert findings[0].commit


def test_clean_history_has_no_findings(tmp_path):
    git(tmp_path, "init")
    (tmp_path / "a.py").write_text("print('hi')\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-m", "init")
    assert scan_history(tmp_path, Scanner()) == []


def test_non_repo_raises_git_error(tmp_path):
    with pytest.raises(GitError):
        scan_history(tmp_path, Scanner())