from leakscan.engine import Scanner


def fake_aws_key() -> str:
    return "AKIA" + "QYZ3TWM5PXLK7B2D"


def fake_github_token() -> str:
    return "ghp_" + "Ab1" * 12


def fake_password() -> str:
    return "k9Xv2LmQ" + "7zTb4RwC"


def test_detects_aws_key_with_line_number():
    text = 'region = "us-east-1"\nkey = "' + fake_aws_key() + '"\n'
    findings = Scanner().scan_text(text, file="app.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-key-id"
    assert findings[0].line == 2
    assert fake_aws_key() not in findings[0].secret_redacted


def test_github_token_reported_once():
    text = 'token = "' + fake_github_token() + '"'
    findings = Scanner().scan_text(text)
    assert len(findings) == 1
    assert findings[0].rule_id == "github-pat"


def test_detects_private_key_header():
    header = "-----BEGIN RSA " + "PRIVATE KEY-----"
    findings = Scanner().scan_text(header)
    assert [f.rule_id for f in findings] == ["private-key"]


def test_flags_high_entropy_password_assignment():
    findings = Scanner().scan_text('password = "' + fake_password() + '"')
    assert [f.rule_id for f in findings] == ["generic-secret-assignment"]


def test_ignores_placeholder_and_low_entropy_values():
    text = 'password = "your_password_here"\nsecret = "aaaaaaaaaa"'
    assert Scanner().scan_text(text) == []


def test_inline_ignore_comment_suppresses_finding():
    text = 'key = "' + fake_aws_key() + '"  # leakscan:ignore'
    assert Scanner().scan_text(text) == []


def test_clean_text_has_no_findings():
    assert Scanner().scan_text("print('hello world')") == []
    
def test_detects_password_in_connection_url():
    text = "DATABASE_URL=postgres://admin:" + "k9Xv2LmQ" + "7zTb@db.host/app"
    findings = Scanner().scan_text(text)
    assert [f.rule_id for f in findings] == ["url-embedded-credentials"]


def test_detects_unquoted_env_assignment():
    findings = Scanner().scan_text("DB_PASSWORD=" + fake_password())
    assert [f.rule_id for f in findings] == ["generic-unquoted-assignment"]


def test_documented_example_key_is_ignored():
    text = 'key = "' + "AKIA" + "IOSFODNN7EXAMPLE" + '"'
    assert Scanner().scan_text(text) == []


def test_numeric_only_value_is_ignored():
    assert Scanner().scan_text('secret_length = "1234567890"') == []