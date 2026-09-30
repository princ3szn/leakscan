import pytest

from leakscan.cli import main
from leakscan.remote import RemoteError, parse_github_url


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/princ3szn/leakscan",
        "https://github.com/princ3szn/leakscan.git",
        "https://github.com/princ3szn/leakscan/",
    ],
)
def test_parses_valid_urls(url):
    assert parse_github_url(url) == ("princ3szn", "leakscan")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://github.com/a",
        "https://github.com/a/b/tree/main",
        "--upload-pack=calc",
        "ext::sh -c calc",
        "https://github.com/a/..",
        "https://github.com.evil.com/a/b",
        "https://user:pass@github.com/a/b",
    ],
)
def test_rejects_unsafe_urls(url):
    with pytest.raises(RemoteError):
        parse_github_url(url)


def test_cli_rejects_non_github_url(capsys):
    assert main(["scan", "https://example.com/a/b"]) == 2
    assert "error" in capsys.readouterr().err