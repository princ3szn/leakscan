from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from leakscan import api

client = TestClient(api.app)


def fake_aws_key() -> str:
    return "AKIA" + "QYZ3TWM5PXLK7B2D"


@pytest.fixture(autouse=True)
def reset_rate_limit():
    api._hits.clear()


@pytest.fixture
def fake_clone(tmp_path, monkeypatch):
    (tmp_path / "config.py").write_text('KEY = "' + fake_aws_key() + '"\n')

    @contextmanager
    def _clone(url, full_history=False):
        yield tmp_path

    monkeypatch.setattr(api, "shallow_clone", _clone)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_scan_returns_redacted_findings(fake_clone):
    response = client.post("/scan", json={"url": "https://github.com/a/b"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    finding = body["findings"][0]
    assert finding["rule_id"] == "aws-access-key-id"
    assert finding["severity"] == "high"
    assert fake_aws_key() not in str(body)


def test_invalid_url_returns_400():
    response = client.post("/scan", json={"url": "https://example.com/a/b"})
    assert response.status_code == 400


def test_rate_limit_returns_429(fake_clone):
    for _ in range(api.RATE_LIMIT):
        assert client.post("/scan", json={"url": "https://github.com/a/b"}).status_code == 200
    assert client.post("/scan", json={"url": "https://github.com/a/b"}).status_code == 429