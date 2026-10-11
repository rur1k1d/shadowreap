"""Tests for tech detection helpers."""

from shadowreap.parsers.tech import (
    TechResult,
    _strip_tech_hints,
    probe_httpx,
    probe_requests,
)


def test_tech_sniffing_signatures():
    headers = {"Server": "nginx/1.24"}
    body = "<script src='/wp-content/theme.js'></script>"
    found = _strip_tech_hints(headers, body)
    assert "nginx" in found
    assert "wordpress" in found


def test_tech_no_false_positive():
    assert _strip_tech_hints({"Server": "Apache/2.4"}, "<html>x</html>") == {"apache"}


def test_probe_requests_real_example():
    r = probe_requests("http://example.com", timeout=10)
    assert r is not None
    assert r.status == 200
    assert "Example Domain" in r.title


def test_probe_requests_connection_refused():
    assert probe_requests("http://127.0.0.1:1", timeout=2) is None


def test_httpx_returns_empty_when_missing(monkeypatch):
    monkeypatch.setattr("shadowreap.parsers.tech.httpx_available", lambda: False)
    assert probe_httpx(["http://example.com"]) == []


def test_tech_result_to_dict():
    r = TechResult(url="http://x", status=200, title="t", server="nginx", techs={"nginx"})
    d = r.to_dict()
    assert d["techs"] == ["nginx"]
    assert d["url"] == "http://x"