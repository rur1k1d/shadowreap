"""Tests for subdomain enumeration helpers (no network calls to real hosts)."""

import pytest

from shadowreap.enumerators.subdomains import (
    _is_wildcard,
    crtsh_subdomains,
    hackertarget_subdomains,
)


def test_is_wildcard():
    assert _is_wildcard("*.example.com")
    assert not _is_wildcard("www.example.com")
    assert not _is_wildcard("example.com")


def test_crtsh_json_shape_populated(monkeypatch):
    """Feed crt.sh a fake JSON response and assert parsing/filtering logic."""

    import requests

    class FakeResp:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return [
                {"name_value": "www.example.com"},
                {"name_value": "*.example.com"},
                {"name_value": "api.example.com\nmail.example.com"},
                {"name_value": "evilenemy.org"},  # unrelated -> dropped
            ]

    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    result = crtsh_subdomains("example.com")
    assert result == ["api.example.com", "mail.example.com", "www.example.com"]


def test_crtsh_network_error_bubbles(monkeypatch):
    import requests

    def boom(*a, **kw):
        raise requests.ConnectionError("nope")

    monkeypatch.setattr(requests, "get", boom)
    with pytest.raises(requests.RequestException):
        crtsh_subdomains("example.com")


def test_crtsh_5xx_bubbles(monkeypatch):
    import requests

    class FakeResp:
        status_code = 502

        def raise_for_status(self):
            return None

    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    with pytest.raises(requests.HTTPError):
        crtsh_subdomains("example.com")


def test_hackertarget_parses(monkeypatch):
    import requests

    class FakeResp:
        status_code = 200
        text = "www.example.com,104.20.23.154\napi.example.com,1.2.3.4"

    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    assert hackertarget_subdomains("example.com") == ["api.example.com", "www.example.com"]


def test_hackertarget_error_returns_empty(monkeypatch):
    import requests

    class FakeResp:
        status_code = 200
        text = "API count exceeded - Increase your max quota"

    monkeypatch.setattr(requests, "get", lambda *a, **kw: FakeResp())
    assert hackertarget_subdomains("example.com") == []