"""Tests for DNS resolution helpers."""

import socket

from shadowreap.parsers.dns import Resolver

ALIVE = "example.com"
DEAD = "definitely-not-a-real-host-abc.example.com"


def test_resolve_alive():
    ips = Resolver().resolve(ALIVE)
    assert isinstance(ips, set)
    assert ips  # example.com always resolves


def test_resolve_dead_empty():
    assert Resolver().resolve(DEAD) == set()


def test_resolve_cache():
    r = Resolver()
    a = r.resolve(ALIVE)
    b = r.resolve(ALIVE)
    assert a is b  # cached object identity


def test_is_alive():
    assert Resolver().is_alive(ALIVE)
    assert not Resolver().is_alive(DEAD)


def test_dedupe_by_ip_keeps_first(monkeypatch):
    r = Resolver()
    monkeypatch.setattr(r, "resolve", lambda h: {"1.2.3.4"} if h.startswith("dup") else set())
    assert r.dedupe_by_ip(["dup1", "other", "dup2"]) == ["dup1"]


def test_wildcard_check_no_root_false():
    assert Resolver().wildcard_check() is False