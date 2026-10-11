"""Tests for scope parsing."""

import pytest

from shadowreap.parsers.scope import Scope, ScopeError, parse_scope


def test_domain():
    s = parse_scope("Example.com")
    assert s.kind == "domain"
    assert s.subdomain_root() == "example.com"


def test_domain_with_dot_suffix():
    s = parse_scope("sub.example.com.")
    assert s.kind == "domain"
    assert s.subdomain_root() == "sub.example.com"


def test_bare_ip():
    s = parse_scope("93.184.215.14")
    assert s.kind == "cidr"
    assert s.display == "93.184.215.14"


def test_cidr():
    s = parse_scope("10.0.0.0/24")
    assert s.kind == "cidr"
    assert s.display == "10.0.0.0/24"


def test_cidr_strict_false_fixes_hostbits():
    s = parse_scope("10.0.0.7/24")
    assert s.display == "10.0.0.0/24"


def test_asn():
    s = parse_scope("AS15169")
    assert s.kind == "asn"
    assert s.display == "AS15169"


def test_asn_numeric():
    s = parse_scope("15169")
    assert s.kind == "asn"


def test_asn_lowercase():
    s = parse_scope("as112")
    assert s.kind == "asn"


@pytest.mark.parametrize("bad", ["", "not a domain", "..", "example", "exa mple.com"])
def test_invalid(bad):
    with pytest.raises(ScopeError):
        parse_scope(bad)


def test_asn_out_of_range():
    with pytest.raises(ScopeError):
        parse_scope("AS4294967296")


def test_scope_display_domain():
    assert parse_scope("example.com").display == "example.com"