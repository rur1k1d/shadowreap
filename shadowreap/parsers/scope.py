"""Scope model + normalization: domain | IP | CIDR | ASN."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional, Union

ScopeValue = Union[str, ipaddress.IPv4Network, int]

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
ASN_RE = re.compile(r"^(?:AS?)?(\d{1,10})$", re.IGNORECASE)


class ScopeError(ValueError):
    """Raised when a scope string cannot be classified."""


@dataclass(frozen=True)
class Scope:
    kind: str  # "domain" | "cidr" | "asn"
    value: ScopeValue

    @property
    def display(self) -> str:
        if isinstance(self.value, ipaddress.IPv4Network):
            return str(self.value)
        return f"AS{self.value}" if self.kind == "asn" else str(self.value)

    def subdomain_root(self) -> Optional[str]:
        """Return the registrable root for domain scopes, else None."""
        return str(self.value) if self.kind == "domain" else None


def _clean(raw: str) -> str:
    return raw.strip().rstrip(".").lower()


def _classify_domain(raw: str) -> str:
    if DOMAIN_RE.match(raw):
        return raw
    raise ScopeError(f"'{raw}' is not a valid domain name")


def _classify_cidr(raw: str) -> str:
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise ScopeError(f"'{raw}' is not a valid IP/CIDR: {exc}") from exc
    return str(net)


def _classify_asn(raw: str) -> int:
    m = ASN_RE.match(raw)
    if not m:
        raise ScopeError(f"'{raw}' is not a valid ASN (use AS123 or 123)")
    num = int(m.group(1))
    if num < 1 or num > 4294967295:
        raise ScopeError(f"ASN {num} out of range")
    return num


def parse_scope(raw: str) -> Scope:
    """Classify a scope string.

    Order of checks: ASN first (single token), then CIDR/IP, then domain.
    A bare IP becomes a /32 or /128 network.
    """
    if not raw or not isinstance(raw, str):
        raise ScopeError("scope must be a non-empty string")

    # ASN — only when the whole token is numeric or "ASnnn".
    if ASN_RE.match(_clean(raw)):
        # But "1.2.3.4" is an IP, not ASN1 — the ASN regex would match "1".
        # Guard: an ASN candidate never contains a dot.
        if "." not in raw:
            return Scope("asn", _classify_asn(raw))

    cleaned = _clean(raw)

    # CIDR / IP — anything with "/" or that fully parses as an IP address.
    if "/" in cleaned:
        return Scope("cidr", _classify_cidr(cleaned))
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    else:
        return Scope("cidr", str(ip))

    return Scope("domain", _classify_domain(cleaned))