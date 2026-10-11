"""Parsers subpackage: scope, dns, tech, endpoints, nmap XML."""

from .scope import Scope, ScopeError, parse_scope  # noqa: F401

__all__ = ["Scope", "ScopeError", "parse_scope"]