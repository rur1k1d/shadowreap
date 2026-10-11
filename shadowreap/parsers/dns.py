"""DNS resolution + wildcard detection + dedupe."""

from __future__ import annotations

import random
import socket
import string
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class Resolver:
    root: str = ""
    _cache: Dict[str, Set[str]] = field(default_factory=dict)

    def resolve(self, host: str) -> Set[str]:
        """Resolve a host to a set of A/AAAA IP strings (cached)."""
        host = host.rstrip(".").lower()
        if host in self._cache:
            return self._cache[host]
        ips: Set[str] = set()
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            infos = []
        for info in infos:
            ip = info[4][0]
            if ip not in ("", "0.0.0.0") and not ip.startswith("::ffff:0:0"):
                ips.add(ip)
        self._cache[host] = ips
        return ips

    def is_alive(self, host: str) -> bool:
        return bool(self.resolve(host))

    def dedupe_by_ip(self, hosts: List[str]) -> List[str]:
        """Return hosts that resolve to at least one IP, deduped by IP set."""
        seen_hosts: Dict[Set[str], str] = {}
        for h in hosts:
            ips = self.resolve(h)
            if not ips:
                continue
            # First host owning a given IP set wins (stable).
            key = tuple(sorted(ips))
            seen_hosts.setdefault(key, h)
        return list(seen_hosts.values())

    def wildcard_check(self, sample_n: int = 3) -> bool:
        """Detect wildcard DNS for the root domain.

        Resolves random labels; if any resolves, the domain has a wildcard
        record (mass virtual-host / catch-all).
        """
        if not self.root:
            return False
        hits = 0
        for _ in range(sample_n):
            label = "".join(random.choices(string.ascii_lowercase, k=12))
            probe = f"{label}.{self.root}"
            if self.is_alive(probe):
                hits += 1
        return hits > 0