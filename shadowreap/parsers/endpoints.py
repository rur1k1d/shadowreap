"""Interesting endpoints: robots.txt + sitemap.xml parsing for web hosts."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import requests

ROBOTS_USERAGENT_RE = re.compile(r"^user-agent\s*:\s*(.+)$", re.IGNORECASE)
ROBOTS_DISALLOW_RE = re.compile(r"^disallow\s*:\s*(.*)$", re.IGNORECASE)
ROBOTS_ALLOW_RE = re.compile(r"^allow\s*:\s*(.*)$", re.IGNORECASE)
ROBOTS_SITEMAP_RE = re.compile(r"^sitemap\s*:\s*(.+)$", re.IGNORECASE)
SITEMAP_LOC_RE = re.compile(r"<loc\s*[^>]*>(.*?)</loc>", re.IGNORECASE | re.DOTALL)

SESSION_HEADERS = {"User-Agent": "Mozilla/5.0 shadowreap/0.1"}


@dataclass
class EndpointResult:
    url: str
    kind: str  # "robots" | "sitemap"
    body: str = ""
    entries: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"url": self.url, "kind": self.kind, "entries": self.entries}


def parse_robots(text: str) -> Dict[str, List[str]]:
    """Return {'disallow': [...], 'allow': [...], 'sitemap': [...]}."""
    out: Dict[str, List[str]] = {"disallow": [], "allow": [], "sitemap": []}
    agent = "*"
    for line in text.splitlines():
        s = line.strip()
        low = s.lower()
        m = ROBOTS_USERAGENT_RE.match(line)
        if m:
            agent = m.group(1).strip().lower()
            continue
        # Sitemap is global, not agent-scoped.
        m = ROBOTS_SITEMAP_RE.match(line)
        if m:
            val = m.group(1).strip()
            if val:
                out["sitemap"].append(val)
            continue
        if agent != "*":
            continue
        for name in ("disallow", "allow"):
            m = {"disallow": ROBOTS_DISALLOW_RE, "allow": ROBOTS_ALLOW_RE}[name].match(line)
            if m:
                val = m.group(1).strip()
                if val:
                    out[name].append(val)
                break
    return out


def parse_sitemap_xml(text: str) -> List[str]:
    """Extract <loc> URLs from a sitemap (including sitemap indexes, which
    point to child sitemaps — the caller decides how deep to go)."""
    return [m.strip() for m in SITEMAP_LOC_RE.findall(text) if m.strip()]


def _fetch(url: str, timeout: int = 10) -> Optional[str]:
    try:
        resp = requests.get(url, headers=SESSION_HEADERS, timeout=timeout)
        resp.raise_for_status()
        return resp.text if len(resp.content) < 2_000_000 else None
    except requests.RequestException:
        return None


def discover_endpoints(urls: List[str], timeout: int = 10) -> List[EndpointResult]:
    """For each URL (http/https origin), try robots.txt then sitemap.xml."""
    res: List[EndpointResult] = []
    seen_entries: Set[str] = set()
    for url in urls:
        base = url.rstrip("/")
        robots_url = base + "/robots.txt"
        robots_body = _fetch(robots_url, timeout=timeout)
        if robots_body is not None:
            parsed = parse_robots(robots_body)
            entries = parsed["disallow"] + parsed["allow"]
            entry_urls = set()
            for e in entries:
                if "://" in e:
                    entry_urls.add(e)
                elif e.startswith("/"):
                    entry_urls.add(base + e)
            new_entries = [x for x in sorted(entry_urls - seen_entries) if x not in seen_entries]
            seen_entries.update(new_entries)
            res.append(
                EndpointResult(url=robots_url, kind="robots", body=robots_body, entries=new_entries)
            )
            for sitemap in parsed.get("sitemap", []):
                sm_body = _fetch(sitemap if "://" in sitemap else base + sitemap, timeout=timeout)
                if sm_body is not None:
                    locs = parse_sitemap_xml(sm_body)
                    uniq = [x for x in locs if x not in seen_entries]
                    seen_entries.update(uniq)
                    res.append(
                        EndpointResult(url=sitemap, kind="sitemap", body=sm_body, entries=uniq)
                    )
    return res