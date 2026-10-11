"""Tech stack detection: httpx first, requests fallback."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import requests

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Low-noise signature list; extended in plan.md improvements.
TECH_SIGNATURES: Dict[str, Set[str]] = {
    "nginx": {"Server: nginx"},
    "apache": {"Server: Apache"},
    "cloudflare": {"Server: cloudflare", "cf-ray"},
    "wordpress": {"wp-content", "wp-includes"},
    "jquery": {"jquery"},
    "bootstrap": {"bootstrap"},
    "react": {"__react", "react-scripts"},
}

SESSION_HEADERS = {"User-Agent": "Mozilla/5.0 shadowreap/0.1"}

MISSING_HTTX_MSG = "httpx not detected"


@dataclass
class TechResult:
    url: str
    status: int = 0
    title: str = ""
    server: str = ""
    techs: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "server": self.server,
            "techs": sorted(self.techs),
        }


def _strip_tech_hints(headers: Dict[str, str], body: str) -> Set[str]:
    found: Set[str] = set()
    joined = " ".join(f"{k.lower()}: {v.lower()}" for k, v in headers.items())
    joined += " " + body[:15000].lower()
    for tech, hints in TECH_SIGNATURES.items():
        if any(h.lower() in joined for h in hints):
            found.add(tech)
    return found


def probe_requests(url: str, timeout: int = 10) -> Optional[TechResult]:
    """Fallback probe: status, title, server, tech signatures."""
    try:
        resp = requests.get(url, headers=SESSION_HEADERS, timeout=timeout)
    except requests.RequestException:
        return None
    title = ""
    m = TITLE_RE.search(resp.text or "")
    if m:
        title = m.group(1).strip()[:200]
    server = resp.headers.get("Server", "")
    techs = _strip_tech_hints(dict(resp.headers), resp.text or "")
    gen = GENERATOR_RE.search(resp.text or "")
    if gen:
        techs.add(gen.group(1).strip())
    return TechResult(url=url, status=resp.status_code, title=title, server=server, techs=techs)


def httpx_available() -> bool:
    return shutil.which("httpx") is not None


def probe_httpx(urls: List[str], timeout: int = 60) -> List[TechResult]:
    """Probe with httpx -json when present; returns [] if unavailable."""
    if not httpx_available():
        return []
    tmp_in = "/tmp/shadowreap_httpx_in.txt"
    with open(tmp_in, "w", encoding="utf-8") as fh:
        fh.write("\n".join(urls) + "\n")
    try:
        proc = subprocess.run(
            ["httpx", "-silent", "-json", "-title", "-tech-detect", "-l", tmp_in],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    results: List[TechResult] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        techs = set(obj.get("tech") or [])
        results.append(
            TechResult(
                url=obj.get("url", ""),
                status=obj.get("status_code", 0),
                title=obj.get("title", "") or "",
                server=obj.get("webserver", "") or "",
                techs=techs,
            )
        )
    return results


def detect_tech(urls: List[str], timeout: int = 60) -> List[TechResult]:
    """httpx first; on any failure fall back to requests."""
    results = probe_httpx(urls, timeout=timeout)
    if results:
        return results
    return [r for r in (probe_requests(u) for u in urls) if r is not None]