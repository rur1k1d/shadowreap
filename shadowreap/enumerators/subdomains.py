"""Subdomain enumeration: crt.sh (passive JSON) + amass fallback."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import List, Set

import requests

CRTSH_URL = "https://crt.sh/?q=%25.{root}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={root}"
CRTSH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
}
MAX_RETRIES = 3
BACKOFF = 2.0  # seconds between crt.sh retries

MISSING_LIBPOSTAL_GATE = "/usr/share/libpostal/transliteration"


def _is_wildcard(name: str) -> bool:
    return name.startswith("*.")


def crtsh_subdomains(root: str, timeout: int = 30) -> List[str]:
    """Query crt.sh for the root and return unique, non-wildcard subdomains."""
    url = CRTSH_URL.format(root=root)
    names: Set[str] = set()
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=CRTSH_HEADERS, timeout=timeout)
            if resp.status_code >= 500:
                raise requests.HTTPError(f"crt.sh status {resp.status_code}")
            resp.raise_for_status()
            data = resp.json()
            for entry in data:
                raw = entry.get("name_value", "") or ""
                for n in raw.split("\n"):
                    n = n.strip().rstrip(".").lower()
                    if not n:
                        continue
                    if _is_wildcard(n):
                        continue
                    if n.endswith("." + root) or n == root:
                        names.add(n)
            return sorted(names)
        except (requests.RequestException, ValueError):
            if attempt < MAX_RETRIES:
                time.sleep(BACKOFF * attempt)
            else:
                raise
    return sorted(names)


def hackertarget_subdomains(root: str, timeout: int = 30) -> List[str]:
    """Passive fallback source (comma lines: host,ip). Returns [] on any
    failure so callers can move on to the next source."""
    url = HACKERTARGET_URL.format(root=root)
    try:
        resp = requests.get(url, headers=CRTSH_HEADERS, timeout=timeout)
        if resp.status_code != 200:
            return []
        raw = resp.text.strip()
        if not raw or "error" in raw.lower() or "API count exceeded" in raw:
            return []
        names = set()
        for line in raw.splitlines():
            host = line.split(",")[0].strip().lower()
            if host and not _is_wildcard(host) and host.endswith("." + root):
                names.add(host)
        return sorted(names)
    except requests.RequestException:
        return []


def _amass_candidates() -> List[str]:
    """Real amass binary paths. The Debian wrapper (/usr/bin/amass) triggers a
    sudo drop to download libpostal — we never ask for root, so we look past it."""
    cands = ["/usr/lib/amass/amass", "/usr/local/bin/amass"]
    if os.path.exists(MISSING_LIBPOSTAL_GATE):
        cands.insert(0, shutil.which("amass") or "")
    return [c for c in cands if c and os.path.isfile(c)]


def amass_available() -> bool:
    """True if a usable, non-sudo amass binary exists."""
    return bool(_amass_candidates())


def amass_subdomains(root: str, timeout: int = 180) -> List[str]:
    """Amass passive subdomain enum. Returns [] on any failure (no binary,
    timeout). Never requests root."""
    bin_path = _amass_candidates()
    if not bin_path:
        return []
    workdir = "/tmp/shadowreap_amass"
    os.makedirs(workdir, exist_ok=True)
    prefix = os.path.join(workdir, "out")
    # Clear stale outputs from the previous run.
    for f in os.listdir(workdir):
        p = os.path.join(workdir, f)
        if os.path.isfile(p):
            try:
                os.unlink(p)
            except OSError:
                pass
    cmd = [bin_path[0], "enum", "-passive", "-d", root, "-oA", prefix]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return []
    if proc.returncode != 0:
        return []
    names: Set[str] = set()
    for f in sorted(os.listdir(workdir)):
        p = os.path.join(workdir, f)
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    n = line.strip().lower()
                    if n and not _is_wildcard(n) and n.endswith("." + root):
                        names.add(n)
        except OSError:
            continue
    return sorted(names)


def enumerate_subdomains(root: str) -> tuple[List[str], List[str]]:
    """Run passive enumeration, sources in order of reliability:
    crt.sh -> hackertarget -> amass. Returns (subdomains, sources_used)."""
    domains: List[str] = []
    sources: List[str] = []
    try:
        domains = crtsh_subdomains(root)
        sources.append("crt.sh")
    except requests.RequestException:
        domains = []
    if not domains:
        ht = hackertarget_subdomains(root)
        if ht:
            domains, sources = ht, ["hackertarget"]
    if amass_available():
        extra = amass_subdomains(root)
        if extra:
            seen = set(domains)
            for d in extra:
                if d not in seen:
                    domains.append(d)
                    seen.add(d)
            domains.sort()
            sources.append("amass")
    return domains, sources