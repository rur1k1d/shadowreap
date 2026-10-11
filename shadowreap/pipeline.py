"""Pipeline: scope -> subdomains -> dns -> ports -> tech -> endpoints -> report."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List

from .enumerators import enumerate_subdomains
from .parsers import Scope, parse_scope
from .parsers.dns import Resolver
from .parsers.endpoints import discover_endpoints
from .parsers.tech import detect_tech
from .reporters import write_reports
from .scanners import run_nmap

_SCRAPER_UA = "Mozilla/5.0 shadowreap/0.1"

_VERBOSE_OFF = object()


def _log(verbose: bool, msg: str) -> None:
    """Stage progress lines (like nmap -v) only when verbose is on."""
    if verbose:
        import sys

        print(f"[shadowreap] {msg}", file=sys.stderr, flush=True)


def _http_urls(host: str) -> List[str]:
    """Two probe URLs per host (http + https) for tech/endpoint stages."""
    return [f"https://{host}", f"http://{host}"]


def run_pipeline(scope_str: str, active: bool = False, outdir: str = "reports", verbose: bool = False) -> Dict[str, Any]:
    """Execute the full recon pipeline for a scope.

    Returns the full report payload dict. Writes report.json + summary.md.
    With verbose=True, prints each stage as it starts (like nmap -v).
    """
    scope: Scope = parse_scope(scope_str)
    _log(verbose, f"scope: {scope_str} ({scope.kind})")
    payload: Dict[str, Any] = {
        "meta": {"scope": scope_str, "kind": scope.kind, "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "active": active},
        "hosts": [],
        "subdomains": [],
        "ports": [],
        "tech": [],
        "endpoints": [],
        "wildcard": False,
        "sources": [],
    }

    resolver = Resolver(root=scope.subdomain_root() or "")

    if scope.kind == "domain":
        # Stage 1: subdomains (passive)
        _log(verbose, "stage 1/6: subdomain enumeration (crt.sh -> hackertarget -> amass)")
        subs, sources = enumerate_subdomains(scope.subdomain_root() or "")
        payload["subdomains"] = subs
        payload["sources"] = sources
        _log(verbose, f"  sources: {', '.join(sources) or 'none'} | found {len(subs)} subdomains")
        # Wildcard check
        _log(verbose, "stage 2/6: DNS resolution + wildcard check")
        payload["wildcard"] = resolver.wildcard_check()
        # Stage 2: DNS
        hosts = [scope.subdomain_root() or ""] + subs
        for h in hosts:
            ips = resolver.resolve(h)
            payload["hosts"].append({"host": h, "ips": sorted(ips)})
        payload["hosts"] = sorted(payload["hosts"], key=lambda h: h["host"])
        _log(verbose, f"  resolved {len(payload['hosts'])} hosts")
    else:
        # cidr/asn — pass the scope through to later stages.
        root = scope.subdomain_root()
        payload["hosts"] = [{"host": scope.display if root is None else root, "ips": []}]

    # Stage 4 (ports) only with --active (and only meaningful for domains/cidr)
    if active and scope.kind != "asn":
        # Deduplicate targets: one IP scanned once, even if several hostnames
        # resolve to it (pentestit.pl + www -> same address -> 2 entries).
        if scope.kind == "domain":
            live_hosts = sorted(
                {
                    ip
                    for h in payload["hosts"]
                    for ip in h.get("ips", [])
                    if ":" not in ip  # IPv4 only for the TCP scan targets
                }
            )
        else:
            live_hosts = [scope.display]
        if live_hosts:
            _log(verbose, f"stage 3/6: port scan (nmap -sT against {len(live_hosts)} unique IPv4)")
            payload["ports"] = [
                {
                    "host": p.host,
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "version": p.version,
                }
                for p in run_nmap(live_hosts)
            ]
            # Map scanned IPs back to their hostnames for readable output.
            ip_to_host = {}
            for h in payload["hosts"]:
                for ip in h.get("ips", []):
                    ip_to_host.setdefault(ip, h["host"])
            for p in payload["ports"]:
                p["hostname"] = ip_to_host.get(p["host"], "")

    # Stage 5+6: tech + endpoints for live web hosts
    target_urls: List[str] = []
    for host in payload["hosts"]:
        if host["ips"] and not host["host"].endswith("ip6.arpa"):
            target_urls.extend(_http_urls(host["host"]))
    if target_urls:
        _log(verbose, f"stage 4/6: tech stack probing ({len(target_urls)} urls, httpx -> requests)")
        payload["tech"] = [t.to_dict() for t in detect_tech(target_urls)]
        _log(verbose, f"  identified {len(payload['tech'])} web results")
        web_urls = [t["url"] for t in payload["tech"] if t.get("status", 0) < 400]
        _log(verbose, "stage 5/6: endpoints (robots.txt + sitemap.xml)")
        payload["endpoints"] = [e.to_dict() for e in discover_endpoints(web_urls or target_urls[:5])]
        _log(verbose, f"  collected {len(payload['endpoints'])} result objects")

    payload["meta"]["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")

    _log(verbose, "stage 6/6: writing report.json + summary.md")
    out = Path(outdir)
    json_path, md_path = write_reports(payload, out, scope_str)
    payload["meta"]["report_json"] = str(json_path)
    payload["meta"]["report_md"] = str(md_path)
    _log(verbose, f"  wrote {json_path.name}, {md_path.name}")
    return payload