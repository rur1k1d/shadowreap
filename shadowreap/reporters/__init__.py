"""Reporters: report.json (full) + summary.md (readable)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _jsonable(obj: Any) -> Any:
    """Convert dataclasses / sets / bytes to JSON-safe structures."""
    if hasattr(obj, "to_dict"):
        return _jsonable(obj.to_dict())
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(x) for x in obj]
    if isinstance(obj, set):
        return sorted(_jsonable(x) for x in obj)
    return obj


def write_json_report(payload: Dict[str, Any], outdir: Path, scope: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in scope)
    path = outdir / f"report_{safe}_{stamp}.json"
    path.write_text(json.dumps(_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")
    return path


def write_markdown_summary(payload: Dict[str, Any], outdir: Path, scope: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in scope)
    path = outdir / f"summary_{safe}_{stamp}.md"

    lines: List[str] = []
    lines.append(f"# ShadowReap summary — {scope}")
    lines.append("")
    lines.append(f"_generated {time.strftime('%Y-%m-%d %H:%M:%S')}_")
    lines.append("")

    meta = payload.get("meta", {})
    lines.append("## Meta")
    lines.append("")
    for k, v in meta.items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")

    if payload.get("wildcard"):
        lines.append("> **WILDCARD DNS detected** — subdomain enumeration is unreliable.")
        lines.append("")

    hosts = payload.get("hosts", [])
    lines.append(f"## Hosts ({len(hosts)})")
    lines.append("")
    for h in hosts:
        lines.append(f"- `{h['host']}` -> {', '.join(h.get('ips', [])) or 'unresolved'}")
    lines.append("")

    subdomains = payload.get("subdomains", [])
    lines.append(f"## Subdomains ({len(subdomains)})")
    lines.append("")
    for s in subdomains:
        lines.append(f"- {s}")
    lines.append("")

    ports = payload.get("ports", [])
    lines.append(f"## Open ports ({len(ports)})")
    lines.append("")
    if not ports:
        lines.append("_none (no --active scan)_")
    else:
        for p in ports:
            svc = f"{p['service']} {p['version']}".strip() or "?"
            label = p.get("hostname") or p["host"]
            lines.append(f"- `{label} ({p['host']}:{p['port']}/{p['protocol']})` — {svc}")
    lines.append("")

    tech = payload.get("tech", [])
    lines.append(f"## Tech stack ({len(tech)})")
    lines.append("")
    if not tech:
        lines.append("_none detected_")
    else:
        for t in tech:
            techs = ", ".join(t.get("techs", [])) or "-"
            lines.append(f"- `{t['url']}` [{t['status']}] {t.get('title', '')} | {techs}")
    lines.append("")

    endpoints = payload.get("endpoints", [])
    lines.append(f"## Interesting endpoints ({len(endpoints)})")
    lines.append("")
    if not endpoints:
        lines.append("_none found_")
    else:
        for e in endpoints:
            lines.append(f"- [{e['kind']}] {e['url']}")
            for entry in e.get("entries", [])[:50]:
                lines.append(f"    - {entry}")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_reports(payload: Dict[str, Any], outdir: Path, scope: str) -> tuple[Path, Path]:
    """Write both files and return (json_path, md_path)."""
    j = write_json_report(payload, outdir, scope)
    m = write_markdown_summary(payload, outdir, scope)
    return j, m