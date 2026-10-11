"""Port scan via nmap (-sT, --active only) + XML parsing."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PortResult:
    host: str
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""


def parse_nmap_xml(xml_text: str) -> List[PortResult]:
    """Parse nmap -oX output into PortResult list."""
    results: List[PortResult] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        addr_el = host.find("address")
        hostname = addr_el.get("addr", "") if addr_el is not None else ""
        for port_el in host.findall("./ports/*"):
            if port_el.tag != "port":
                continue
            state_el = port_el.find("state")
            if state_el is None:
                continue
            state = state_el.get("state", "")
            if state != "open":
                continue
            service_el = port_el.find("service")
            results.append(
                PortResult(
                    host=hostname,
                    port=int(port_el.get("portid", "0")),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state,
                    service=(service_el.get("name", "") if service_el is not None else ""),
                    version=(service_el.get("version", "") if service_el is not None else ""),
                )
            )
    return results


def parse_nmap_file(path: str) -> List[PortResult]:
    with open(path, encoding="utf-8") as fh:
        return parse_nmap_xml(fh.read())


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run_nmap(hosts: List[str], ports: str = "top-100", timeout: int = 300) -> List[PortResult]:
    """Run `nmap -sT -Pn` against hosts. Returns parsed open ports.

    Requires --active context (enforced by the orchestrator, not here).
    """
    if not nmap_available():
        return []
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name
    cmd = [
        "nmap",
        "-sT", "-Pn", "--open",
        "--top-ports", ports if ports.isdigit() else "100",
        "-oX", xml_path,
        "--min-rate", "2000",
        *hosts,
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return parse_nmap_file(xml_path)
    except (subprocess.TimeoutExpired, OSError):
        return []
    finally:
        try:
            import os
            os.unlink(xml_path)
        except FileNotFoundError:
            pass
    return []