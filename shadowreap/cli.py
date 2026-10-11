"""ShadowReap CLI."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .pipeline import run_pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shadowreap", description="Intelligent Recon Orchestrator")
    parser.add_argument("--scope", required=True, help="domain | IP | CIDR | ASN")
    parser.add_argument("--active", action="store_true", help="enable port scan (nmap -sT)")
    parser.add_argument("--outdir", default="reports", help="output directory (default: reports)")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="print each pipeline stage as it starts (like nmap -v)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        payload = run_pipeline(args.scope, active=args.active, outdir=args.outdir, verbose=args.verbose)
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(f"[shadowreap] ERROR: {exc}", file=sys.stderr)
        return 1

    j = payload["meta"].get("report_json")
    m = payload["meta"].get("report_md")
    print(f"[shadowreap] scope      : {payload['meta']['scope']} ({payload['meta']['kind']})")
    print(f"[shadowreap] subdomains : {len(payload['subdomains'])}")
    print(f"[shadowreap] hosts      : {len(payload['hosts'])}")
    print(f"[shadowreap] wildcard   : {payload['wildcard']}")
    print(f"[shadowreap] ports      : {len(payload['ports'])} (active={args.active})")
    print(f"[shadowreap] tech       : {len(payload['tech'])}")
    print(f"[shadowreap] endpoints  : {len(payload['endpoints'])}")
    print(f"[shadowreap] report.json: {j}")
    print(f"[shadowreap] summary.md : {m}")
    return 0


if __name__ == "__main__":
    sys.exit(main())