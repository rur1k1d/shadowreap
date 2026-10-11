# ShadowReap

Intelligent Recon Orchestrator — the flagship project from `projects/ideas.md`.

Give it a **scope** (domain / CIDR / ASN) and it runs the whole recon pipeline
and generates a report:

```
scope -> subdomains -> DNS -> ports -> tech stack -> interesting endpoints -> report
```

Each stage degrades gracefully: external tools (`amass`, `httpx`, `nmap`) are
used when present, pure-Python fallbacks otherwise. Nothing needs root; active
stages (port scan) are gated behind `--active`.

Name: **ShadowReap** — from `projects/inspirationX.md` ("Reaper of", "shadow",
"spreading shadows"): it reaps the shadow — everything a target exposes.

## Quick start

```bash
pip install -r requirements.txt
python -m shadowreap --scope example.com            # passive + DNS + tech + endpoints
python -m shadowreap --scope 93.184.215.0/24       # CIDR scope
python -m shadowreap --scope AS15169               # ASN scope
python -m shadowreap --scope example.com --active  # enable port scan (nmap)
```

`--active` is required for the port-scan stage. Reports land in `reports/`
(`report.json` full data + `summary.md` readable).

## Stages

| Stage | Tool | Fallback |
|---|---|---|
| Subdomain enum | crt.sh (passive JSON) → hackertarget → amass | degrades between sources |
| DNS resolution | `resolve` via Python `socket` | — |
| Wildcard check | random label resolve | — |
| Port scan (`--active`) | nmap -sT | — |
| Tech stack | httpx | requests (title/server + signatures) |
| Endpoints | robots.txt + sitemap.xml | — |
| Report | report.json + summary.md | — |

Amass is detected **sudo-aware**: the Debian wrapper `/usr/bin/amass` drops to
sudo to fetch libpostal, so ShadowReap looks for the real binary
(`/usr/lib/amass/amass`) and never asks for root.

## Tests

```bash
python -m pytest tests/ -q
```