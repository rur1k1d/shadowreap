# ShadowReap — plan.md

> Project plan + improvement roadmap. Created 2026-10-11. English by default.

## 1. Name decision

Source: `projects/inspirationX.md` — main words: *Dread, dark, shadow,
shadowed, doom, soul, seal, hand, reaper, spreading shadows*.

**Chosen: ShadowReap** — "Reaper of" (the shadow) — recon oracle that reaps
the attack surface. "Shadow" matches the fee / darkness category; it mines
subdomains, hosts, ports, tech, endpoints = harvests the shadow of the scope.

Name is lowercase-safe for CLI/pip (`shadowreap`), unique, red-team flavored.

Alternatives considered:

| Candidate | Why | Verdict |
|---|---|---|
| `ShadowReap` | reaps the shadow surface, memorable | **selected** |
| `DreadRecon` | "Dread" from main words; clear "recon" | 2nd |
| `SpreadingShadows` | verbatim line 49; poetic but long | 3rd |
| `ShadowScript` | main word + script | generic, clashes with ShadowSpawn etc. |
| `DoomHand` | line 15/53 vibe | too doom-metal, unclear purpose |

## 2. Architecture

```
shadowreap/
  __init__.py      # version
  cli.py           # argparse entry (scope, --active, --outdir)
  pipeline.py      # orchestrates stages in order
  parsers/
    scope.py       # normalize scope: domain | CIDR | ASN
    dns.py         # resolve + wildcard check + dedupe
    tech.py        # title/server/tech signatures from requests
    endpoints.py   # robots.txt + sitemap.xml parsing
    nmap_xml.py    # nmap XML -> ports
  enumerators/
    subdomains.py  # crt.sh JSON + amass fallback-if-available
  scanners/
    ports.py       # nmap -sT runner
  reporters/
    base.py        # report.json + summary.md writers
tests/
  test_scope.py
  test_subdomains.py
  test_dns.py
  test_tech.py
  test_endpoints.py
  test_nmap_xml.py
```

## 3. Stage list

1. **Scope** — accept `example.com` | `1.2.3.4` | `1.2.3.0/24` | `AS15169`.
2. **Subdomains** — crt.sh passive JSON (wildcard-filtered); amass only if
   binary exists and runs without sudo (graceful skip otherwise).
3. **DNS** — resolve hosts to IPs (`socket`), wildcard-DNS check, dedupe
   (host -> set of IPs).
4. **Ports** (`--active` only) — nmap `-sT -Pn`, parse XML.
5. **Tech stack** — httpx if present (`-json`), else requests: title, server,
   tech signatures.
6. **Endpoints** — robots.txt + sitemap.xml discovery for live hosts.
7. **Report** — `report.json` (full) + `summary.md` (readable) in `reports/`.

## 4. Roadmap / improvements

See end of this file — kept in `PLAN_ROADMAP.md`-style section below (or
inline if short).

## 5. Improvements log (unscoped ideas)

### High-value (recommended next)

- [ ] **ASN/IP expansion stage** — resolve ASN to CIDR set (amass intel / bgp
  heimdall / `whois`), then enumerate live hosts; CIDR scope: masscan full L4
  sweep → alive IPs. Currently CIDR/ASN pass straight to nmap.
- [ ] **Scope guard** — reject subdomain enum for CIDR/ASN scopes (only IP
  enumeration), reject DNS for bare IP scopes. *This is a correctness guard,
  not a scope-police (bug-bounty scope-enforcement lives elsewhere — see
  `Projects_archive` CleverTrap scope_guard).*
- [ ] **Concurrency** — thread pool for DNS resolution and tech probing
  (currently sequential; ~2 s/request × 100 hosts adds up).
- [ ] **`--resume` / incremental** — skip stages whose results are cached in the
  report dir; dedupe state file (`state.json`).
- [ ] **Config file `shadowreap.yaml`** — default flags, tool paths, tech
  signature additions, timeout tuning.
- [ ] **429/backoff hardening on all passive sources** (crt.sh flaky by nature,
  hackertarget has daily free quota).

### Integrations

- [ ] **Nuclei scan stage** (`--active --vuln`) — feed live hosts to nuclei,
  fold findings into report.
- [ ] **katana/gau** when present — expand endpoint discovery beyond
  robots/sitemap (JS files, link extraction).
- [ ] **GitHub Actions smoke** — daily passive run on example.com, TOTP sync of
  reports, badge in README.
- [ ] **`pip` entry point** (`console_scripts`), publishable to PyPI.

### ideas.md tie-ins (the "bigger picture" from `projects/ideas.md`)

- [ ] **Continuous Recon Monitor (idea #3)** — scheduled runs + diffing
  (`shadowreap run` twice → compare hosts/ports/tech) + Telegram/Discord/email
  alert when **new** subdomains/ports/services/certs appear. This is the
  natural v0.2: "ShadowReap as a service".
- [ ] **Netrunner / AI operator vision** — wrap the pipeline as an opencode
  agent tool: natural-language target → `shadowreap` → report → opencode reads
  and summarizes. ShadowReap becomes module 1 of the Netrunner platform.
- [ ] **Bento/report UI (idea #2 synergy)** — the ReportForge project could
  render `report.json` into branded PDF/HTML (reuse ReportForge ingest).

### Polish

- [ ] Risk notes per exposed tech version in summary.md.
- [ ] `-oA`-style summary (all formats: json + md + html) in one command.
- [ ] Optional `textual` TUI menu (original ideas.md proposal) over the same
  pipeline.
- [ ] Sitemap recursion (sitemap index → child sitemaps, depth-limited).
- [ ] Vhost/redirect detection for web tech stage.

## 6. Verification (house rule)

Every stage ships with a pytest test; smoke run is passive on example.com
(no `--active`). `--active` never runs in tests.