# Recon

Fast, free security reconnaissance tool for pentesters, developers, and bug bounty hunters.

Scans any domain or IP in under 2 minutes and outputs a colour-coded terminal report + optional PDF.

```
$ python -m reconx hvacestimators.net

  ── PORT SCAN ──────────────────────────────────────────
  ⚪ INFO      Open port 80/HTTP
  ⚪ INFO      Open port 443/HTTPS

  ── SSL/TLS ────────────────────────────────────────────
  ⚪ INFO      TLS protocol: TLSv1.3
  🟡 MEDIUM    SSL certificate expires in 18 days

  ── SENSITIVE PATHS ────────────────────────────────────
  🔴 CRITICAL  Git repository exposed
  🔴 CRITICAL  Environment file exposed
  🔴 CRITICAL  Database backup exposed

  ╭─────────────────────────────────────────────────────╮
  │  Grade: F   Risk Score: 100/100   CRITICAL          │
  │  (0 = no risk, 100 = critical — lower is better)    │
  ╰─────────────────────────────────────────────────────╯
```

## Install

```bash
pipx install git+https://github.com/stacked0001/Recon.git
```

> Don't have pipx? Run `pip install pipx` first.

Then scan any domain:

```bash
python -m reconx example.com
```

## Usage

```bash
# Basic scan
python -m reconx example.com

# Save a PDF report
python -m reconx example.com --pdf report.pdf

# JSON output (great for pipelines)
python -m reconx example.com --json > findings.json

# Run specific modules only
python -m reconx example.com --modules port,ssl,headers

# Show full details for every finding
python -m reconx example.com --verbose

# Scan an IP
python -m reconx 192.168.1.1
```

## What it checks

| Module | What it checks |
|--------|---------------|
| `port` | Top 20 common ports (SSH, RDP, Redis, MongoDB, etc.) |
| `ssl` | Cert expiry, weak ciphers, deprecated protocols (TLS 1.0/1.1) |
| `headers` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `dns` | A, MX, NS, TXT, SPF, DMARC, zone transfer attempt |
| `subdomains` | Brute-forces 60 common subdomains |
| `paths` | `.git`, `.env`, phpMyAdmin, admin panels, backup files, actuator endpoints |
| `whois` | Registrar, registration/expiry dates, privacy check |

## Risk Scoring

| Severity | Points |
|----------|--------|
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 3 |
| Info | 0 |

Grades: **A** (0–20, Minimal) · **B** (21–40, Low) · **C** (41–60, Moderate) · **D** (61–80, High) · **F** (81–100, Critical)

## Requirements

- Python 3.10+
- Works on Linux, macOS, Windows

## Legal

Only scan targets you own or have **written authorisation** to test.
Unauthorised scanning may be illegal in your jurisdiction.

## License

MIT
