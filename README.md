# Recon-CLI

Fast, free security reconnaissance tool for pentesters, developers, and bug bounty hunters.

Scans any domain or IP in under 2 minutes and outputs a colour-coded terminal report + optional PDF.

```
$ recon example.com

  Target:  example.com
  Modules: Port Scan, SSL/TLS, HTTP Headers, DNS, Subdomains, Paths, WHOIS

  ── PORT SCAN ──────────────────────────────────────────
  🔴 CRITICAL  Open port 6379/Redis
  🟠 HIGH      Open port 22/SSH
  ⚪ INFO      Open port 443/HTTPS

  ── SSL/TLS ────────────────────────────────────────────
  ⚪ INFO      TLS protocol: TLSv1.3
  🟡 MEDIUM    SSL certificate expires in 18 days

  ── HTTP HEADERS ───────────────────────────────────────
  🟡 MEDIUM    Missing security header: Content-Security-Policy
  🟡 MEDIUM    Missing security header: Strict-Transport-Security

  ┌─────────────────────────────────────────┐
  │  Grade: C   Score: 47/100   MODERATE    │
  └─────────────────────────────────────────┘
```

## Install

```bash
pipx install reconx
```

> Don't have pipx? `pip install pipx` then `pipx ensurepath` (restart terminal after)

Then run from anywhere:

```bash
python -m reconx example.com
```

## Usage

```bash
# Basic scan
recon example.com

# Save a PDF report
recon example.com --pdf report.pdf

# JSON output (great for pipelines)
recon example.com --json > findings.json

# Run specific modules only
recon example.com --modules port,ssl,headers

# Show details for every finding
recon example.com --verbose

# Scan an IP
recon 192.168.1.1 --modules port,ssl
```

## Modules

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

Each finding contributes to a 0–100 risk score:

| Severity | Points |
|----------|--------|
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 3 |
| Info | 0 |

Grades: **A** (0–20, Minimal) · **B** (21–40, Low) · **C** (41–60, Moderate) · **D** (61–80, High) · **F** (81–100, Critical)

## Development install

```bash
git clone https://github.com/YOUR_USERNAME/reconx.git
cd reconx
pipx install -e .
```

## Requirements

- Python 3.10+
- Works on Linux, macOS, Windows

## Legal

Only scan targets you own or have **written authorisation** to test.
Unauthorised scanning may be illegal in your jurisdiction.

## License

MIT
