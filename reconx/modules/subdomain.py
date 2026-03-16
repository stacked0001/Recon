import socket
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "vpn",
    "remote", "beta", "app", "portal", "login", "secure", "shop", "blog",
    "forum", "support", "docs", "cdn", "static", "assets", "media", "img",
    "images", "video", "files", "download", "upload", "smtp", "pop", "imap",
    "webmail", "mx", "ns1", "ns2", "git", "svn", "ci", "jenkins", "jira",
    "confluence", "monitor", "grafana", "prometheus", "elk", "kibana", "redis",
    "db", "mysql", "postgres", "backup", "dashboard", "internal", "intranet",
    "sandbox", "uat", "preprod", "old", "new", "v1", "v2", "auth", "sso",
]

RISKY_SUBS = {
    "admin", "jenkins", "jira", "grafana", "kibana", "redis", "db", "mysql",
    "postgres", "backup", "internal", "intranet", "elk", "prometheus", "git",
    "svn", "ci", "confluence", "staging", "dev", "uat", "preprod",
}


def _resolve(subdomain: str, domain: str):
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(2)
        ip = socket.gethostbyname(fqdn)
        return (fqdn, ip, subdomain)
    except Exception:
        return None


def _check_unauthed(fqdn: str):
    """Returns response snippet if accessible without auth, else None."""
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{fqdn}",
                timeout=4, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 ReconCLI/1.0"},
            )
            if r.status_code in (401, 403):
                return None  # Properly protected
            if r.status_code == 200 and len(r.content) > 200:
                body_lower = r.content.lower()
                # Skip generic error pages
                if any(kw in body_lower for kw in [b"404", b"not found"]):
                    return None
                return f"HTTP 200 — {len(r.content)} bytes"
        except Exception:
            pass
    return None


def scan(target: str) -> list[dict]:
    findings = []
    found = []

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_resolve, sub, target): sub for sub in WORDLIST}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: x[0])

    if not found:
        findings.append({
            "category": "subdomain",
            "severity": "info",
            "title": "No common subdomains found",
            "detail": f"None of {len(WORDLIST)} common subdomains resolved.",
            "remediation": None,
        })
        return findings

    # All found subdomains → info (no score impact)
    findings.append({
        "category": "subdomain",
        "severity": "info",
        "title": f"{len(found)} subdomains discovered",
        "detail": "\n".join(f"{fqdn} → {ip}" for fqdn, ip, _ in found),
        "remediation": None,
    })

    # Only elevate risky subs that are actually accessible without auth
    risky = [(fqdn, ip, sub) for fqdn, ip, sub in found if sub in RISKY_SUBS]
    if risky:
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(_check_unauthed, fqdn): (fqdn, ip, sub) for fqdn, ip, sub in risky}
            for fut in as_completed(futures):
                fqdn, ip, sub = futures[fut]
                snippet = fut.result()
                if snippet:
                    findings.append({
                        "category": "subdomain",
                        "severity": "medium",
                        "title": f"Sensitive subdomain publicly accessible: {fqdn}",
                        "detail": f"{fqdn} → {ip} | {snippet}",
                        "remediation": f"Restrict {fqdn} to authenticated users or internal networks only.",
                    })

    return findings
