import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def _resolve(subdomain: str, domain: str) -> str | None:
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(2)
        ip = socket.gethostbyname(fqdn)
        return (fqdn, ip)
    except Exception:
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

    if found:
        detail = "\n".join(f"{fqdn} → {ip}" for fqdn, ip in found)
        findings.append({
            "category": "subdomain",
            "severity": "info",
            "title": f"{len(found)} subdomains discovered",
            "detail": detail,
            "remediation": "Review each subdomain. Remove or restrict any unneeded services.",
        })

        # Flag risky subdomains
        risky_keywords = ["admin", "jenkins", "jira", "grafana", "kibana", "redis",
                          "db", "mysql", "postgres", "backup", "internal", "intranet",
                          "staging", "dev", "test", "uat", "preprod", "elk"]
        for fqdn, ip in found:
            sub = fqdn.split(".")[0]
            if sub in risky_keywords:
                findings.append({
                    "category": "subdomain",
                    "severity": "medium",
                    "title": f"Sensitive subdomain exposed: {fqdn}",
                    "detail": f"{fqdn} resolves to {ip}. This subdomain suggests an internal/admin service.",
                    "remediation": f"Ensure {fqdn} is not publicly accessible or requires authentication.",
                })
    else:
        findings.append({
            "category": "subdomain",
            "severity": "info",
            "title": "No common subdomains found",
            "detail": f"None of {len(WORDLIST)} common subdomains resolved.",
            "remediation": None,
        })

    return findings
