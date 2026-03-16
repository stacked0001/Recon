import requests
import urllib3
urllib3.disable_warnings()

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "remediation": "Add a Content-Security-Policy header to prevent XSS attacks.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "remediation": "Add a Permissions-Policy header to restrict browser features.",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Exposing server software version aids attackers. Remove or obscure the Server header.",
    "X-Powered-By": "Remove X-Powered-By to avoid disclosing technology stack.",
    "X-AspNet-Version": "Remove X-AspNet-Version header to hide framework version.",
}


def scan(target: str) -> list[dict]:
    findings = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            resp = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 ReconCLI/1.0"})
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header, meta in REQUIRED_HEADERS.items():
                if header.lower() not in headers_lower:
                    findings.append({
                        "category": "header",
                        "severity": meta["severity"],
                        "title": f"Missing security header: {header}",
                        "detail": f"{header} is not set in the HTTP response.",
                        "remediation": meta["remediation"],
                    })
                else:
                    findings.append({
                        "category": "header",
                        "severity": "info",
                        "title": f"Header present: {header}",
                        "detail": f"{header}: {headers_lower[header.lower()]}",
                        "remediation": None,
                    })

            for header, fix in DANGEROUS_HEADERS.items():
                if header.lower() in headers_lower:
                    findings.append({
                        "category": "header",
                        "severity": "low",
                        "title": f"Information disclosure: {header}",
                        "detail": f"{header}: {headers_lower[header.lower()]}",
                        "remediation": fix,
                    })

            break  # Got a response, stop trying schemes

        except requests.RequestException:
            continue

    if not findings:
        findings.append({
            "category": "header",
            "severity": "info",
            "title": "Could not fetch HTTP headers",
            "detail": "No HTTP/HTTPS response received.",
            "remediation": None,
        })

    return findings
