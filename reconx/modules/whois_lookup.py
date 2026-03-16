import whois as pythonwhois
from datetime import datetime, timezone


def scan(target: str) -> list[dict]:
    findings = []

    try:
        w = pythonwhois.whois(target)

        info_lines = []
        if w.registrar:
            info_lines.append(f"Registrar: {w.registrar}")
        if w.creation_date:
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            info_lines.append(f"Registered: {cd.date() if isinstance(cd, datetime) else cd}")
        if w.expiration_date:
            ed = w.expiration_date
            if isinstance(ed, list):
                ed = ed[0]
            info_lines.append(f"Expires: {ed.date() if isinstance(ed, datetime) else ed}")

            # Warn on domain expiry
            if isinstance(ed, datetime):
                ed_utc = ed.replace(tzinfo=timezone.utc) if ed.tzinfo is None else ed
                days_left = (ed_utc - datetime.now(timezone.utc)).days
                if days_left < 30:
                    findings.append({
                        "category": "whois",
                        "severity": "high",
                        "title": f"Domain expires in {days_left} days",
                        "detail": f"Domain registration expires on {ed.date()}.",
                        "remediation": "Renew the domain registration immediately.",
                    })

        if w.name_servers:
            ns = w.name_servers
            if isinstance(ns, list):
                ns = [str(n) for n in ns[:4]]
            info_lines.append(f"Name servers: {', '.join(ns)}")

        if w.country:
            info_lines.append(f"Registrant country: {w.country}")

        if info_lines:
            findings.append({
                "category": "whois",
                "severity": "info",
                "title": "WHOIS information retrieved",
                "detail": "\n".join(info_lines),
                "remediation": None,
            })

        # Privacy check
        org = str(w.org or "")
        if any(kw in org.lower() for kw in ["privacy", "redacted", "whoisguard", "domains by proxy"]):
            findings.append({
                "category": "whois",
                "severity": "info",
                "title": "WHOIS privacy protection enabled",
                "detail": f"Registrant details are masked: {org}",
                "remediation": None,
            })

    except Exception as e:
        findings.append({
            "category": "whois",
            "severity": "info",
            "title": "WHOIS lookup failed or unavailable",
            "detail": str(e),
            "remediation": None,
        })

    return findings
