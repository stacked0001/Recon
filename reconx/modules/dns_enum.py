import dns.resolver
import dns.exception
import dns.zone
import dns.query

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def _query(domain: str, rtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def scan(target: str) -> list[dict]:
    findings = []

    for rtype in RECORD_TYPES:
        records = _query(target, rtype)
        if records:
            findings.append({
                "category": "dns",
                "severity": "info",
                "title": f"DNS {rtype} records found",
                "detail": "\n".join(records[:10]),
                "remediation": None,
            })

    # SPF check
    txt_records = _query(target, "TXT")
    spf_found = any("v=spf1" in r for r in txt_records)
    if not spf_found:
        findings.append({
            "category": "dns",
            "severity": "medium",
            "title": "Missing SPF record",
            "detail": "No SPF TXT record found. Allows email spoofing.",
            "remediation": 'Add a TXT record: "v=spf1 include:_spf.google.com ~all" (adjust for your mail provider).',
        })
    else:
        spf_val = next(r for r in txt_records if "v=spf1" in r)
        findings.append({
            "category": "dns",
            "severity": "info",
            "title": "SPF record present",
            "detail": spf_val,
            "remediation": None,
        })

    # DMARC check
    dmarc_records = _query(f"_dmarc.{target}", "TXT")
    if not dmarc_records:
        findings.append({
            "category": "dns",
            "severity": "medium",
            "title": "Missing DMARC record",
            "detail": "No DMARC policy found at _dmarc." + target,
            "remediation": 'Add: _dmarc TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@' + target + '"',
        })
    else:
        findings.append({
            "category": "dns",
            "severity": "info",
            "title": "DMARC record present",
            "detail": "\n".join(dmarc_records),
            "remediation": None,
        })

    # Zone transfer attempt
    ns_records = _query(target, "NS")
    for ns in ns_records[:3]:
        ns = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, target, timeout=3))
            findings.append({
                "category": "dns",
                "severity": "critical",
                "title": f"DNS Zone Transfer allowed on {ns}",
                "detail": f"Nameserver {ns} allows AXFR zone transfer. Full zone exposed.",
                "remediation": "Restrict zone transfers to authorized secondary nameservers only.",
            })
        except Exception:
            pass

    return findings
