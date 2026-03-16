import ssl
import socket
from datetime import datetime, timezone

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5"}


def scan(target: str, port: int = 443) -> list[dict]:
    findings = []

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher_name, proto, _ = ssock.cipher()
                proto_ver = ssock.version()

        # Protocol check
        if proto_ver in WEAK_PROTOCOLS:
            findings.append({
                "category": "ssl",
                "severity": "critical",
                "title": f"Deprecated TLS protocol in use: {proto_ver}",
                "detail": f"Server negotiated {proto_ver}, which is considered insecure.",
                "remediation": "Disable TLSv1.0 and TLSv1.1. Only allow TLSv1.2 and TLSv1.3.",
            })
        else:
            findings.append({
                "category": "ssl",
                "severity": "info",
                "title": f"TLS protocol: {proto_ver}",
                "detail": f"Server is using {proto_ver}.",
                "remediation": None,
            })

        # Cipher check
        cipher_upper = cipher_name.upper()
        weak_found = [w for w in WEAK_CIPHERS if w in cipher_upper]
        if weak_found:
            findings.append({
                "category": "ssl",
                "severity": "high",
                "title": f"Weak cipher suite: {cipher_name}",
                "detail": f"Cipher contains weak components: {', '.join(weak_found)}",
                "remediation": "Configure server to use strong cipher suites only (AES-GCM, ChaCha20).",
            })
        else:
            findings.append({
                "category": "ssl",
                "severity": "info",
                "title": f"Cipher suite: {cipher_name}",
                "detail": "No obviously weak cipher components detected.",
                "remediation": None,
            })

        # Certificate expiry
        if cert and "notAfter" in cert:
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days

            if days_left < 0:
                findings.append({
                    "category": "ssl",
                    "severity": "critical",
                    "title": "SSL certificate has EXPIRED",
                    "detail": f"Certificate expired {abs(days_left)} days ago on {expiry.date()}.",
                    "remediation": "Renew the SSL certificate immediately.",
                })
            elif days_left < 14:
                findings.append({
                    "category": "ssl",
                    "severity": "high",
                    "title": f"SSL certificate expires in {days_left} days",
                    "detail": f"Certificate expires on {expiry.date()}.",
                    "remediation": "Renew the SSL certificate as soon as possible.",
                })
            elif days_left < 30:
                findings.append({
                    "category": "ssl",
                    "severity": "medium",
                    "title": f"SSL certificate expires in {days_left} days",
                    "detail": f"Certificate expires on {expiry.date()}.",
                    "remediation": "Plan to renew the SSL certificate within the next few weeks.",
                })
            else:
                findings.append({
                    "category": "ssl",
                    "severity": "info",
                    "title": f"SSL certificate valid for {days_left} more days",
                    "detail": f"Certificate expires on {expiry.date()}.",
                    "remediation": None,
                })

        # CN / SAN match
        if cert:
            san_list = []
            for (name, val) in cert.get("subjectAltName", []):
                if name == "DNS":
                    san_list.append(val.lstrip("*.").lower())
            clean_target = target.lstrip("*.").lower()
            if san_list and clean_target not in san_list:
                findings.append({
                    "category": "ssl",
                    "severity": "medium",
                    "title": "Certificate CN/SAN may not match target",
                    "detail": f"Target: {target}. SANs: {', '.join(san_list[:5])}",
                    "remediation": "Ensure the certificate covers the target domain.",
                })

    except ssl.SSLError as e:
        findings.append({
            "category": "ssl",
            "severity": "high",
            "title": "SSL handshake error",
            "detail": str(e),
            "remediation": "Review the server SSL/TLS configuration.",
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        findings.append({
            "category": "ssl",
            "severity": "info",
            "title": "HTTPS not available on port 443",
            "detail": "Could not establish SSL connection to port 443.",
            "remediation": None,
        })

    return findings
