import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

PORTS = {
    21:   ("FTP",        "medium"),
    22:   ("SSH",        "info"),
    23:   ("Telnet",     "high"),
    25:   ("SMTP",       "low"),
    53:   ("DNS",        "info"),
    80:   ("HTTP",       "info"),
    110:  ("POP3",       "low"),
    143:  ("IMAP",       "low"),
    443:  ("HTTPS",      "info"),
    445:  ("SMB",        "high"),
    3306: ("MySQL",      "critical"),
    3389: ("RDP",        "high"),
    5432: ("PostgreSQL", "critical"),
    5900: ("VNC",        "high"),
    6379: ("Redis",      "critical"),
    8080: ("HTTP-Alt",   "low"),
    8443: ("HTTPS-Alt",  "info"),
    9200: ("Elasticsearch", "critical"),
    27017:("MongoDB",    "critical"),
    11211:("Memcached",  "critical"),
}

RISKY = {3306, 5432, 6379, 9200, 27017, 11211, 23, 445, 3389, 5900}

def _check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def scan(target: str) -> list[dict]:
    findings = []
    open_ports = []

    with ThreadPoolExecutor(max_workers=20) as ex:
        future_map = {ex.submit(_check_port, target, p): p for p in PORTS}
        for fut in as_completed(future_map):
            port = future_map[fut]
            if fut.result():
                open_ports.append(port)

    open_ports.sort()

    for port in open_ports:
        service, base_sev = PORTS[port]
        severity = "critical" if port in RISKY else base_sev
        findings.append({
            "category": "port",
            "severity": severity,
            "title": f"Open port {port}/{service}",
            "detail": f"Port {port} ({service}) is open and reachable.",
            "remediation": (
                f"If {service} should not be publicly accessible, restrict it via firewall rules."
                if port in RISKY
                else f"Ensure {service} on port {port} is intentionally exposed."
            ),
        })

    if not open_ports:
        findings.append({
            "category": "port",
            "severity": "info",
            "title": "No high-risk ports detected",
            "detail": "None of the top 20 common ports are open.",
            "remediation": None,
        })

    return findings
