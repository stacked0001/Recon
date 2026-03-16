import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings()

PATHS = [
    ("/.git/config",         "critical", "Git repository exposed",          lambda r: b"[core]" in r.content),
    ("/.env",                "critical", "Environment file exposed",         lambda r: _is_env(r)),
    ("/.env.backup",         "critical", "Environment backup exposed",       lambda r: _is_env(r)),
    ("/.env.production",     "critical", "Production environment file exposed", lambda r: _is_env(r)),
    ("/phpMyAdmin/",         "high",     "phpMyAdmin panel exposed",         lambda r: b"phpMyAdmin" in r.content or b"phpmyadmin" in r.content.lower()),
    ("/phpmyadmin/",         "high",     "phpMyAdmin panel exposed",         lambda r: b"phpMyAdmin" in r.content or b"phpmyadmin" in r.content.lower()),
    ("/admin/",              "high",     "Admin panel exposed",              lambda r: _is_html_page(r)),
    ("/wp-admin/",           "high",     "WordPress admin panel exposed",    lambda r: b"WordPress" in r.content or b"wp-login" in r.content),
    ("/wp-login.php",        "high",     "WordPress login page exposed",     lambda r: b"WordPress" in r.content or b"wp-login" in r.content),
    ("/.htaccess",           "medium",   "Apache config file exposed",       lambda r: b"RewriteEngine" in r.content or b"Options" in r.content or b"Allow" in r.content),
    ("/backup.zip",          "critical", "Backup archive exposed",           lambda r: _is_binary(r, b"PK\x03\x04")),
    ("/backup.sql",          "critical", "Database backup exposed",          lambda r: _is_sql(r)),
    ("/backup.tar.gz",       "critical", "Backup archive exposed",           lambda r: _is_binary(r, b"\x1f\x8b")),
    ("/config.php",          "critical", "Config file exposed",              lambda r: b"<?php" in r.content or b"DB_" in r.content),
    ("/web.config",          "high",     "IIS config file exposed",          lambda r: b"<configuration" in r.content or b"<?xml" in r.content),
    ("/server-status",       "medium",   "Apache server-status exposed",     lambda r: b"Apache" in r.content or b"Server Status" in r.content),
    ("/actuator",            "high",     "Spring Boot actuator exposed",     lambda r: b"_links" in r.content or b"actuator" in r.content),
    ("/actuator/health",     "medium",   "Spring Boot health endpoint exposed", lambda r: b"status" in r.content),
    ("/actuator/env",        "critical", "Spring Boot env endpoint exposed", lambda r: b"propertySources" in r.content or b"systemProperties" in r.content),
    ("/api/swagger",         "low",      "Swagger API docs exposed",         lambda r: b"swagger" in r.content.lower()),
    ("/swagger-ui.html",     "low",      "Swagger UI exposed",               lambda r: b"swagger" in r.content.lower()),
    ("/swagger.json",        "low",      "Swagger JSON spec exposed",        lambda r: b"swagger" in r.content or b"openapi" in r.content),
    ("/openapi.json",        "low",      "OpenAPI spec exposed",             lambda r: b"openapi" in r.content or b"paths" in r.content),
    ("/.DS_Store",           "low",      "macOS .DS_Store file exposed",     lambda r: len(r.content) > 4 and r.content[:4] == b"\x00\x00\x00\x01"),
    ("/robots.txt",          "info",     "robots.txt found",                 lambda r: b"User-agent" in r.content or b"Disallow" in r.content),
    ("/sitemap.xml",         "info",     "sitemap.xml found",                lambda r: b"<urlset" in r.content or b"<sitemapindex" in r.content),
    ("/.well-known/security.txt", "info","security.txt found",              lambda r: b"Contact:" in r.content),
    ("/crossdomain.xml",     "medium",   "Flash crossdomain policy exposed", lambda r: b"cross-domain-policy" in r.content),
    ("/elmah.axd",           "high",     "ELMAH error log exposed",          lambda r: b"Error Log" in r.content or b"elmah" in r.content.lower()),
    ("/trace.axd",           "high",     "ASP.NET trace exposed",            lambda r: b"Application Trace" in r.content or b"aspnet" in r.content.lower()),
]


def _is_env(r: requests.Response) -> bool:
    body = r.content
    is_html = b"<html" in body.lower() or b"<!doctype" in body.lower()
    has_kv = b"=" in body and b"\n" in body
    return has_kv and not is_html


def _is_sql(r: requests.Response) -> bool:
    body = r.content.lower()
    return any(kw in body for kw in [b"insert into", b"create table", b"drop table", b"-- mysql", b"mysqldump"])


def _is_binary(r: requests.Response, magic: bytes) -> bool:
    return r.content[:len(magic)] == magic


def _is_html_page(r: requests.Response) -> bool:
    body = r.content.lower()
    return b"<html" in body or b"<!doctype" in body


def _check(url: str, path: str, label: str, severity: str, validator, session: requests.Session):
    full_url = url.rstrip("/") + path
    try:
        resp = session.get(full_url, timeout=6, verify=False, allow_redirects=False)
        if resp.status_code in (200, 206):
            if validator(resp):
                return (path, severity, label, full_url, resp.status_code)
    except Exception:
        pass
    return None


def _homepage_fingerprint(base_url: str, session: requests.Session):
    """Returns (status, size) of homepage to detect catch-all servers."""
    try:
        r = session.get(base_url, timeout=5, verify=False, allow_redirects=True)
        return (r.status_code, len(r.content))
    except Exception:
        return (None, 0)


def _is_catchall(base_url: str, session: requests.Session) -> bool:
    """Check if server returns 200 for random nonexistent paths."""
    try:
        r = session.get(f"{base_url}/zz_recon_test_xq9k2", timeout=4,
                        verify=False, allow_redirects=False)
        return r.status_code == 200
    except Exception:
        return False


def scan(target: str) -> list[dict]:
    findings = []
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 ReconCLI/1.0"

    base_urls = [f"https://{target}", f"http://{target}"]
    seen = set()

    # Detect catch-all servers upfront — skip path scanning if true
    catchall_bases = set()
    for base in base_urls:
        if _is_catchall(base, session):
            catchall_bases.add(base)

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = []
        for base in base_urls:
            if base in catchall_bases:
                continue  # Skip — server returns 200 for everything
            for path, severity, label, validator in PATHS:
                futures.append(ex.submit(_check, base, path, label, severity, validator, session))

        for fut in as_completed(futures):
            result = fut.result()
            if result:
                path, severity, label, full_url, code = result
                if path not in seen:
                    seen.add(path)
                    findings.append({
                        "category": "path",
                        "severity": severity,
                        "title": label,
                        "detail": f"Confirmed at: {full_url}",
                        "remediation": _remediation(path),
                    })

    if catchall_bases and not findings:
        findings.append({
            "category": "path",
            "severity": "info",
            "title": "Path scanning skipped — catch-all server detected",
            "detail": "Server returns HTTP 200 for all URLs. Path results would be false positives.",
            "remediation": None,
        })
    elif not findings:
        findings.append({
            "category": "path",
            "severity": "info",
            "title": "No sensitive paths found",
            "detail": f"None of {len(PATHS)} checked paths returned confirmed content.",
            "remediation": None,
        })

    return findings


def _remediation(path: str) -> str:
    if ".git" in path:
        return "Block access to .git directory via web server config. Never deploy with .git exposed."
    if ".env" in path:
        return "Remove .env files from the webroot or block access via server config."
    if "phpmyadmin" in path.lower():
        return "Restrict phpMyAdmin to internal networks or specific IPs only."
    if "admin" in path.lower():
        return "Restrict admin interfaces to authenticated users and known IP ranges."
    if "backup" in path.lower() or ".sql" in path or ".zip" in path:
        return "Move backup files outside the webroot immediately."
    if "actuator" in path:
        return "Secure or disable Spring Boot actuator endpoints in production."
    if "swagger" in path.lower() or "openapi" in path.lower():
        return "Restrict API documentation to internal networks in production."
    return "Restrict or remove access to this resource from public internet."
