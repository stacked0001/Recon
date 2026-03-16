#!/usr/bin/env python3
"""
reconx — Fast security reconnaissance tool
Usage:
  python -m reconx example.com
  python -m reconx example.com --pdf report.pdf
  python -m reconx example.com --json
  python -m reconx example.com --modules port,ssl,headers
"""

import click
import json
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.rule import Rule
from rich import box

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim white",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

GRADE_STYLES = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}

ALL_MODULES = ["port", "ssl", "headers", "dns", "subdomains", "paths", "whois"]

MODULE_LABELS = {
    "port":       "Port Scan",
    "ssl":        "SSL/TLS Check",
    "headers":    "HTTP Headers",
    "dns":        "DNS Enumeration",
    "subdomains": "Subdomain Brute-Force",
    "paths":      "Sensitive Path Discovery",
    "whois":      "WHOIS Lookup",
}


def _strip_scheme(target: str) -> str:
    for prefix in ("https://", "http://", "ftp://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0].strip()


def _run_module(name: str, target: str, progress=None, task_id=None) -> list[dict]:
    from reconx.modules import port_scan, ssl_check, headers, dns_enum, subdomain, sensitive_paths, whois_lookup

    if progress and task_id is not None:
        progress.update(task_id, description=f"  [cyan]{MODULE_LABELS[name]}[/cyan]...")

    runners = {
        "port":       port_scan.scan,
        "ssl":        ssl_check.scan,
        "headers":    headers.scan,
        "dns":        dns_enum.scan,
        "subdomains": subdomain.scan,
        "paths":      sensitive_paths.scan,
        "whois":      whois_lookup.scan,
    }

    try:
        return runners[name](target)
    except Exception as e:
        return [{
            "category": name,
            "severity": "info",
            "title":    f"{MODULE_LABELS[name]} error",
            "detail":   str(e),
            "remediation": None,
        }]


def _print_findings(findings: list[dict], verbose: bool = False):
    from collections import defaultdict
    by_category = defaultdict(list)
    for f in findings:
        by_category[f["category"]].append(f)

    order = ["port", "ssl", "header", "dns", "subdomain", "path", "whois"]
    labels = {
        "port":      "PORT SCAN",
        "ssl":       "SSL/TLS",
        "header":    "HTTP HEADERS",
        "dns":       "DNS",
        "subdomain": "SUBDOMAINS",
        "path":      "SENSITIVE PATHS",
        "whois":     "WHOIS",
    }

    for cat in order:
        cat_findings = by_category.get(cat, [])
        if not cat_findings:
            continue

        console.print()
        console.print(Rule(f"[bold]{labels.get(cat, cat.upper())}[/bold]", style="dim"))

        for f in sorted(cat_findings, key=lambda x: ["critical","high","medium","low","info"].index(x["severity"])):
            sev   = f["severity"]
            color = SEVERITY_COLORS.get(sev, "white")
            icon  = SEVERITY_ICONS.get(sev, "•")

            console.print(f"  {icon} [{color}]{sev.upper():8}[/] {f['title']}")

            if verbose or sev in ("critical", "high"):
                if f.get("detail"):
                    for line in f["detail"].split("\n")[:5]:
                        console.print(f"           [dim]{line}[/]")
                if f.get("remediation"):
                    console.print(f"           [blue]↳ {f['remediation']}[/]")


def _print_score(score: int, grade: str, label: str):
    g_color = GRADE_STYLES.get(grade, "white")
    style_map = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}
    console.print()
    console.print(Panel(
        f"\n  [bold {g_color}]Grade: {grade}   Risk Score: {score}/100   {label}[/bold {g_color}]\n"
        f"  [dim](0 = no risk, 100 = critical — lower is better)[/dim]\n",
        title="[bold]Risk Assessment[/bold]",
        border_style=style_map.get(grade, "white"),
        expand=False,
    ))


@click.command()
@click.argument("target")
@click.option("--modules", "-m", default=",".join(ALL_MODULES),
              help="Comma-separated modules. Options: port,ssl,headers,dns,subdomains,paths,whois")
@click.option("--pdf", "-p", default=None, metavar="FILE", help="Save PDF report to FILE")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output findings as JSON")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show details for all findings")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output")
def cli(target, modules, pdf, output_json, verbose, no_color):
    """
    \b
    reconx — Security reconnaissance tool
    ──────────────────────────────────────
    Scans any domain or IP for security issues.
    Only scan targets you own or have written authorization to test.

    \b
    Examples:
      python -m reconx example.com
      python -m reconx example.com --pdf report.pdf
      python -m reconx example.com --modules port,ssl
      python -m reconx example.com --json > findings.json
    """
    global console
    if no_color:
        console = Console(no_color=True)

    target = _strip_scheme(target)
    selected = [m.strip() for m in modules.split(",") if m.strip() in ALL_MODULES]

    if not selected:
        console.print("[red]No valid modules selected.[/red]")
        sys.exit(1)

    if not output_json:
        console.print()
        console.print(Panel(
            f"[bold cyan]Target:[/bold cyan]  {target}\n"
            f"[bold cyan]Modules:[/bold cyan] {', '.join(MODULE_LABELS.get(m, m) for m in selected)}\n"
            f"[bold cyan]Started:[/bold cyan] {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            title="[bold]reconx[/bold]",
            border_style="cyan",
        ))
        console.print()

    all_findings = []

    if not output_json:
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(bar_width=30),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Starting...", total=len(selected))
            for mod in selected:
                findings = _run_module(mod, target, progress, task)
                all_findings.extend(findings)
                progress.advance(task)
                progress.update(task, description=f"  [green]✓[/green] {MODULE_LABELS[mod]}")
    else:
        for mod in selected:
            all_findings.extend(_run_module(mod, target))

    from reconx.modules.scoring import calculate
    score, grade, label = calculate(all_findings)

    if output_json:
        print(json.dumps({
            "target":     target,
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "score":      score,
            "grade":      grade,
            "risk_label": label,
            "findings":   all_findings,
        }, indent=2))
        return

    _print_findings(all_findings, verbose=verbose)
    _print_score(score, grade, label)

    from collections import Counter
    counts = Counter(f["severity"] for f in all_findings)
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ["critical", "high", "medium", "low", "info"]:
        n = counts.get(sev, 0)
        if n:
            table.add_row(f"[{SEVERITY_COLORS[sev]}]{sev.capitalize()}[/]", str(n))
    console.print()
    console.print(table)

    if pdf:
        try:
            from reconx.modules.pdf_report import generate
            console.print(f"\n[cyan]Generating PDF → {pdf}[/cyan]")
            generate(target, all_findings, score, grade, label, pdf)
            console.print(f"[green]✓ Report saved: {pdf}[/green]")
        except Exception as e:
            console.print(f"[red]PDF generation failed: {e}[/red]")

    console.print()


if __name__ == "__main__":
    cli()
