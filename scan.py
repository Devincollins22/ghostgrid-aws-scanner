#!/usr/bin/env python3
"""
GhostGrid AWS Scanner - Main CLI
=================================
Run this to scan your AWS environment for security issues.

Usage:
    python scan.py                    # Full scan with AI analysis
    python scan.py --no-ai            # Scan only, skip AI analysis
    python scan.py --scanners iam s3  # Run specific scanners only
    python scan.py --json             # Output raw JSON findings
    python scan.py --output report    # Save report to file

Requires:
    - AWS credentials configured (aws configure)
    - ANTHROPIC_API_KEY env var (for AI analysis)
"""
import sys
import os
import json
import click
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from scanners import ALL_SCANNERS
from scanners.iam_scanner import IAMScanner
from scanners.s3_scanner import S3Scanner
from scanners.ec2_scanner import EC2Scanner
from scanners.sg_scanner import SecurityGroupScanner
from utils.finding import FindingCollection
from config import SEVERITY_ORDER

console = Console()

SCANNER_MAP = {
    "iam": IAMScanner,
    "s3": S3Scanner,
    "ec2": EC2Scanner,
    "sg": SecurityGroupScanner,
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def print_banner():
    banner = """
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗ ██████╗ ██████╗ ██╗██████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝ ██╔══██╗██║██╔══██╗
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██║  ███╗██████╔╝██║██║  ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║   ██║██╔══██╗██║██║  ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚██████╔╝██║  ██║██║██████╔╝
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝
                    AWS Vulnerability Scanner v0.1.0
    """
    console.print(Text(banner, style="bold green"))


def print_findings_table(findings: FindingCollection):
    """Print findings as a nice table."""
    table = Table(
        title="Scan Findings",
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold white",
    )
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Scanner", width=12)
    table.add_column("Resource", width=30)
    table.add_column("Finding", width=60)

    # Sort by severity
    sorted_findings = sorted(
        findings.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
    )

    for f in sorted_findings:
        severity_style = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            Text(f.severity, style=severity_style),
            f.scanner,
            f.resource_id[:28] + ".." if len(f.resource_id) > 30 else f.resource_id,
            f.title,
        )

    console.print(table)


def print_summary(findings: FindingCollection):
    """Print a summary panel."""
    summary = findings.summary()
    text = Text()
    text.append(f"Total: {summary['total']}  ", style="bold")
    text.append(f"Critical: {summary['critical']}  ", style="bold red")
    text.append(f"High: {summary['high']}  ", style="red")
    text.append(f"Medium: {summary['medium']}  ", style="yellow")
    text.append(f"Low: {summary['low']}  ", style="cyan")
    text.append(f"Info: {summary['info']}", style="dim")
    console.print(Panel(text, title="Summary", border_style="green"))


@click.command()
@click.option("--region", default="us-east-2", help="AWS region to scan")
@click.option("--scanners", multiple=True, help="Specific scanners to run (iam, s3, ec2, sg)")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis")
@click.option("--json-output", "use_json", is_flag=True, help="Output raw JSON")
@click.option("--output", "output_file", help="Save report to file")
def main(region, scanners, no_ai, use_json, output_file):
    """GhostGrid AWS Vulnerability Scanner"""

    if not use_json:
        print_banner()
        console.print(f"[dim]Region: {region} | Time: {datetime.utcnow().isoformat()}Z[/dim]\n")

    # Decide which scanners to run
    if scanners:
        scanner_classes = []
        for s in scanners:
            if s in SCANNER_MAP:
                scanner_classes.append(SCANNER_MAP[s])
            else:
                console.print(f"[red]Unknown scanner: {s}. Options: {', '.join(SCANNER_MAP.keys())}[/red]")
                sys.exit(1)
    else:
        scanner_classes = ALL_SCANNERS

    # Run scans
    all_findings = FindingCollection()

    for scanner_cls in scanner_classes:
        scanner = scanner_cls(region=region)
        if not use_json:
            console.print(f"[bold cyan]▶ Running {scanner.name} scanner...[/bold cyan]")

        try:
            results = scanner.scan()
            for finding in results.findings:
                all_findings.add(finding)
            if not use_json:
                console.print(f"  [green]✓ Found {len(results.findings)} issues[/green]\n")
        except Exception as e:
            if not use_json:
                console.print(f"  [red]✗ Scanner failed: {e}[/red]\n")

    # Output results
    if use_json:
        print(all_findings.to_json())
        return

    if not all_findings.findings:
        console.print(Panel(
            "[bold green]No security issues found! Your AWS environment looks solid.[/bold green]",
            title="All Clear",
            border_style="green",
        ))
        return

    print_findings_table(all_findings)
    print_summary(all_findings)

    # AI Analysis
    if not no_ai:
        console.print("\n[bold magenta]▶ Running AI analysis...[/bold magenta]")
        try:
            from ai.analyzer import AIAnalyzer
            analyzer = AIAnalyzer()
            report = analyzer.analyze_findings(all_findings)
            console.print(Panel(report, title="GhostGrid AI Analysis", border_style="magenta"))

            # Save report if requested
            if output_file:
                full_report = f"# GhostGrid Security Assessment\n"
                full_report += f"**Date:** {datetime.utcnow().isoformat()}Z\n"
                full_report += f"**Region:** {region}\n\n"
                full_report += report
                full_report += f"\n\n---\n\n## Raw Findings\n\n```json\n{all_findings.to_json()}\n```"

                with open(output_file, "w") as f:
                    f.write(full_report)
                console.print(f"\n[green]Report saved to {output_file}[/green]")

        except ValueError as e:
            console.print(f"\n[yellow]Skipping AI analysis: {e}[/yellow]")
            console.print("[dim]Set ANTHROPIC_API_KEY to enable AI-powered risk assessment[/dim]")
    elif output_file:
        # Save without AI
        with open(output_file, "w") as f:
            f.write(all_findings.to_json())
        console.print(f"\n[green]Findings saved to {output_file}[/green]")


if __name__ == "__main__":
    main()
