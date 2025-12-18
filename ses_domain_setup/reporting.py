"""Reporting and output formatting using Rich."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import (
    AuditFinding,
    DNSRecord,
    DomainStatus,
    Severity,
    SetupReport,
    Status,
)


console = Console()


def status_color(status: Status) -> str:
    """Get the color for a status."""
    color_map = {
        Status.SUCCESS: "green",
        Status.PENDING: "yellow",
        Status.FAILED: "red",
        Status.MISSING: "red",
        Status.WARNING: "yellow",
        Status.NEEDS_UPDATE: "yellow",
    }
    return color_map.get(status, "white")


def status_icon(status: Status) -> str:
    """Get the icon for a status."""
    icon_map = {
        Status.SUCCESS: "[green]✓[/green]",
        Status.PENDING: "[yellow]○[/yellow]",
        Status.FAILED: "[red]✗[/red]",
        Status.MISSING: "[red]✗[/red]",
        Status.WARNING: "[yellow]![/yellow]",
        Status.NEEDS_UPDATE: "[yellow]↑[/yellow]",
    }
    return icon_map.get(status, "?")


def severity_color(severity: Severity) -> str:
    """Get the color for a severity level."""
    color_map = {
        Severity.INFO: "blue",
        Severity.WARNING: "yellow",
        Severity.ERROR: "red",
    }
    return color_map.get(severity, "white")


def create_summary_table(domains: list[DomainStatus]) -> Table:
    """
    Create a summary table of domain statuses.

    Args:
        domains: List of DomainStatus objects

    Returns:
        Rich Table object
    """
    table = Table(title="SES Domain Setup Summary", show_header=True, header_style="bold cyan")

    table.add_column("Domain", style="bold")
    table.add_column("SES Verified", justify="center")
    table.add_column("DKIM", justify="center")
    table.add_column("SPF", justify="center")
    table.add_column("DMARC", justify="center")
    table.add_column("MX", justify="center")

    for domain in domains:
        # SES Verification
        ses_cell = Text()
        ses_cell.append(
            status_icon(domain.ses_verification_status) + " ",
        )
        ses_cell.append(
            domain.ses_verification_status.value,
            style=status_color(domain.ses_verification_status),
        )

        # DKIM
        dkim_cell = Text()
        dkim_cell.append(status_icon(domain.dkim.status) + " ")
        dkim_cell.append(
            domain.dkim.status.value,
            style=status_color(domain.dkim.status),
        )

        # SPF
        spf_cell = Text()
        spf_cell.append(status_icon(domain.spf.status) + " ")

        if domain.spf.status == Status.SUCCESS:
            if domain.spf.has_google and domain.spf.has_ses:
                spf_cell.append("Gmail+SES", style="green")
            elif domain.spf.has_google:
                spf_cell.append("Gmail only", style="yellow")
            elif domain.spf.has_ses:
                spf_cell.append("SES only", style="yellow")
            else:
                spf_cell.append("present", style="green")
        else:
            spf_cell.append(domain.spf.status.value, style=status_color(domain.spf.status))

        # DMARC
        dmarc_cell = Text()
        dmarc_cell.append(status_icon(domain.dmarc.status) + " ")
        if domain.dmarc.exists and domain.dmarc.policy:
            dmarc_cell.append(
                f"p={domain.dmarc.policy}",
                style=status_color(domain.dmarc.status),
            )
        else:
            dmarc_cell.append(
                domain.dmarc.status.value,
                style=status_color(domain.dmarc.status),
            )

        # MX
        mx_cell = Text()
        mx_cell.append(status_icon(domain.mx.status) + " ")
        if domain.mx.exists:
            if domain.mx.has_gmail:
                mx_cell.append("Gmail", style=status_color(domain.mx.status))
            else:
                mx_cell.append(
                    f"{len(domain.mx.mx_records)} records",
                    style=status_color(domain.mx.status),
                )
        else:
            mx_cell.append(
                domain.mx.status.value,
                style=status_color(domain.mx.status),
            )

        table.add_row(
            domain.domain,
            ses_cell,
            dkim_cell,
            spf_cell,
            dmarc_cell,
            mx_cell,
        )

    return table


def create_findings_table(findings: list[AuditFinding]) -> Optional[Table]:
    """
    Create a table of audit findings.

    Args:
        findings: List of AuditFinding objects

    Returns:
        Rich Table object or None if no findings
    """
    if not findings:
        return None

    table = Table(title="Audit Findings", show_header=True, header_style="bold magenta")

    table.add_column("Domain", style="bold")
    table.add_column("Category")
    table.add_column("Severity", justify="center")
    table.add_column("Message")
    table.add_column("Recommendation")

    for finding in findings:
        severity_text = Text(
            finding.severity.value.upper(),
            style=severity_color(finding.severity),
        )

        table.add_row(
            finding.domain,
            finding.category,
            severity_text,
            finding.message,
            finding.recommendation or "-",
        )

    return table


def create_suggested_records_table(records: list[DNSRecord], domain: str) -> Optional[Table]:
    """
    Create a table of suggested DNS records.

    Args:
        records: List of DNSRecord objects
        domain: The domain name

    Returns:
        Rich Table object or None if no records
    """
    if not records:
        return None

    table = Table(
        title=f"Suggested DNS Records for {domain}",
        show_header=True,
        header_style="bold blue",
    )

    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Action", justify="center")

    for record in records:
        action_text = Text(
            record.action.value.upper(),
            style="green" if record.action.value == "create" else "yellow",
        )

        # Truncate long values for display
        value = record.value
        if len(value) > 60:
            value = value[:57] + "..."

        table.add_row(
            record.name,
            record.record_type,
            value,
            action_text,
        )

    return table


def print_domain_details(domain: DomainStatus) -> None:
    """
    Print detailed information for a single domain.

    Args:
        domain: DomainStatus object
    """
    console.print()
    console.print(Panel(f"[bold]{domain.domain}[/bold]", style="cyan"))

    # SES Status
    console.print(f"  SES Verification: {status_icon(domain.ses_verification_status)} ", end="")
    console.print(
        domain.ses_verification_status.value,
        style=status_color(domain.ses_verification_status),
    )

    if domain.ses_verification_token:
        console.print(f"    Token: {domain.ses_verification_token}", style="dim")

    # DKIM Status
    console.print(f"  DKIM: {status_icon(domain.dkim.status)} ", end="")
    console.print(domain.dkim.status.value, style=status_color(domain.dkim.status))

    if domain.dkim.tokens:
        console.print(f"    Tokens: {len(domain.dkim.tokens)} CNAME records", style="dim")

    # SPF Status
    console.print(f"  SPF: {status_icon(domain.spf.status)} ", end="")
    console.print(domain.spf.message, style=status_color(domain.spf.status))

    if domain.spf.current_value:
        console.print(f"    Current: {domain.spf.current_value}", style="dim")
    if domain.spf.suggested_value:
        console.print(f"    Suggested: {domain.spf.suggested_value}", style="yellow")

    # DMARC Status
    console.print(f"  DMARC: {status_icon(domain.dmarc.status)} ", end="")
    console.print(domain.dmarc.message, style=status_color(domain.dmarc.status))

    if domain.dmarc.current_value:
        console.print(f"    Current: {domain.dmarc.current_value}", style="dim")

    # MX Status
    console.print(f"  MX: {status_icon(domain.mx.status)} ", end="")
    console.print(domain.mx.message, style=status_color(domain.mx.status))

    if domain.mx.mx_records:
        console.print(f"    Servers: {', '.join(domain.mx.mx_records[:3])}", style="dim")
        if len(domain.mx.mx_records) > 3:
            console.print(f"    ... and {len(domain.mx.mx_records) - 3} more", style="dim")

    # Errors
    if domain.errors:
        console.print()
        for error in domain.errors:
            console.print(f"  [red]Error: {error}[/red]")


def print_summary(report: SetupReport) -> None:
    """
    Print the complete summary report.

    Args:
        report: SetupReport object
    """
    console.print()

    # Summary table
    table = create_summary_table(report.domains)
    console.print(table)

    # Findings table
    if report.findings:
        console.print()
        findings_table = create_findings_table(report.findings)
        if findings_table:
            console.print(findings_table)

    # Summary statistics
    console.print()
    total = len(report.domains)
    verified = sum(1 for d in report.domains if d.ses_verified)
    dkim_ok = sum(1 for d in report.domains if d.dkim.status == Status.SUCCESS)
    spf_ok = sum(1 for d in report.domains if d.spf.status == Status.SUCCESS)
    dmarc_ok = sum(1 for d in report.domains if d.dmarc.status == Status.SUCCESS)
    mx_ok = sum(1 for d in report.domains if d.mx.status == Status.SUCCESS)
    mx_gmail = sum(1 for d in report.domains if d.mx.has_gmail)

    console.print(Panel(
        f"[bold]Summary:[/bold]\n"
        f"  Total domains: {total}\n"
        f"  SES Verified: [green]{verified}[/green]/{total}\n"
        f"  DKIM OK: [green]{dkim_ok}[/green]/{total}\n"
        f"  SPF OK: [green]{spf_ok}[/green]/{total}\n"
        f"  DMARC OK: [green]{dmarc_ok}[/green]/{total}\n"
        f"  MX OK: [green]{mx_ok}[/green]/{total} "
        f"([cyan]{mx_gmail}[/cyan] using Gmail)",
        title="Statistics",
        style="cyan",
    ))


def print_suggested_fixes(domains: list[DomainStatus]) -> None:
    """
    Print suggested DNS record fixes for all domains.

    Args:
        domains: List of DomainStatus objects with suggested records
    """
    has_suggestions = any(d.suggested_records for d in domains)

    if not has_suggestions:
        console.print()
        console.print("[green]No DNS changes needed.[/green]")
        return

    console.print()
    console.print("[bold yellow]Suggested DNS Changes:[/bold yellow]")

    for domain in domains:
        if not domain.suggested_records:
            continue

        table = create_suggested_records_table(domain.suggested_records, domain.domain)
        if table:
            console.print()
            console.print(table)


def generate_json_report(
    report: SetupReport,
    filename: str = "ses_setup_report.json",
) -> Path:
    """
    Generate a JSON report file.

    Args:
        report: SetupReport object
        filename: Output filename

    Returns:
        Path to the generated file
    """
    output_path = Path(filename)

    report_data = report.to_dict()
    report_data["generated_at"] = datetime.now().isoformat()

    with open(output_path, "w") as f:
        json.dump(report_data, f, indent=2)

    console.print()
    console.print(f"[green]Report saved to: {output_path}[/green]")

    return output_path


def print_dry_run_notice() -> None:
    """Print a notice that this is a dry run."""
    console.print()
    console.print(Panel(
        "[bold yellow]DRY RUN MODE[/bold yellow]\n"
        "No changes will be made. Review the output and run without --dry-run to apply changes.",
        style="yellow",
    ))


def print_backup_notice(backup_path: Path) -> None:
    """Print a notice about backup creation."""
    console.print(f"[dim]Backup created: {backup_path}[/dim]")


def confirm_action(message: str) -> bool:
    """
    Prompt for user confirmation.

    Args:
        message: The confirmation message

    Returns:
        True if user confirmed, False otherwise
    """
    console.print()
    response = console.input(f"[yellow]{message} (y/N): [/yellow]")
    return response.lower() in ("y", "yes")
