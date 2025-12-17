"""CLI interface for SES domain setup tool."""

import click

from . import __version__
from .aws_operations import (
    AWSOperationError,
    Route53Client,
    SESClient,
    process_domain,
)
from .dns_auditor import audit_domain_dns
from .models import AuditFinding, SetupReport
from .reporting import (
    confirm_action,
    console,
    generate_json_report,
    print_backup_notice,
    print_domain_details,
    print_dry_run_notice,
    print_suggested_fixes,
    print_summary,
)


@click.command()
@click.option(
    "--dry-run",
    is_flag=True,
    help="Preview changes without applying them",
)
@click.option(
    "--domain",
    type=str,
    help="Target a specific domain instead of all",
)
@click.option(
    "--region",
    type=str,
    default="us-east-1",
    help="AWS region for SES (default: us-east-1)",
)
@click.option(
    "--verify-only",
    is_flag=True,
    help="Only check verification status without making changes",
)
@click.option(
    "--audit",
    is_flag=True,
    help="Only audit SPF/DMARC without making SES changes",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation prompts",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed output for each domain",
)
@click.option(
    "--output",
    "-o",
    type=str,
    default="ses_setup_report.json",
    help="Output JSON report filename",
)
@click.version_option(version=__version__)
def main(
    dry_run: bool,
    domain: str | None,
    region: str,
    verify_only: bool,
    audit: bool,
    yes: bool,
    verbose: bool,
    output: str,
) -> None:
    """
    AWS SES Domain Setup Tool.

    Automates SES domain verification and DNS record management for Route 53.
    Audits SPF and DMARC records for Gmail and SES compatibility.
    """
    try:
        _run_setup(
            dry_run=dry_run,
            target_domain=domain,
            region=region,
            verify_only=verify_only,
            audit_only=audit,
            skip_confirm=yes,
            verbose=verbose,
            output_file=output,
        )
    except AWSOperationError as e:
        console.print(f"[red]AWS Error: {e}[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise SystemExit(1)


def _run_setup(
    dry_run: bool,
    target_domain: str | None,
    region: str,
    verify_only: bool,
    audit_only: bool,
    skip_confirm: bool,
    verbose: bool,
    output_file: str,
) -> None:
    """
    Main setup workflow.

    Args:
        dry_run: Preview changes without applying
        target_domain: Specific domain to target (None for all)
        region: AWS region for SES
        verify_only: Only check verification status
        audit_only: Only audit SPF/DMARC
        skip_confirm: Skip confirmation prompts
        verbose: Show detailed output
        output_file: JSON report filename
    """
    if dry_run:
        print_dry_run_notice()

    console.print()
    console.print("[bold cyan]AWS SES Domain Setup Tool[/bold cyan]")
    console.print(f"Region: {region}")
    console.print()

    # Initialize clients
    route53 = Route53Client()
    ses = SESClient(region=region)

    # Get hosted zones
    console.print("[dim]Fetching Route53 hosted zones...[/dim]")
    zones = route53.list_hosted_zones()

    if not zones:
        console.print("[yellow]No public hosted zones found in Route53.[/yellow]")
        return

    console.print(f"[dim]Found {len(zones)} hosted zones[/dim]")

    # Filter to specific domain if provided
    if target_domain:
        zones = [z for z in zones if z["Name"] == target_domain]
        if not zones:
            console.print(f"[red]Domain '{target_domain}' not found in Route53.[/red]")
            return

    # Collect results
    report = SetupReport()
    all_findings: list[AuditFinding] = []

    for zone in zones:
        zone_id = zone["Id"]
        domain_name = zone["Name"]

        console.print()
        console.print(f"[bold]Processing: {domain_name}[/bold]")

        # Backup existing records before making changes
        if not dry_run and not verify_only and not audit_only:
            backup_path = route53.backup_records(zone_id, domain_name)
            print_backup_notice(backup_path)

        # Get current DNS records for auditing
        records = route53.get_domain_records(zone_id, domain_name)

        # Process domain for SES setup
        # In audit mode, we still check SES status but don't make changes (verify_only=True)
        domain_status = process_domain(
            domain=domain_name,
            zone_id=zone_id,
            route53=route53,
            ses=ses,
            dry_run=dry_run,
            verify_only=verify_only or audit_only,
        )

        # Audit DNS records (SPF, DMARC)
        domain_status, findings = audit_domain_dns(domain_status, records)
        all_findings.extend(findings)

        report.domains.append(domain_status)

        if verbose:
            print_domain_details(domain_status)

    report.findings = all_findings

    # Generate summary statistics
    report.summary = {
        "total_domains": len(report.domains),
        "ses_verified": sum(1 for d in report.domains if d.ses_verified),
        "dkim_ok": sum(1 for d in report.domains if d.dkim.status.value == "success"),
        "spf_ok": sum(1 for d in report.domains if d.spf.status.value == "success"),
        "dmarc_ok": sum(1 for d in report.domains if d.dmarc.status.value == "success"),
        "total_findings": len(report.findings),
    }

    # Print summary
    print_summary(report)

    # Print suggested fixes
    print_suggested_fixes(report.domains)

    # Determine if we need to create DNS records
    domains_needing_changes = [d for d in report.domains if d.suggested_records]

    if domains_needing_changes and not verify_only and not dry_run:
        if not skip_confirm:
            if not confirm_action("Do you want to create the suggested DNS records?"):
                console.print("[yellow]Skipping DNS record creation.[/yellow]")
                domains_needing_changes = []

        # Create DNS records
        if domains_needing_changes:
            console.print()
            console.print("[bold]Creating DNS records...[/bold]")

            for domain_status in domains_needing_changes:
                for record in domain_status.suggested_records:
                    try:
                        console.print(
                            f"  Creating {record.record_type} record: {record.name}"
                        )
                        route53.create_record(
                            zone_id=domain_status.zone_id,
                            record=record,
                            dry_run=False,
                        )
                        console.print("    [green]Created successfully[/green]")
                    except AWSOperationError as e:
                        console.print(f"    [red]Failed: {e}[/red]")

    # Generate JSON report
    generate_json_report(report, output_file)

    # Final status
    console.print()
    if dry_run:
        console.print("[yellow]Dry run complete. No changes were made.[/yellow]")
    else:
        console.print("[green]Setup complete![/green]")


if __name__ == "__main__":
    main()
