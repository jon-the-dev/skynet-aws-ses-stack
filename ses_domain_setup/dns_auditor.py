"""DNS auditing for SPF and DMARC records with Gmail and SES support."""

import re
from typing import Optional

from .models import (
    AuditFinding,
    DMARCAuditResult,
    DNSRecord,
    DomainStatus,
    MXAuditResult,
    RecordAction,
    Severity,
    SPFAuditResult,
    Status,
)


# SPF include patterns
GOOGLE_SPF_INCLUDE = "include:_spf.google.com"
SES_SPF_INCLUDE = "include:amazonses.com"

# SPF qualifier patterns
SPF_ALL_PATTERNS = [
    (r"\s*~all\s*$", "~all"),  # Soft fail
    (r"\s*-all\s*$", "-all"),  # Hard fail
    (r"\s*\+all\s*$", "+all"),  # Pass (dangerous)
    (r"\s*\?all\s*$", "?all"),  # Neutral
]

# Gmail/Google Workspace MX records (standard SMTP servers)
# These are the expected MX records for Google Workspace
GMAIL_MX_SERVERS = [
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
    "alt2.aspmx.l.google.com",
    "alt3.aspmx.l.google.com",
    "alt4.aspmx.l.google.com",
]


def parse_spf_record(value: str) -> dict:
    """
    Parse an SPF record into its components.

    Args:
        value: The SPF record value

    Returns:
        Dictionary with includes, mechanisms, and qualifier
    """
    result = {
        "includes": [],
        "mechanisms": [],
        "qualifier": None,
        "raw": value,
    }

    # Clean up the value
    value = value.strip().strip('"')

    # Check if it's an SPF record
    if not value.startswith("v=spf1"):
        return result

    # Extract includes
    include_pattern = r"include:([^\s]+)"
    for match in re.finditer(include_pattern, value):
        result["includes"].append(match.group(1))

    # Extract the qualifier (all mechanism)
    for pattern, qualifier in SPF_ALL_PATTERNS:
        if re.search(pattern, value):
            result["qualifier"] = qualifier
            break

    # Extract other mechanisms
    mechanism_pattern = r"(?:^|\s)((?:ip4|ip6|a|mx|ptr):[^\s]+)"
    for match in re.finditer(mechanism_pattern, value):
        result["mechanisms"].append(match.group(1))

    return result


def audit_spf_record(records: list[dict], domain: str) -> SPFAuditResult:
    """
    Audit SPF records for a domain.

    Checks for:
    - Existence of SPF record
    - Google Workspace include (required for Gmail)
    - Amazon SES include (required for SES sending)

    Args:
        records: List of DNS records from Route53
        domain: The domain name

    Returns:
        SPFAuditResult with current state and suggestions
    """
    # Find SPF record (TXT record starting with v=spf1)
    spf_value = None
    for record in records:
        if record.get("Type") != "TXT":
            continue

        record_name = record.get("Name", "").rstrip(".")
        if record_name != domain:
            continue

        for rr in record.get("ResourceRecords", []):
            value = rr.get("Value", "").strip('"')
            if value.startswith("v=spf1"):
                spf_value = value
                break

    if not spf_value:
        # No SPF record exists - suggest creating one with both Google and SES
        suggested = f"v=spf1 {GOOGLE_SPF_INCLUDE} {SES_SPF_INCLUDE} ~all"
        return SPFAuditResult(
            exists=False,
            status=Status.MISSING,
            suggested_value=suggested,
            message="No SPF record found. Suggested record includes Gmail and SES.",
        )

    # Parse the SPF record
    parsed = parse_spf_record(spf_value)

    has_google = any("_spf.google.com" in inc for inc in parsed["includes"])
    has_ses = any("amazonses.com" in inc for inc in parsed["includes"])

    # Determine status and suggestion
    if has_google and has_ses:
        return SPFAuditResult(
            exists=True,
            current_value=spf_value,
            has_google=True,
            has_ses=True,
            status=Status.SUCCESS,
            message="SPF record includes both Gmail and SES.",
        )

    # Build suggestion - preserve existing record but add missing includes
    suggested = suggest_spf_update(spf_value, add_google=not has_google, add_ses=not has_ses)

    if not has_google and not has_ses:
        return SPFAuditResult(
            exists=True,
            current_value=spf_value,
            has_google=False,
            has_ses=False,
            status=Status.NEEDS_UPDATE,
            suggested_value=suggested,
            message="SPF record missing both Gmail and SES includes.",
        )

    if not has_google:
        return SPFAuditResult(
            exists=True,
            current_value=spf_value,
            has_google=False,
            has_ses=True,
            status=Status.WARNING,
            suggested_value=suggested,
            message="SPF record missing Gmail include. Required for Google Workspace.",
        )

    # Has Google but not SES
    return SPFAuditResult(
        exists=True,
        current_value=spf_value,
        has_google=True,
        has_ses=False,
        status=Status.NEEDS_UPDATE,
        suggested_value=suggested,
        message="SPF record missing SES include. Required for Amazon SES sending.",
    )


def suggest_spf_update(
    existing: str,
    add_google: bool = False,
    add_ses: bool = True,
) -> str:
    """
    Generate an updated SPF record with missing includes.

    Preserves existing includes and mechanisms while adding new ones.
    Never removes existing entries.

    Args:
        existing: The existing SPF record value
        add_google: Whether to add Google Workspace include
        add_ses: Whether to add Amazon SES include

    Returns:
        Updated SPF record value
    """
    existing = existing.strip().strip('"')

    # Start with the base
    if not existing.startswith("v=spf1"):
        existing = f"v=spf1 {existing}"

    # Find the qualifier
    qualifier = "~all"  # Default to soft fail
    for pattern, qual in SPF_ALL_PATTERNS:
        if re.search(pattern, existing):
            qualifier = qual
            existing = re.sub(pattern, "", existing)
            break

    # Add missing includes before the qualifier
    includes_to_add = []

    if add_google and GOOGLE_SPF_INCLUDE not in existing:
        includes_to_add.append(GOOGLE_SPF_INCLUDE)

    if add_ses and SES_SPF_INCLUDE not in existing:
        includes_to_add.append(SES_SPF_INCLUDE)

    if includes_to_add:
        existing = f"{existing.strip()} {' '.join(includes_to_add)}"

    # Add qualifier back
    result = f"{existing.strip()} {qualifier}"

    return result


def audit_dmarc_record(records: list[dict], domain: str) -> DMARCAuditResult:
    """
    Audit DMARC record for a domain.

    Checks for:
    - Existence of _dmarc.{domain} TXT record
    - DMARC policy (p=none is warned as non-enforcing)

    Args:
        records: List of DNS records from Route53
        domain: The domain name

    Returns:
        DMARCAuditResult with current state
    """
    dmarc_name = f"_dmarc.{domain}"

    # Find DMARC record
    dmarc_value = None
    for record in records:
        if record.get("Type") != "TXT":
            continue

        record_name = record.get("Name", "").rstrip(".")
        if record_name != dmarc_name:
            continue

        for rr in record.get("ResourceRecords", []):
            value = rr.get("Value", "").strip('"')
            if value.startswith("v=DMARC1"):
                dmarc_value = value
                break

    if not dmarc_value:
        return DMARCAuditResult(
            exists=False,
            status=Status.MISSING,
            message=f"No DMARC record found at {dmarc_name}. Email authentication is incomplete.",
        )

    # Parse the policy
    policy = None
    policy_match = re.search(r"p=(none|quarantine|reject)", dmarc_value, re.IGNORECASE)
    if policy_match:
        policy = policy_match.group(1).lower()

    # Determine status based on policy
    if policy == "none":
        return DMARCAuditResult(
            exists=True,
            current_value=dmarc_value,
            policy=policy,
            status=Status.WARNING,
            message="DMARC policy is 'none' (monitoring only). "
                    "Consider upgrading to 'quarantine' or 'reject'.",
        )

    if policy in ("quarantine", "reject"):
        return DMARCAuditResult(
            exists=True,
            current_value=dmarc_value,
            policy=policy,
            status=Status.SUCCESS,
            message=f"DMARC policy is '{policy}' (enforcing).",
        )

    # Policy not recognized or missing
    return DMARCAuditResult(
        exists=True,
        current_value=dmarc_value,
        policy=policy,
        status=Status.WARNING,
        message="DMARC record found but policy could not be parsed.",
    )


def audit_mx_record(records: list[dict], domain: str) -> MXAuditResult:
    """
    Audit MX records for Gmail/Google Workspace SMTP servers.

    Checks for:
    - Existence of MX records
    - Presence of Gmail/Google Workspace MX servers

    Args:
        records: List of DNS records from Route53
        domain: The domain name

    Returns:
        MXAuditResult with current state
    """
    # Find MX records for the domain
    mx_values = []
    for record in records:
        if record.get("Type") != "MX":
            continue

        record_name = record.get("Name", "").rstrip(".")
        if record_name != domain:
            continue

        for rr in record.get("ResourceRecords", []):
            # MX record format: "priority server"
            value = rr.get("Value", "").strip()
            if value:
                # Extract server name (remove priority number)
                parts = value.split()
                if len(parts) >= 2:
                    server = parts[1].rstrip(".").lower()
                    mx_values.append(server)
                elif len(parts) == 1:
                    # Handle case where only server is present
                    mx_values.append(parts[0].rstrip(".").lower())

    if not mx_values:
        return MXAuditResult(
            exists=False,
            status=Status.MISSING,
            message="No MX records found. Email delivery will not work.",
        )

    # Check for Gmail MX servers
    gmail_servers_found = []
    for mx in mx_values:
        for gmail_mx in GMAIL_MX_SERVERS:
            if gmail_mx.lower() in mx or mx in gmail_mx.lower():
                gmail_servers_found.append(mx)
                break

    has_gmail = len(gmail_servers_found) > 0

    if has_gmail:
        # Check if all primary Gmail MX servers are present
        primary_gmail = "aspmx.l.google.com"
        has_primary = any(primary_gmail in mx for mx in mx_values)

        if has_primary and len(gmail_servers_found) >= 2:
            return MXAuditResult(
                exists=True,
                has_gmail=True,
                mx_records=mx_values,
                status=Status.SUCCESS,
                message=f"Gmail MX records configured ({len(gmail_servers_found)} servers).",
            )
        else:
            return MXAuditResult(
                exists=True,
                has_gmail=True,
                mx_records=mx_values,
                status=Status.WARNING,
                message="Gmail MX records found but may be incomplete.",
            )

    # MX records exist but not Gmail
    return MXAuditResult(
        exists=True,
        has_gmail=False,
        mx_records=mx_values,
        status=Status.SUCCESS,
        message=f"MX records found ({len(mx_values)} servers), not using Gmail.",
    )


def audit_domain_dns(
    domain_status: DomainStatus,
    records: list[dict],
) -> tuple[DomainStatus, list[AuditFinding]]:
    """
    Perform complete DNS audit for a domain.

    Args:
        domain_status: The DomainStatus to update
        records: List of DNS records from Route53

    Returns:
        Tuple of (updated DomainStatus, list of findings)
    """
    findings = []
    domain = domain_status.domain

    # Audit SPF
    spf_result = audit_spf_record(records, domain)
    domain_status.spf = spf_result

    if spf_result.status == Status.MISSING:
        findings.append(AuditFinding(
            domain=domain,
            category="SPF",
            severity=Severity.ERROR,
            message="No SPF record found.",
            recommendation=f"Add TXT record: {spf_result.suggested_value}",
        ))

        # Add suggested record
        domain_status.suggested_records.append(DNSRecord(
            name=domain,
            record_type="TXT",
            value=f'"{spf_result.suggested_value}"',
            action=RecordAction.CREATE,
        ))

    elif spf_result.status == Status.NEEDS_UPDATE:
        findings.append(AuditFinding(
            domain=domain,
            category="SPF",
            severity=Severity.WARNING,
            message=spf_result.message,
            recommendation=f"Update SPF to: {spf_result.suggested_value}",
        ))

        # Add suggested record for update
        domain_status.suggested_records.append(DNSRecord(
            name=domain,
            record_type="TXT",
            value=f'"{spf_result.suggested_value}"',
            action=RecordAction.UPDATE,
        ))

    elif spf_result.status == Status.WARNING:
        findings.append(AuditFinding(
            domain=domain,
            category="SPF",
            severity=Severity.WARNING,
            message=spf_result.message,
            recommendation=f"Update SPF to: {spf_result.suggested_value}",
        ))

    # Audit DMARC
    dmarc_result = audit_dmarc_record(records, domain)
    domain_status.dmarc = dmarc_result

    if dmarc_result.status == Status.MISSING:
        findings.append(AuditFinding(
            domain=domain,
            category="DMARC",
            severity=Severity.ERROR,
            message="No DMARC record found.",
            recommendation=f"Add TXT record at _dmarc.{domain}",
        ))

    elif dmarc_result.status == Status.WARNING:
        findings.append(AuditFinding(
            domain=domain,
            category="DMARC",
            severity=Severity.WARNING,
            message=dmarc_result.message,
            recommendation="Consider upgrading to p=quarantine or p=reject",
        ))

    # Audit MX records
    mx_result = audit_mx_record(records, domain)
    domain_status.mx = mx_result

    if mx_result.status == Status.MISSING:
        findings.append(AuditFinding(
            domain=domain,
            category="MX",
            severity=Severity.ERROR,
            message="No MX records found.",
            recommendation="Add MX records for email delivery.",
        ))

    elif mx_result.status == Status.WARNING:
        findings.append(AuditFinding(
            domain=domain,
            category="MX",
            severity=Severity.WARNING,
            message=mx_result.message,
            recommendation="Review MX record configuration.",
        ))

    return domain_status, findings


def generate_suggested_dmarc(domain: str, email: Optional[str] = None) -> str:
    """
    Generate a suggested DMARC record.

    Args:
        domain: The domain name
        email: Optional email for aggregate reports

    Returns:
        Suggested DMARC record value
    """
    if email:
        return f"v=DMARC1; p=quarantine; rua=mailto:{email}; ruf=mailto:{email}; pct=100"
    else:
        return f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; pct=100"
