"""AWS operations for Route53 and SES."""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import boto3
from botocore.exceptions import ClientError

from .models import DKIMStatus, DNSRecord, DomainStatus, RecordAction, Status


class AWSOperationError(Exception):
    """Custom exception for AWS operation failures."""

    pass


def retry_with_backoff(
    func: Callable[[], Any],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> Any:
    """
    Execute a function with exponential backoff retry logic.

    Args:
        func: The function to execute
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds

    Returns:
        The result of the function call

    Raises:
        AWSOperationError: If all retries are exhausted
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return func()
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")

            # Retry on throttling errors
            if error_code in ("Throttling", "RequestLimitExceeded", "TooManyRequestsException"):
                last_exception = e
                if attempt < max_retries:
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    time.sleep(delay)
                    continue

            # Don't retry on other errors
            raise AWSOperationError(f"AWS operation failed: {e}") from e

    raise AWSOperationError(
        f"Operation failed after {max_retries} retries: {last_exception}"
    ) from last_exception


class Route53Client:
    """Client for Route53 operations."""

    def __init__(self, session: Optional[boto3.Session] = None):
        """
        Initialize Route53 client.

        Args:
            session: Optional boto3 session. Creates default if not provided.
        """
        self._session = session or boto3.Session()
        self._client = self._session.client("route53")

    def list_hosted_zones(self) -> list[dict]:
        """
        List all Route53 hosted zones.

        Returns:
            List of hosted zone dictionaries with Id, Name, and Config
        """
        zones = []
        paginator = self._client.get_paginator("list_hosted_zones")

        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                # Skip private hosted zones
                if not zone.get("Config", {}).get("PrivateZone", False):
                    zones.append({
                        "Id": zone["Id"].replace("/hostedzone/", ""),
                        "Name": zone["Name"].rstrip("."),
                        "Config": zone.get("Config", {}),
                    })

        return zones

    def get_domain_records(self, zone_id: str, domain: str) -> list[dict]:
        """
        Get all DNS records for a domain in a hosted zone.

        Args:
            zone_id: The Route53 hosted zone ID
            domain: The domain name

        Returns:
            List of resource record sets
        """
        records = []
        paginator = self._client.get_paginator("list_resource_record_sets")

        for page in paginator.paginate(HostedZoneId=zone_id):
            for record in page.get("ResourceRecordSets", []):
                # Include records for the domain or its subdomains
                record_name = record["Name"].rstrip(".")
                if record_name == domain or record_name.endswith(f".{domain}"):
                    records.append(record)

        return records

    def get_record(
        self, zone_id: str, record_name: str, record_type: str
    ) -> Optional[dict]:
        """
        Get a specific DNS record.

        Args:
            zone_id: The Route53 hosted zone ID
            record_name: The record name (e.g., "example.com")
            record_type: The record type (e.g., "TXT", "CNAME")

        Returns:
            The record dictionary or None if not found
        """
        try:
            # Ensure record_name ends with a dot for Route53
            if not record_name.endswith("."):
                record_name = f"{record_name}."

            response = self._client.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=record_name,
                StartRecordType=record_type,
                MaxItems="1",
            )

            for record in response.get("ResourceRecordSets", []):
                if record["Name"] == record_name and record["Type"] == record_type:
                    return record

            return None
        except ClientError:
            return None

    def create_record(
        self,
        zone_id: str,
        record: DNSRecord,
        dry_run: bool = False,
    ) -> bool:
        """
        Create or update a DNS record.

        Args:
            zone_id: The Route53 hosted zone ID
            record: The DNSRecord to create
            dry_run: If True, don't actually create the record

        Returns:
            True if successful (or would be successful in dry run)
        """
        if dry_run:
            return True

        # Ensure record name ends with a dot
        record_name = record.name if record.name.endswith(".") else f"{record.name}."

        change_batch = {
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": record.record_type,
                        "TTL": record.ttl,
                        "ResourceRecords": [{"Value": record.value}],
                    },
                }
            ]
        }

        def _create():
            return self._client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch=change_batch,
            )

        retry_with_backoff(_create)
        return True

    def backup_records(
        self,
        zone_id: str,
        domain: str,
        backup_dir: Path = Path("backups"),
    ) -> Path:
        """
        Backup existing DNS records to a JSON file.

        Args:
            zone_id: The Route53 hosted zone ID
            domain: The domain name
            backup_dir: Directory to store backups

        Returns:
            Path to the backup file
        """
        backup_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"{domain}_{timestamp}.json"

        records = self.get_domain_records(zone_id, domain)

        backup_data = {
            "domain": domain,
            "zone_id": zone_id,
            "timestamp": timestamp,
            "records": records,
        }

        with open(backup_file, "w") as f:
            json.dump(backup_data, f, indent=2, default=str)

        return backup_file


class SESClient:
    """Client for SES operations."""

    def __init__(
        self,
        region: str = "us-east-1",
        session: Optional[boto3.Session] = None,
    ):
        """
        Initialize SES client.

        Args:
            region: AWS region for SES
            session: Optional boto3 session. Creates default if not provided.
        """
        self._session = session or boto3.Session()
        self._client = self._session.client("ses", region_name=region)
        self._region = region

    def get_verification_status(self, domain: str) -> tuple[Status, Optional[str]]:
        """
        Get the SES verification status for a domain.

        Args:
            domain: The domain to check

        Returns:
            Tuple of (Status, verification_token)
        """
        try:
            response = self._client.get_identity_verification_attributes(
                Identities=[domain]
            )

            attrs = response.get("VerificationAttributes", {}).get(domain, {})

            if not attrs:
                return Status.MISSING, None

            status_str = attrs.get("VerificationStatus", "").lower()
            token = attrs.get("VerificationToken")

            status_map = {
                "success": Status.SUCCESS,
                "pending": Status.PENDING,
                "failed": Status.FAILED,
                "temporaryfailure": Status.PENDING,
                "notstarted": Status.MISSING,
            }

            return status_map.get(status_str, Status.MISSING), token

        except ClientError as e:
            raise AWSOperationError(f"Failed to get verification status: {e}") from e

    def verify_domain(self, domain: str) -> str:
        """
        Initiate domain verification in SES.

        Args:
            domain: The domain to verify

        Returns:
            The verification token to add as a TXT record
        """
        try:
            response = self._client.verify_domain_identity(Domain=domain)
            return response["VerificationToken"]
        except ClientError as e:
            raise AWSOperationError(f"Failed to verify domain: {e}") from e

    def get_dkim_attributes(self, domain: str) -> DKIMStatus:
        """
        Get DKIM attributes for a domain.

        Args:
            domain: The domain to check

        Returns:
            DKIMStatus with tokens and status
        """
        try:
            response = self._client.get_identity_dkim_attributes(
                Identities=[domain]
            )

            attrs = response.get("DkimAttributes", {}).get(domain, {})

            if not attrs:
                return DKIMStatus(enabled=False, status=Status.MISSING)

            enabled = attrs.get("DkimEnabled", False)
            tokens = attrs.get("DkimTokens", [])
            verification_status = attrs.get("DkimVerificationStatus", "").lower()

            status_map = {
                "success": Status.SUCCESS,
                "pending": Status.PENDING,
                "failed": Status.FAILED,
                "temporaryfailure": Status.PENDING,
                "notstarted": Status.MISSING,
            }

            status = status_map.get(verification_status, Status.MISSING)

            # Generate CNAME records for DKIM tokens
            cname_records = []
            for token in tokens:
                cname_records.append(
                    DNSRecord(
                        name=f"{token}._domainkey.{domain}",
                        record_type="CNAME",
                        value=f"{token}.dkim.amazonses.com",
                        action=RecordAction.CREATE,
                    )
                )

            return DKIMStatus(
                enabled=enabled,
                status=status,
                tokens=tokens,
                cname_records=cname_records,
            )

        except ClientError as e:
            raise AWSOperationError(f"Failed to get DKIM attributes: {e}") from e

    def enable_dkim(self, domain: str) -> list[str]:
        """
        Enable DKIM for a domain and return the tokens.

        Args:
            domain: The domain to enable DKIM for

        Returns:
            List of DKIM tokens for CNAME records
        """
        try:
            response = self._client.verify_domain_dkim(Domain=domain)
            return response.get("DkimTokens", [])
        except ClientError as e:
            raise AWSOperationError(f"Failed to enable DKIM: {e}") from e


def process_domain(
    domain: str,
    zone_id: str,
    route53: Route53Client,
    ses: SESClient,
    dry_run: bool = False,
    verify_only: bool = False,
) -> DomainStatus:
    """
    Process a single domain for SES setup.

    Args:
        domain: The domain name
        zone_id: The Route53 hosted zone ID
        route53: Route53Client instance
        ses: SESClient instance
        dry_run: If True, don't make any changes
        verify_only: If True, only check verification status

    Returns:
        DomainStatus with current state and suggested changes
    """
    status = DomainStatus(domain=domain, zone_id=zone_id)

    try:
        # Check SES verification status
        ses_status, token = ses.get_verification_status(domain)
        status.ses_verification_status = ses_status
        status.ses_verified = ses_status == Status.SUCCESS
        status.ses_verification_token = token

        # If not verified and not verify_only, initiate verification or ensure TXT record
        if ses_status == Status.MISSING and not verify_only:
            token = ses.verify_domain(domain)
            status.ses_verification_token = token
            status.ses_verification_status = Status.PENDING

        # If pending or just initiated, check if TXT record exists and suggest if missing
        if status.ses_verification_status == Status.PENDING and token and not verify_only:
            # Check if TXT record exists
            existing_txt = route53.get_record(
                zone_id, f"_amazonses.{domain}", "TXT"
            )
            if not existing_txt:
                txt_record = DNSRecord(
                    name=f"_amazonses.{domain}",
                    record_type="TXT",
                    value=f'"{token}"',
                    action=RecordAction.CREATE,
                )
                status.suggested_records.append(txt_record)

        # Get DKIM status
        dkim_status = ses.get_dkim_attributes(domain)

        # If DKIM not enabled and not verify_only, enable it
        if dkim_status.status == Status.MISSING and not verify_only:
            tokens = ses.enable_dkim(domain)
            dkim_status.tokens = tokens
            dkim_status.status = Status.PENDING

        # If DKIM pending, check if CNAME records exist and suggest missing ones
        if dkim_status.status == Status.PENDING and dkim_status.tokens and not verify_only:
            for dkim_token in dkim_status.tokens:
                existing_cname = route53.get_record(
                    zone_id, f"{dkim_token}._domainkey.{domain}", "CNAME"
                )
                if not existing_cname:
                    cname_record = DNSRecord(
                        name=f"{dkim_token}._domainkey.{domain}",
                        record_type="CNAME",
                        value=f"{dkim_token}.dkim.amazonses.com",
                        action=RecordAction.CREATE,
                    )
                    status.suggested_records.append(cname_record)
                    dkim_status.cname_records.append(cname_record)

        status.dkim = dkim_status

    except AWSOperationError as e:
        status.errors.append(str(e))

    return status
