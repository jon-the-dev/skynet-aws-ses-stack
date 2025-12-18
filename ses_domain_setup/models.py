"""Data models for SES domain setup tool."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(Enum):
    """Status levels for domain verification and DNS records."""

    SUCCESS = "success"
    PENDING = "pending"
    FAILED = "failed"
    MISSING = "missing"
    WARNING = "warning"
    NEEDS_UPDATE = "needs_update"


class Severity(Enum):
    """Severity levels for audit findings."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class RecordAction(Enum):
    """Actions to take on DNS records."""

    CREATE = "create"
    UPDATE = "update"
    SKIP = "skip"


@dataclass
class DNSRecord:
    """Represents a DNS record to create or update."""

    name: str
    record_type: str
    value: str
    ttl: int = 300
    action: RecordAction = RecordAction.CREATE

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "action": self.action.value,
        }


@dataclass
class SPFAuditResult:
    """Result of SPF record audit."""

    exists: bool
    current_value: Optional[str] = None
    has_google: bool = False
    has_ses: bool = False
    status: Status = Status.MISSING
    suggested_value: Optional[str] = None
    message: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "exists": self.exists,
            "current_value": self.current_value,
            "has_google": self.has_google,
            "has_ses": self.has_ses,
            "status": self.status.value,
            "suggested_value": self.suggested_value,
            "message": self.message,
        }


@dataclass
class DMARCAuditResult:
    """Result of DMARC record audit."""

    exists: bool
    current_value: Optional[str] = None
    policy: Optional[str] = None
    status: Status = Status.MISSING
    message: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "exists": self.exists,
            "current_value": self.current_value,
            "policy": self.policy,
            "status": self.status.value,
            "message": self.message,
        }


@dataclass
class MXAuditResult:
    """Result of MX record audit for Gmail compatibility."""

    exists: bool
    has_gmail: bool = False
    mx_records: list[str] = field(default_factory=list)
    status: Status = Status.MISSING
    message: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "exists": self.exists,
            "has_gmail": self.has_gmail,
            "mx_records": self.mx_records,
            "status": self.status.value,
            "message": self.message,
        }


@dataclass
class DKIMStatus:
    """Status of DKIM configuration for a domain."""

    enabled: bool = False
    status: Status = Status.MISSING
    tokens: list[str] = field(default_factory=list)
    cname_records: list[DNSRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "enabled": self.enabled,
            "status": self.status.value,
            "tokens": self.tokens,
            "cname_records": [r.to_dict() for r in self.cname_records],
        }


@dataclass
class DomainStatus:
    """Complete status for a domain's SES and DNS configuration."""

    domain: str
    zone_id: str
    ses_verified: bool = False
    ses_verification_status: Status = Status.MISSING
    ses_verification_token: Optional[str] = None
    dkim: DKIMStatus = field(default_factory=DKIMStatus)
    spf: SPFAuditResult = field(default_factory=lambda: SPFAuditResult(exists=False))
    dmarc: DMARCAuditResult = field(default_factory=lambda: DMARCAuditResult(exists=False))
    mx: MXAuditResult = field(default_factory=lambda: MXAuditResult(exists=False))
    suggested_records: list[DNSRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "zone_id": self.zone_id,
            "ses_verified": self.ses_verified,
            "ses_verification_status": self.ses_verification_status.value,
            "ses_verification_token": self.ses_verification_token,
            "dkim": self.dkim.to_dict(),
            "spf": self.spf.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "mx": self.mx.to_dict(),
            "suggested_records": [r.to_dict() for r in self.suggested_records],
            "errors": self.errors,
        }


@dataclass
class AuditFinding:
    """A single audit finding with severity and recommendation."""

    domain: str
    category: str
    severity: Severity
    message: str
    recommendation: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "category": self.category,
            "severity": self.severity.value,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class SetupReport:
    """Complete report of SES setup across all domains."""

    domains: list[DomainStatus] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "domains": [d.to_dict() for d in self.domains],
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
        }
