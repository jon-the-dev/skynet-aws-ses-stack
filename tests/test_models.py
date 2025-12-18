"""Tests for models.py dataclasses and enums."""

from ses_domain_setup.models import (
    AuditFinding,
    DKIMStatus,
    DMARCAuditResult,
    DNSRecord,
    DomainStatus,
    MXAuditResult,
    RecordAction,
    SetupReport,
    Severity,
    SPFAuditResult,
    Status,
)


class TestStatusEnum:
    """Tests for Status enum."""

    def test_status_values(self):
        """Test all Status enum values exist."""
        assert Status.SUCCESS.value == "success"
        assert Status.PENDING.value == "pending"
        assert Status.FAILED.value == "failed"
        assert Status.MISSING.value == "missing"
        assert Status.WARNING.value == "warning"
        assert Status.NEEDS_UPDATE.value == "needs_update"

    def test_status_count(self):
        """Test expected number of Status values."""
        assert len(Status) == 6


class TestSeverityEnum:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test all Severity enum values exist."""
        assert Severity.INFO.value == "info"
        assert Severity.WARNING.value == "warning"
        assert Severity.ERROR.value == "error"

    def test_severity_count(self):
        """Test expected number of Severity values."""
        assert len(Severity) == 3


class TestRecordActionEnum:
    """Tests for RecordAction enum."""

    def test_record_action_values(self):
        """Test all RecordAction enum values exist."""
        assert RecordAction.CREATE.value == "create"
        assert RecordAction.UPDATE.value == "update"
        assert RecordAction.SKIP.value == "skip"

    def test_record_action_count(self):
        """Test expected number of RecordAction values."""
        assert len(RecordAction) == 3


class TestDNSRecord:
    """Tests for DNSRecord dataclass."""

    def test_create_dns_record(self):
        """Test creating a basic DNS record."""
        record = DNSRecord(
            name="example.com",
            record_type="TXT",
            value='"v=spf1 include:_spf.google.com ~all"',
        )
        assert record.name == "example.com"
        assert record.record_type == "TXT"
        assert record.value == '"v=spf1 include:_spf.google.com ~all"'
        assert record.ttl == 300  # default
        assert record.action == RecordAction.CREATE  # default

    def test_create_dns_record_with_custom_ttl(self):
        """Test creating a DNS record with custom TTL."""
        record = DNSRecord(
            name="example.com",
            record_type="CNAME",
            value="target.example.com",
            ttl=600,
        )
        assert record.ttl == 600

    def test_create_dns_record_with_update_action(self):
        """Test creating a DNS record with UPDATE action."""
        record = DNSRecord(
            name="example.com",
            record_type="TXT",
            value="new value",
            action=RecordAction.UPDATE,
        )
        assert record.action == RecordAction.UPDATE

    def test_dns_record_to_dict(self):
        """Test converting DNS record to dictionary."""
        record = DNSRecord(
            name="_dmarc.example.com",
            record_type="TXT",
            value='"v=DMARC1; p=reject"',
            ttl=3600,
            action=RecordAction.CREATE,
        )
        result = record.to_dict()

        assert result == {
            "name": "_dmarc.example.com",
            "type": "TXT",
            "value": '"v=DMARC1; p=reject"',
            "ttl": 3600,
            "action": "create",
        }


class TestSPFAuditResult:
    """Tests for SPFAuditResult dataclass."""

    def test_create_missing_spf(self):
        """Test creating SPF result for missing record."""
        result = SPFAuditResult(exists=False)
        assert result.exists is False
        assert result.current_value is None
        assert result.has_google is False
        assert result.has_ses is False
        assert result.status == Status.MISSING
        assert result.suggested_value is None
        assert result.message == ""

    def test_create_spf_with_google(self):
        """Test creating SPF result with Google include."""
        result = SPFAuditResult(
            exists=True,
            current_value="v=spf1 include:_spf.google.com ~all",
            has_google=True,
            has_ses=False,
            status=Status.WARNING,
            message="SPF present but missing SES",
        )
        assert result.has_google is True
        assert result.has_ses is False
        assert result.status == Status.WARNING

    def test_create_spf_with_both(self):
        """Test creating SPF result with both Google and SES."""
        result = SPFAuditResult(
            exists=True,
            current_value="v=spf1 include:_spf.google.com include:amazonses.com ~all",
            has_google=True,
            has_ses=True,
            status=Status.SUCCESS,
            message="SPF configured for Gmail and SES",
        )
        assert result.has_google is True
        assert result.has_ses is True
        assert result.status == Status.SUCCESS

    def test_spf_audit_result_to_dict(self):
        """Test converting SPF result to dictionary."""
        result = SPFAuditResult(
            exists=True,
            current_value="v=spf1 ~all",
            has_google=False,
            has_ses=False,
            status=Status.WARNING,
            suggested_value="v=spf1 include:amazonses.com ~all",
            message="Basic SPF, missing providers",
        )
        output = result.to_dict()

        assert output == {
            "exists": True,
            "current_value": "v=spf1 ~all",
            "has_google": False,
            "has_ses": False,
            "status": "warning",
            "suggested_value": "v=spf1 include:amazonses.com ~all",
            "message": "Basic SPF, missing providers",
        }


class TestDMARCAuditResult:
    """Tests for DMARCAuditResult dataclass."""

    def test_create_missing_dmarc(self):
        """Test creating DMARC result for missing record."""
        result = DMARCAuditResult(exists=False)
        assert result.exists is False
        assert result.current_value is None
        assert result.policy is None
        assert result.status == Status.MISSING
        assert result.message == ""

    def test_create_dmarc_with_policy(self):
        """Test creating DMARC result with policy."""
        result = DMARCAuditResult(
            exists=True,
            current_value="v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
            policy="quarantine",
            status=Status.WARNING,
            message="DMARC with quarantine policy",
        )
        assert result.policy == "quarantine"
        assert result.status == Status.WARNING

    def test_create_dmarc_with_reject_policy(self):
        """Test creating DMARC result with reject policy."""
        result = DMARCAuditResult(
            exists=True,
            current_value="v=DMARC1; p=reject",
            policy="reject",
            status=Status.SUCCESS,
            message="DMARC with reject policy",
        )
        assert result.policy == "reject"
        assert result.status == Status.SUCCESS

    def test_dmarc_audit_result_to_dict(self):
        """Test converting DMARC result to dictionary."""
        result = DMARCAuditResult(
            exists=True,
            current_value="v=DMARC1; p=none",
            policy="none",
            status=Status.WARNING,
            message="DMARC with monitoring only",
        )
        output = result.to_dict()

        assert output == {
            "exists": True,
            "current_value": "v=DMARC1; p=none",
            "policy": "none",
            "status": "warning",
            "message": "DMARC with monitoring only",
        }


class TestMXAuditResult:
    """Tests for MXAuditResult dataclass."""

    def test_create_missing_mx(self):
        """Test creating MX result for missing records."""
        result = MXAuditResult(exists=False)
        assert result.exists is False
        assert result.has_gmail is False
        assert result.mx_records == []
        assert result.status == Status.MISSING
        assert result.message == ""

    def test_create_mx_with_gmail(self):
        """Test creating MX result with Gmail records."""
        result = MXAuditResult(
            exists=True,
            has_gmail=True,
            mx_records=[
                "aspmx.l.google.com",
                "alt1.aspmx.l.google.com",
                "alt2.aspmx.l.google.com",
            ],
            status=Status.SUCCESS,
            message="Gmail MX records detected",
        )
        assert result.has_gmail is True
        assert len(result.mx_records) == 3
        assert result.status == Status.SUCCESS

    def test_create_mx_with_other_provider(self):
        """Test creating MX result with non-Gmail provider."""
        result = MXAuditResult(
            exists=True,
            has_gmail=False,
            mx_records=["mail.example.com"],
            status=Status.SUCCESS,
            message="Custom MX records",
        )
        assert result.has_gmail is False
        assert result.mx_records == ["mail.example.com"]

    def test_mx_audit_result_to_dict(self):
        """Test converting MX result to dictionary."""
        result = MXAuditResult(
            exists=True,
            has_gmail=True,
            mx_records=["aspmx.l.google.com"],
            status=Status.SUCCESS,
            message="Gmail configured",
        )
        output = result.to_dict()

        assert output == {
            "exists": True,
            "has_gmail": True,
            "mx_records": ["aspmx.l.google.com"],
            "status": "success",
            "message": "Gmail configured",
        }


class TestDKIMStatus:
    """Tests for DKIMStatus dataclass."""

    def test_create_default_dkim_status(self):
        """Test creating default DKIM status."""
        status = DKIMStatus()
        assert status.enabled is False
        assert status.status == Status.MISSING
        assert status.tokens == []
        assert status.cname_records == []

    def test_create_enabled_dkim_status(self):
        """Test creating enabled DKIM status."""
        cname_record = DNSRecord(
            name="abc123._domainkey.example.com",
            record_type="CNAME",
            value="abc123.dkim.amazonses.com",
        )
        status = DKIMStatus(
            enabled=True,
            status=Status.SUCCESS,
            tokens=["abc123", "def456", "ghi789"],
            cname_records=[cname_record],
        )
        assert status.enabled is True
        assert status.status == Status.SUCCESS
        assert len(status.tokens) == 3
        assert len(status.cname_records) == 1

    def test_dkim_status_to_dict(self):
        """Test converting DKIM status to dictionary."""
        status = DKIMStatus(
            enabled=True,
            status=Status.PENDING,
            tokens=["token1"],
            cname_records=[],
        )
        output = status.to_dict()

        assert output == {
            "enabled": True,
            "status": "pending",
            "tokens": ["token1"],
            "cname_records": [],
        }

    def test_dkim_status_to_dict_with_cname_records(self):
        """Test converting DKIM status with CNAME records to dictionary."""
        cname = DNSRecord(
            name="abc._domainkey.example.com",
            record_type="CNAME",
            value="abc.dkim.amazonses.com",
        )
        status = DKIMStatus(
            enabled=True,
            status=Status.SUCCESS,
            tokens=["abc"],
            cname_records=[cname],
        )
        output = status.to_dict()

        assert len(output["cname_records"]) == 1
        assert output["cname_records"][0]["name"] == "abc._domainkey.example.com"


class TestDomainStatus:
    """Tests for DomainStatus dataclass."""

    def test_create_default_domain_status(self):
        """Test creating default domain status."""
        status = DomainStatus(domain="example.com", zone_id="Z123456")
        assert status.domain == "example.com"
        assert status.zone_id == "Z123456"
        assert status.ses_verified is False
        assert status.ses_verification_status == Status.MISSING
        assert status.ses_verification_token is None
        assert isinstance(status.dkim, DKIMStatus)
        assert isinstance(status.spf, SPFAuditResult)
        assert isinstance(status.dmarc, DMARCAuditResult)
        assert isinstance(status.mx, MXAuditResult)
        assert status.suggested_records == []
        assert status.errors == []

    def test_create_verified_domain_status(self):
        """Test creating verified domain status."""
        status = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verified=True,
            ses_verification_status=Status.SUCCESS,
            ses_verification_token="abc123token",
        )
        assert status.ses_verified is True
        assert status.ses_verification_status == Status.SUCCESS
        assert status.ses_verification_token == "abc123token"

    def test_domain_status_with_suggested_records(self):
        """Test domain status with suggested DNS records."""
        record = DNSRecord(
            name="_amazonses.example.com",
            record_type="TXT",
            value='"verification-token"',
        )
        status = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            suggested_records=[record],
        )
        assert len(status.suggested_records) == 1
        assert status.suggested_records[0].name == "_amazonses.example.com"

    def test_domain_status_with_errors(self):
        """Test domain status with errors."""
        status = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            errors=["Failed to verify domain", "DNS propagation timeout"],
        )
        assert len(status.errors) == 2

    def test_domain_status_to_dict(self):
        """Test converting domain status to dictionary."""
        status = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verified=True,
            ses_verification_status=Status.SUCCESS,
        )
        output = status.to_dict()

        assert output["domain"] == "example.com"
        assert output["zone_id"] == "Z123456"
        assert output["ses_verified"] is True
        assert output["ses_verification_status"] == "success"
        assert "dkim" in output
        assert "spf" in output
        assert "dmarc" in output
        assert "mx" in output
        assert output["suggested_records"] == []
        assert output["errors"] == []


class TestAuditFinding:
    """Tests for AuditFinding dataclass."""

    def test_create_info_finding(self):
        """Test creating an info-level finding."""
        finding = AuditFinding(
            domain="example.com",
            category="SPF",
            severity=Severity.INFO,
            message="SPF record is properly configured",
        )
        assert finding.domain == "example.com"
        assert finding.category == "SPF"
        assert finding.severity == Severity.INFO
        assert finding.message == "SPF record is properly configured"
        assert finding.recommendation is None

    def test_create_warning_finding_with_recommendation(self):
        """Test creating a warning finding with recommendation."""
        finding = AuditFinding(
            domain="example.com",
            category="DMARC",
            severity=Severity.WARNING,
            message="DMARC policy is set to none",
            recommendation="Consider upgrading to quarantine or reject",
        )
        assert finding.severity == Severity.WARNING
        assert finding.recommendation == "Consider upgrading to quarantine or reject"

    def test_create_error_finding(self):
        """Test creating an error finding."""
        finding = AuditFinding(
            domain="example.com",
            category="SPF",
            severity=Severity.ERROR,
            message="SPF record is missing",
            recommendation="Add SPF record immediately",
        )
        assert finding.severity == Severity.ERROR

    def test_audit_finding_to_dict(self):
        """Test converting audit finding to dictionary."""
        finding = AuditFinding(
            domain="example.com",
            category="MX",
            severity=Severity.INFO,
            message="Gmail MX records detected",
            recommendation=None,
        )
        output = finding.to_dict()

        assert output == {
            "domain": "example.com",
            "category": "MX",
            "severity": "info",
            "message": "Gmail MX records detected",
            "recommendation": None,
        }


class TestSetupReport:
    """Tests for SetupReport dataclass."""

    def test_create_empty_report(self):
        """Test creating an empty report."""
        report = SetupReport()
        assert report.domains == []
        assert report.findings == []
        assert report.summary == {}

    def test_create_report_with_domains(self):
        """Test creating a report with domains."""
        domain_status = DomainStatus(domain="example.com", zone_id="Z123456")
        report = SetupReport(
            domains=[domain_status],
            summary={"total": 1, "verified": 0},
        )
        assert len(report.domains) == 1
        assert report.summary["total"] == 1

    def test_create_report_with_findings(self):
        """Test creating a report with findings."""
        finding = AuditFinding(
            domain="example.com",
            category="SPF",
            severity=Severity.WARNING,
            message="Test finding",
        )
        report = SetupReport(findings=[finding])
        assert len(report.findings) == 1

    def test_report_to_dict(self):
        """Test converting report to dictionary."""
        domain_status = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verified=True,
            ses_verification_status=Status.SUCCESS,
        )
        finding = AuditFinding(
            domain="example.com",
            category="DKIM",
            severity=Severity.INFO,
            message="DKIM enabled",
        )
        report = SetupReport(
            domains=[domain_status],
            findings=[finding],
            summary={"total": 1, "verified": 1},
        )
        output = report.to_dict()

        assert len(output["domains"]) == 1
        assert output["domains"][0]["domain"] == "example.com"
        assert len(output["findings"]) == 1
        assert output["findings"][0]["category"] == "DKIM"
        assert output["summary"]["verified"] == 1
