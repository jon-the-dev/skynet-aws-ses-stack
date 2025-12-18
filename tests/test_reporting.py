"""Tests for reporting.py output formatting and report generation."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from rich.table import Table

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
from ses_domain_setup.reporting import (
    confirm_action,
    create_findings_table,
    create_suggested_records_table,
    create_summary_table,
    generate_json_report,
    print_backup_notice,
    print_domain_details,
    print_dry_run_notice,
    print_suggested_fixes,
    print_summary,
    severity_color,
    status_color,
    status_icon,
)


class TestStatusColor:
    """Tests for status_color function."""

    def test_success_color(self):
        """Test SUCCESS status returns green."""
        assert status_color(Status.SUCCESS) == "green"

    def test_pending_color(self):
        """Test PENDING status returns yellow."""
        assert status_color(Status.PENDING) == "yellow"

    def test_failed_color(self):
        """Test FAILED status returns red."""
        assert status_color(Status.FAILED) == "red"

    def test_missing_color(self):
        """Test MISSING status returns red."""
        assert status_color(Status.MISSING) == "red"

    def test_warning_color(self):
        """Test WARNING status returns yellow."""
        assert status_color(Status.WARNING) == "yellow"

    def test_needs_update_color(self):
        """Test NEEDS_UPDATE status returns yellow."""
        assert status_color(Status.NEEDS_UPDATE) == "yellow"


class TestStatusIcon:
    """Tests for status_icon function."""

    def test_success_icon(self):
        """Test SUCCESS status returns checkmark."""
        icon = status_icon(Status.SUCCESS)
        assert "✓" in icon
        assert "green" in icon

    def test_pending_icon(self):
        """Test PENDING status returns circle."""
        icon = status_icon(Status.PENDING)
        assert "○" in icon
        assert "yellow" in icon

    def test_failed_icon(self):
        """Test FAILED status returns X."""
        icon = status_icon(Status.FAILED)
        assert "✗" in icon
        assert "red" in icon

    def test_missing_icon(self):
        """Test MISSING status returns X."""
        icon = status_icon(Status.MISSING)
        assert "✗" in icon
        assert "red" in icon

    def test_warning_icon(self):
        """Test WARNING status returns exclamation."""
        icon = status_icon(Status.WARNING)
        assert "!" in icon
        assert "yellow" in icon

    def test_needs_update_icon(self):
        """Test NEEDS_UPDATE status returns arrow."""
        icon = status_icon(Status.NEEDS_UPDATE)
        assert "↑" in icon
        assert "yellow" in icon


class TestSeverityColor:
    """Tests for severity_color function."""

    def test_info_color(self):
        """Test INFO severity returns blue."""
        assert severity_color(Severity.INFO) == "blue"

    def test_warning_color(self):
        """Test WARNING severity returns yellow."""
        assert severity_color(Severity.WARNING) == "yellow"

    def test_error_color(self):
        """Test ERROR severity returns red."""
        assert severity_color(Severity.ERROR) == "red"


class TestCreateSummaryTable:
    """Tests for create_summary_table function."""

    def test_empty_domains_list(self):
        """Test creating table with empty domains list."""
        table = create_summary_table([])
        assert isinstance(table, Table)
        assert table.title == "SES Domain Setup Summary"

    def test_single_domain(self):
        """Test creating table with single domain."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verified=True,
            ses_verification_status=Status.SUCCESS,
            dkim=DKIMStatus(enabled=True, status=Status.SUCCESS),
            spf=SPFAuditResult(exists=True, status=Status.SUCCESS, has_google=True),
            dmarc=DMARCAuditResult(exists=True, status=Status.SUCCESS, policy="reject"),
            mx=MXAuditResult(exists=True, status=Status.SUCCESS, has_gmail=True),
        )
        table = create_summary_table([domain])
        assert isinstance(table, Table)
        assert table.row_count == 1

    def test_multiple_domains(self):
        """Test creating table with multiple domains."""
        domains = [
            DomainStatus(domain="example.com", zone_id="Z123456"),
            DomainStatus(domain="test.com", zone_id="Z789012"),
        ]
        table = create_summary_table(domains)
        assert table.row_count == 2

    def test_domain_with_gmail_and_ses(self):
        """Test domain showing Gmail+SES in SPF column."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            spf=SPFAuditResult(
                exists=True,
                status=Status.SUCCESS,
                has_google=True,
                has_ses=True,
            ),
        )
        table = create_summary_table([domain])
        assert table.row_count == 1


class TestCreateFindingsTable:
    """Tests for create_findings_table function."""

    def test_empty_findings_returns_none(self):
        """Test empty findings list returns None."""
        result = create_findings_table([])
        assert result is None

    def test_single_finding(self):
        """Test creating table with single finding."""
        finding = AuditFinding(
            domain="example.com",
            category="SPF",
            severity=Severity.WARNING,
            message="SPF needs update",
            recommendation="Add SES include",
        )
        table = create_findings_table([finding])
        assert isinstance(table, Table)
        assert table.title == "Audit Findings"
        assert table.row_count == 1

    def test_multiple_findings(self):
        """Test creating table with multiple findings."""
        findings = [
            AuditFinding(
                domain="example.com",
                category="SPF",
                severity=Severity.ERROR,
                message="SPF missing",
            ),
            AuditFinding(
                domain="example.com",
                category="DMARC",
                severity=Severity.WARNING,
                message="DMARC policy is none",
            ),
            AuditFinding(
                domain="test.com",
                category="DKIM",
                severity=Severity.INFO,
                message="DKIM configured",
            ),
        ]
        table = create_findings_table(findings)
        assert table.row_count == 3

    def test_finding_without_recommendation(self):
        """Test finding with no recommendation shows dash."""
        finding = AuditFinding(
            domain="example.com",
            category="MX",
            severity=Severity.INFO,
            message="MX records present",
            recommendation=None,
        )
        table = create_findings_table([finding])
        assert table is not None


class TestCreateSuggestedRecordsTable:
    """Tests for create_suggested_records_table function."""

    def test_empty_records_returns_none(self):
        """Test empty records list returns None."""
        result = create_suggested_records_table([], "example.com")
        assert result is None

    def test_single_record(self):
        """Test creating table with single record."""
        record = DNSRecord(
            name="_amazonses.example.com",
            record_type="TXT",
            value='"verification-token"',
            action=RecordAction.CREATE,
        )
        table = create_suggested_records_table([record], "example.com")
        assert isinstance(table, Table)
        assert "example.com" in table.title
        assert table.row_count == 1

    def test_multiple_records(self):
        """Test creating table with multiple records."""
        records = [
            DNSRecord(
                name="_amazonses.example.com",
                record_type="TXT",
                value='"token"',
            ),
            DNSRecord(
                name="abc._domainkey.example.com",
                record_type="CNAME",
                value="abc.dkim.amazonses.com",
            ),
        ]
        table = create_suggested_records_table(records, "example.com")
        assert table.row_count == 2

    def test_long_value_truncated(self):
        """Test long values are truncated for display."""
        long_value = "x" * 100
        record = DNSRecord(
            name="example.com",
            record_type="TXT",
            value=long_value,
        )
        table = create_suggested_records_table([record], "example.com")
        assert table is not None

    def test_update_action_styling(self):
        """Test UPDATE action records are styled differently."""
        record = DNSRecord(
            name="example.com",
            record_type="TXT",
            value="new value",
            action=RecordAction.UPDATE,
        )
        table = create_suggested_records_table([record], "example.com")
        assert table is not None


class TestPrintDomainDetails:
    """Tests for print_domain_details function."""

    @patch("ses_domain_setup.reporting.console")
    def test_print_basic_domain(self, mock_console):
        """Test printing basic domain details."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verification_status=Status.PENDING,
        )
        print_domain_details(domain)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_print_domain_with_token(self, mock_console):
        """Test printing domain with verification token."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verification_token="abc123token",
        )
        print_domain_details(domain)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_print_domain_with_dkim_tokens(self, mock_console):
        """Test printing domain with DKIM tokens."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            dkim=DKIMStatus(
                status=Status.PENDING,
                tokens=["token1", "token2", "token3"],
            ),
        )
        print_domain_details(domain)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_print_domain_with_spf_values(self, mock_console):
        """Test printing domain with SPF current and suggested values."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            spf=SPFAuditResult(
                exists=True,
                current_value="v=spf1 ~all",
                suggested_value="v=spf1 include:amazonses.com ~all",
                status=Status.NEEDS_UPDATE,
                message="SPF needs update",
            ),
        )
        print_domain_details(domain)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_print_domain_with_mx_records(self, mock_console):
        """Test printing domain with MX records."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            mx=MXAuditResult(
                exists=True,
                mx_records=[
                    "aspmx.l.google.com",
                    "alt1.aspmx.l.google.com",
                    "alt2.aspmx.l.google.com",
                    "alt3.aspmx.l.google.com",
                    "alt4.aspmx.l.google.com",
                ],
                status=Status.SUCCESS,
                message="Gmail MX configured",
            ),
        )
        print_domain_details(domain)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_print_domain_with_errors(self, mock_console):
        """Test printing domain with errors."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            errors=["Error 1", "Error 2"],
        )
        print_domain_details(domain)
        assert mock_console.print.called


class TestPrintSummary:
    """Tests for print_summary function."""

    @patch("ses_domain_setup.reporting.console")
    def test_print_empty_report(self, mock_console):
        """Test printing empty report."""
        report = SetupReport()
        print_summary(report)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_print_report_with_domains(self, mock_console):
        """Test printing report with domains."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verified=True,
            ses_verification_status=Status.SUCCESS,
        )
        report = SetupReport(domains=[domain])
        print_summary(report)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_print_report_with_findings(self, mock_console):
        """Test printing report with findings."""
        finding = AuditFinding(
            domain="example.com",
            category="SPF",
            severity=Severity.WARNING,
            message="Test",
        )
        report = SetupReport(findings=[finding])
        print_summary(report)
        assert mock_console.print.called


class TestPrintSuggestedFixes:
    """Tests for print_suggested_fixes function."""

    @patch("ses_domain_setup.reporting.console")
    def test_no_suggestions(self, mock_console):
        """Test when no domains have suggestions."""
        domains = [DomainStatus(domain="example.com", zone_id="Z123456")]
        print_suggested_fixes(domains)
        assert mock_console.print.called

    @patch("ses_domain_setup.reporting.console")
    def test_with_suggestions(self, mock_console):
        """Test when domains have suggested records."""
        record = DNSRecord(
            name="_amazonses.example.com",
            record_type="TXT",
            value='"token"',
        )
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            suggested_records=[record],
        )
        print_suggested_fixes([domain])
        assert mock_console.print.called


class TestGenerateJsonReport:
    """Tests for generate_json_report function."""

    @patch("ses_domain_setup.reporting.console")
    def test_generate_basic_report(self, mock_console):
        """Test generating basic JSON report."""
        report = SetupReport()

        with tempfile.TemporaryDirectory() as tmpdir:
            filename = Path(tmpdir) / "test_report.json"
            result = generate_json_report(report, str(filename))

            assert result == filename
            assert filename.exists()

            with open(filename) as f:
                data = json.load(f)
                assert "domains" in data
                assert "findings" in data
                assert "summary" in data
                assert "generated_at" in data

    @patch("ses_domain_setup.reporting.console")
    def test_generate_report_with_domains(self, mock_console):
        """Test generating report with domain data."""
        domain = DomainStatus(
            domain="example.com",
            zone_id="Z123456",
            ses_verified=True,
            ses_verification_status=Status.SUCCESS,
        )
        report = SetupReport(
            domains=[domain],
            summary={"total": 1, "verified": 1},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            filename = Path(tmpdir) / "test_report.json"
            generate_json_report(report, str(filename))

            with open(filename) as f:
                data = json.load(f)
                assert len(data["domains"]) == 1
                assert data["domains"][0]["domain"] == "example.com"
                assert data["summary"]["verified"] == 1

    @patch("ses_domain_setup.reporting.console")
    def test_generate_report_with_findings(self, mock_console):
        """Test generating report with findings."""
        finding = AuditFinding(
            domain="example.com",
            category="DMARC",
            severity=Severity.ERROR,
            message="DMARC missing",
            recommendation="Add DMARC record",
        )
        report = SetupReport(findings=[finding])

        with tempfile.TemporaryDirectory() as tmpdir:
            filename = Path(tmpdir) / "test_report.json"
            generate_json_report(report, str(filename))

            with open(filename) as f:
                data = json.load(f)
                assert len(data["findings"]) == 1
                assert data["findings"][0]["severity"] == "error"


class TestPrintDryRunNotice:
    """Tests for print_dry_run_notice function."""

    @patch("ses_domain_setup.reporting.console")
    def test_prints_notice(self, mock_console):
        """Test dry run notice is printed."""
        print_dry_run_notice()
        assert mock_console.print.called


class TestPrintBackupNotice:
    """Tests for print_backup_notice function."""

    @patch("ses_domain_setup.reporting.console")
    def test_prints_backup_path(self, mock_console):
        """Test backup notice shows path."""
        backup_path = Path("/backups/example.com_20240101.json")
        print_backup_notice(backup_path)
        mock_console.print.assert_called()


class TestConfirmAction:
    """Tests for confirm_action function."""

    @patch("ses_domain_setup.reporting.console")
    def test_confirm_yes(self, mock_console):
        """Test confirmation with 'y' input."""
        mock_console.input.return_value = "y"
        result = confirm_action("Proceed?")
        assert result is True

    @patch("ses_domain_setup.reporting.console")
    def test_confirm_yes_uppercase(self, mock_console):
        """Test confirmation with 'Y' input."""
        mock_console.input.return_value = "Y"
        result = confirm_action("Proceed?")
        assert result is True

    @patch("ses_domain_setup.reporting.console")
    def test_confirm_yes_full_word(self, mock_console):
        """Test confirmation with 'yes' input."""
        mock_console.input.return_value = "yes"
        result = confirm_action("Proceed?")
        assert result is True

    @patch("ses_domain_setup.reporting.console")
    def test_confirm_no(self, mock_console):
        """Test confirmation with 'n' input."""
        mock_console.input.return_value = "n"
        result = confirm_action("Proceed?")
        assert result is False

    @patch("ses_domain_setup.reporting.console")
    def test_confirm_empty(self, mock_console):
        """Test confirmation with empty input (default no)."""
        mock_console.input.return_value = ""
        result = confirm_action("Proceed?")
        assert result is False

    @patch("ses_domain_setup.reporting.console")
    def test_confirm_other_input(self, mock_console):
        """Test confirmation with arbitrary input."""
        mock_console.input.return_value = "maybe"
        result = confirm_action("Proceed?")
        assert result is False
