"""Tests for DNS auditing functionality."""

from ses_domain_setup.dns_auditor import (
    GMAIL_MX_SERVERS,
    GOOGLE_SPF_INCLUDE,
    SES_SPF_INCLUDE,
    audit_dmarc_record,
    audit_mx_record,
    audit_spf_record,
    generate_suggested_dmarc,
    parse_spf_record,
    suggest_spf_update,
)
from ses_domain_setup.models import Status


class TestParseSPFRecord:
    """Tests for SPF record parsing."""

    def test_parse_valid_spf(self):
        """Test parsing a valid SPF record."""
        spf = "v=spf1 include:_spf.google.com include:amazonses.com ~all"
        result = parse_spf_record(spf)

        assert result["includes"] == ["_spf.google.com", "amazonses.com"]
        assert result["qualifier"] == "~all"

    def test_parse_spf_with_ip4(self):
        """Test parsing SPF with IP mechanisms."""
        spf = "v=spf1 ip4:192.168.1.0/24 include:_spf.google.com -all"
        result = parse_spf_record(spf)

        assert "_spf.google.com" in result["includes"]
        assert result["qualifier"] == "-all"
        assert "ip4:192.168.1.0/24" in result["mechanisms"]

    def test_parse_spf_hard_fail(self):
        """Test parsing SPF with hard fail."""
        spf = "v=spf1 include:_spf.google.com -all"
        result = parse_spf_record(spf)

        assert result["qualifier"] == "-all"

    def test_parse_non_spf_record(self):
        """Test parsing a non-SPF record returns empty result."""
        result = parse_spf_record("not an spf record")

        assert result["includes"] == []
        assert result["qualifier"] is None


class TestAuditSPFRecord:
    """Tests for SPF record auditing."""

    def test_audit_missing_spf(self):
        """Test auditing when no SPF record exists."""
        records = [
            {"Type": "A", "Name": "example.com.", "ResourceRecords": [{"Value": "1.2.3.4"}]},
        ]

        result = audit_spf_record(records, "example.com")

        assert not result.exists
        assert result.status == Status.MISSING
        assert GOOGLE_SPF_INCLUDE in result.suggested_value
        assert SES_SPF_INCLUDE in result.suggested_value

    def test_audit_spf_with_google_only(self):
        """Test auditing SPF that only has Google."""
        records = [
            {
                "Type": "TXT",
                "Name": "example.com.",
                "ResourceRecords": [{"Value": '"v=spf1 include:_spf.google.com ~all"'}],
            },
        ]

        result = audit_spf_record(records, "example.com")

        assert result.exists
        assert result.has_google
        assert not result.has_ses
        assert result.status == Status.NEEDS_UPDATE
        assert SES_SPF_INCLUDE in result.suggested_value

    def test_audit_spf_with_ses_only(self):
        """Test auditing SPF that only has SES."""
        records = [
            {
                "Type": "TXT",
                "Name": "example.com.",
                "ResourceRecords": [{"Value": '"v=spf1 include:amazonses.com ~all"'}],
            },
        ]

        result = audit_spf_record(records, "example.com")

        assert result.exists
        assert not result.has_google
        assert result.has_ses
        assert result.status == Status.WARNING
        assert GOOGLE_SPF_INCLUDE in result.suggested_value

    def test_audit_spf_with_both(self):
        """Test auditing SPF that has both Google and SES."""
        records = [
            {
                "Type": "TXT",
                "Name": "example.com.",
                "ResourceRecords": [
                    {"Value": '"v=spf1 include:_spf.google.com include:amazonses.com ~all"'}
                ],
            },
        ]

        result = audit_spf_record(records, "example.com")

        assert result.exists
        assert result.has_google
        assert result.has_ses
        assert result.status == Status.SUCCESS


class TestSuggestSPFUpdate:
    """Tests for SPF update suggestions."""

    def test_add_ses_to_google_spf(self):
        """Test adding SES to Google-only SPF."""
        existing = "v=spf1 include:_spf.google.com ~all"
        result = suggest_spf_update(existing, add_google=False, add_ses=True)

        assert GOOGLE_SPF_INCLUDE in result
        assert SES_SPF_INCLUDE in result
        assert result.endswith("~all")

    def test_add_google_to_ses_spf(self):
        """Test adding Google to SES-only SPF."""
        existing = "v=spf1 include:amazonses.com ~all"
        result = suggest_spf_update(existing, add_google=True, add_ses=False)

        assert GOOGLE_SPF_INCLUDE in result
        assert SES_SPF_INCLUDE in result

    def test_preserve_hard_fail(self):
        """Test that hard fail qualifier is preserved."""
        existing = "v=spf1 include:_spf.google.com -all"
        result = suggest_spf_update(existing, add_ses=True)

        assert result.endswith("-all")

    def test_preserve_existing_mechanisms(self):
        """Test that existing mechanisms are preserved."""
        existing = "v=spf1 ip4:10.0.0.0/8 include:_spf.google.com ~all"
        result = suggest_spf_update(existing, add_ses=True)

        assert "ip4:10.0.0.0/8" in result
        assert GOOGLE_SPF_INCLUDE in result
        assert SES_SPF_INCLUDE in result

    def test_no_duplicate_includes(self):
        """Test that already-present includes aren't duplicated."""
        existing = "v=spf1 include:_spf.google.com include:amazonses.com ~all"
        result = suggest_spf_update(existing, add_google=True, add_ses=True)

        # Count occurrences
        assert result.count(GOOGLE_SPF_INCLUDE) == 1
        assert result.count(SES_SPF_INCLUDE) == 1


class TestAuditDMARCRecord:
    """Tests for DMARC record auditing."""

    def test_audit_missing_dmarc(self):
        """Test auditing when no DMARC record exists."""
        records = [
            {"Type": "TXT", "Name": "example.com.", "ResourceRecords": [{"Value": "something"}]},
        ]

        result = audit_dmarc_record(records, "example.com")

        assert not result.exists
        assert result.status == Status.MISSING

    def test_audit_dmarc_policy_none(self):
        """Test auditing DMARC with p=none (warning)."""
        records = [
            {
                "Type": "TXT",
                "Name": "_dmarc.example.com.",
                "ResourceRecords": [{"Value": '"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'}],
            },
        ]

        result = audit_dmarc_record(records, "example.com")

        assert result.exists
        assert result.policy == "none"
        assert result.status == Status.WARNING

    def test_audit_dmarc_policy_quarantine(self):
        """Test auditing DMARC with p=quarantine (success)."""
        records = [
            {
                "Type": "TXT",
                "Name": "_dmarc.example.com.",
                "ResourceRecords": [{"Value": '"v=DMARC1; p=quarantine"'}],
            },
        ]

        result = audit_dmarc_record(records, "example.com")

        assert result.exists
        assert result.policy == "quarantine"
        assert result.status == Status.SUCCESS

    def test_audit_dmarc_policy_reject(self):
        """Test auditing DMARC with p=reject (success)."""
        records = [
            {
                "Type": "TXT",
                "Name": "_dmarc.example.com.",
                "ResourceRecords": [{"Value": '"v=DMARC1; p=reject"'}],
            },
        ]

        result = audit_dmarc_record(records, "example.com")

        assert result.exists
        assert result.policy == "reject"
        assert result.status == Status.SUCCESS


class TestGenerateSuggestedDMARC:
    """Tests for DMARC record generation."""

    def test_generate_dmarc_without_email(self):
        """Test generating DMARC without custom email."""
        result = generate_suggested_dmarc("example.com")

        assert "v=DMARC1" in result
        assert "p=quarantine" in result
        assert "dmarc@example.com" in result

    def test_generate_dmarc_with_email(self):
        """Test generating DMARC with custom email."""
        result = generate_suggested_dmarc("example.com", email="security@example.com")

        assert "v=DMARC1" in result
        assert "p=quarantine" in result
        assert "security@example.com" in result


class TestAuditMXRecord:
    """Tests for MX record auditing."""

    def test_audit_missing_mx(self):
        """Test auditing when no MX records exist."""
        records = [
            {"Type": "A", "Name": "example.com.", "ResourceRecords": [{"Value": "1.2.3.4"}]},
        ]

        result = audit_mx_record(records, "example.com")

        assert not result.exists
        assert result.status == Status.MISSING
        assert not result.has_gmail
        assert result.mx_records == []

    def test_audit_gmail_mx_complete(self):
        """Test auditing complete Gmail MX configuration."""
        records = [
            {
                "Type": "MX",
                "Name": "example.com.",
                "ResourceRecords": [
                    {"Value": "1 aspmx.l.google.com."},
                    {"Value": "5 alt1.aspmx.l.google.com."},
                    {"Value": "5 alt2.aspmx.l.google.com."},
                    {"Value": "10 alt3.aspmx.l.google.com."},
                    {"Value": "10 alt4.aspmx.l.google.com."},
                ],
            },
        ]

        result = audit_mx_record(records, "example.com")

        assert result.exists
        assert result.has_gmail
        assert result.status == Status.SUCCESS
        assert len(result.mx_records) == 5
        assert "aspmx.l.google.com" in result.mx_records

    def test_audit_gmail_mx_partial(self):
        """Test auditing partial Gmail MX configuration (warning)."""
        records = [
            {
                "Type": "MX",
                "Name": "example.com.",
                "ResourceRecords": [
                    {"Value": "10 alt3.aspmx.l.google.com."},
                ],
            },
        ]

        result = audit_mx_record(records, "example.com")

        assert result.exists
        assert result.has_gmail
        assert result.status == Status.WARNING
        assert len(result.mx_records) == 1

    def test_audit_non_gmail_mx(self):
        """Test auditing non-Gmail MX records."""
        records = [
            {
                "Type": "MX",
                "Name": "example.com.",
                "ResourceRecords": [
                    {"Value": "10 mail.example.com."},
                    {"Value": "20 mail2.example.com."},
                ],
            },
        ]

        result = audit_mx_record(records, "example.com")

        assert result.exists
        assert not result.has_gmail
        assert result.status == Status.SUCCESS
        assert len(result.mx_records) == 2
        assert "mail.example.com" in result.mx_records

    def test_audit_mx_other_provider(self):
        """Test auditing MX records from another provider (e.g., Microsoft 365)."""
        records = [
            {
                "Type": "MX",
                "Name": "example.com.",
                "ResourceRecords": [
                    {"Value": "0 example-com.mail.protection.outlook.com."},
                ],
            },
        ]

        result = audit_mx_record(records, "example.com")

        assert result.exists
        assert not result.has_gmail
        assert result.status == Status.SUCCESS
        assert "example-com.mail.protection.outlook.com" in result.mx_records

    def test_audit_mx_subdomain_ignored(self):
        """Test that MX records for subdomains are ignored."""
        records = [
            {
                "Type": "MX",
                "Name": "mail.example.com.",
                "ResourceRecords": [
                    {"Value": "10 mx.example.com."},
                ],
            },
        ]

        result = audit_mx_record(records, "example.com")

        assert not result.exists
        assert result.status == Status.MISSING

    def test_gmail_mx_servers_constant(self):
        """Test that GMAIL_MX_SERVERS contains expected servers."""
        assert "aspmx.l.google.com" in GMAIL_MX_SERVERS
        assert "alt1.aspmx.l.google.com" in GMAIL_MX_SERVERS
        assert len(GMAIL_MX_SERVERS) == 5
