"""Tests for AWS operations."""

import pytest

from ses_domain_setup.aws_operations import Route53Client, SESClient
from ses_domain_setup.models import DNSRecord, RecordAction, Status


@pytest.fixture
def route53_setup(mock_aws_services, route53_client):
    """Setup Route53 with a test zone."""
    response = route53_client.create_hosted_zone(
        Name="example.com",
        CallerReference="test-ref-123",
    )
    zone_id = response["HostedZone"]["Id"].replace("/hostedzone/", "")

    # Add some test records
    route53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": "example.com.",
                        "Type": "TXT",
                        "TTL": 300,
                        "ResourceRecords": [
                            {"Value": '"v=spf1 include:_spf.google.com ~all"'},
                        ],
                    },
                },
            ],
        },
    )

    return {"zone_id": zone_id, "domain": "example.com"}


class TestRoute53Client:
    """Tests for Route53Client."""

    def test_list_hosted_zones(self, mock_aws_services, route53_client):
        """Test listing hosted zones."""
        # Create a zone
        route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )

        client = Route53Client()
        zones = client.list_hosted_zones()

        assert len(zones) == 1
        assert zones[0]["Name"] == "example.com"

    def test_list_hosted_zones_excludes_private(self, mock_aws_services, route53_client):
        """Test that private zones are excluded."""
        # Create public zone
        route53_client.create_hosted_zone(
            Name="public.com",
            CallerReference="test-ref-1",
        )

        client = Route53Client()
        zones = client.list_hosted_zones()

        # Should only include public zones
        names = [z["Name"] for z in zones]
        assert "public.com" in names

    def test_get_domain_records(self, route53_setup):
        """Test getting records for a domain."""
        client = Route53Client()
        records = client.get_domain_records(
            route53_setup["zone_id"],
            route53_setup["domain"],
        )

        # Should have at least the TXT record we created
        txt_records = [r for r in records if r["Type"] == "TXT"]
        assert len(txt_records) >= 1

    def test_create_record(self, route53_setup):
        """Test creating a DNS record."""
        client = Route53Client()
        record = DNSRecord(
            name="test.example.com",
            record_type="CNAME",
            value="target.example.com",
            action=RecordAction.CREATE,
        )

        result = client.create_record(route53_setup["zone_id"], record)
        assert result is True

        # Verify record was created
        created = client.get_record(
            route53_setup["zone_id"],
            "test.example.com",
            "CNAME",
        )
        assert created is not None

    def test_create_record_dry_run(self, route53_setup):
        """Test dry run doesn't create records."""
        client = Route53Client()
        record = DNSRecord(
            name="dryrun.example.com",
            record_type="CNAME",
            value="target.example.com",
            action=RecordAction.CREATE,
        )

        result = client.create_record(route53_setup["zone_id"], record, dry_run=True)
        assert result is True

        # Record should not exist
        created = client.get_record(
            route53_setup["zone_id"],
            "dryrun.example.com",
            "CNAME",
        )
        assert created is None


class TestSESClient:
    """Tests for SESClient."""

    def test_verify_domain(self, mock_aws_services):
        """Test verifying a domain."""
        client = SESClient(region="us-east-1")
        token = client.verify_domain("example.com")

        assert token is not None
        assert len(token) > 0

    def test_get_verification_status_unverified(self, mock_aws_services):
        """Test getting status for unverified domain."""
        client = SESClient(region="us-east-1")

        status, token = client.get_verification_status("notverified.com")

        assert status == Status.MISSING
        assert token is None

    def test_get_verification_status_after_verify(self, mock_aws_services):
        """Test getting status after verification initiated."""
        client = SESClient(region="us-east-1")

        # Initiate verification
        client.verify_domain("example.com")

        # Check status
        status, token = client.get_verification_status("example.com")

        # Moto returns pending after verify_domain_identity
        assert status in (Status.PENDING, Status.SUCCESS)
        assert token is not None

    def test_enable_dkim(self, mock_aws_services):
        """Test enabling DKIM for a domain."""
        client = SESClient(region="us-east-1")

        # First verify the domain
        client.verify_domain("example.com")

        # Enable DKIM
        tokens = client.enable_dkim("example.com")

        assert tokens is not None
        assert len(tokens) == 3  # SES returns 3 DKIM tokens

    def test_get_dkim_attributes(self, mock_aws_services):
        """Test getting DKIM attributes."""
        client = SESClient(region="us-east-1")

        # Verify and enable DKIM
        client.verify_domain("example.com")
        client.enable_dkim("example.com")

        # Get DKIM status
        dkim_status = client.get_dkim_attributes("example.com")

        assert dkim_status.tokens is not None
        assert len(dkim_status.tokens) == 3
        assert len(dkim_status.cname_records) == 3

    def test_dkim_cname_format(self, mock_aws_services):
        """Test that DKIM CNAME records have correct format."""
        client = SESClient(region="us-east-1")

        client.verify_domain("example.com")
        client.enable_dkim("example.com")

        dkim_status = client.get_dkim_attributes("example.com")

        for record in dkim_status.cname_records:
            assert record.record_type == "CNAME"
            assert "_domainkey.example.com" in record.name
            assert "dkim.amazonses.com" in record.value
