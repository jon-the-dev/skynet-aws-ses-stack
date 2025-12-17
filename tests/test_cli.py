"""Tests for CLI functionality."""

import json

import pytest
from click.testing import CliRunner

from ses_domain_setup.cli import main


@pytest.fixture
def cli_runner():
    """Create a Click CLI test runner."""
    return CliRunner()


class TestCLI:
    """Tests for CLI commands."""

    def test_help(self, cli_runner):
        """Test --help option."""
        result = cli_runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "AWS SES Domain Setup Tool" in result.output
        assert "--dry-run" in result.output
        assert "--domain" in result.output

    def test_version(self, cli_runner):
        """Test --version option."""
        result = cli_runner.invoke(main, ["--version"])

        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_dry_run_flag(self, cli_runner, mock_aws_services, route53_client):
        """Test --dry-run flag shows notice."""
        # Create a test zone
        route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )

        result = cli_runner.invoke(main, ["--dry-run", "--yes"])

        assert "DRY RUN MODE" in result.output

    def test_no_zones_message(self, cli_runner, mock_aws_services):
        """Test message when no hosted zones exist."""
        result = cli_runner.invoke(main, ["--dry-run"])

        assert result.exit_code == 0
        assert "No public hosted zones found" in result.output

    def test_domain_not_found(self, cli_runner, mock_aws_services, route53_client):
        """Test message when specified domain not found."""
        # Create a different zone
        route53_client.create_hosted_zone(
            Name="other.com",
            CallerReference="test-ref-1",
        )

        result = cli_runner.invoke(main, ["--domain", "notfound.com", "--dry-run"])

        assert result.exit_code == 0
        assert "not found" in result.output

    def test_audit_only_flag(self, cli_runner, mock_aws_services, route53_client):
        """Test --audit flag only performs auditing."""
        # Create a test zone with SPF
        response = route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )
        zone_id = response["HostedZone"]["Id"]

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

        result = cli_runner.invoke(main, ["--audit", "--yes"])

        assert result.exit_code == 0
        # Should show SPF findings
        assert "SPF" in result.output

    def test_verify_only_flag(self, cli_runner, mock_aws_services, route53_client):
        """Test --verify-only flag."""
        route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )

        result = cli_runner.invoke(main, ["--verify-only", "--yes"])

        assert result.exit_code == 0
        assert "SES Verification" in result.output or "example.com" in result.output

    def test_output_file_option(self, cli_runner, mock_aws_services, route53_client, tmp_path):
        """Test custom output file."""
        route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )

        output_file = tmp_path / "custom_report.json"

        with cli_runner.isolated_filesystem(temp_dir=tmp_path):
            result = cli_runner.invoke(
                main,
                ["--dry-run", "--yes", "--output", str(output_file)],
            )

            assert result.exit_code == 0
            assert output_file.exists()

            # Verify JSON is valid
            with open(output_file) as f:
                report = json.load(f)
                assert "domains" in report
                assert "summary" in report

    def test_verbose_flag(self, cli_runner, mock_aws_services, route53_client):
        """Test --verbose flag shows detailed output."""
        route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )

        result = cli_runner.invoke(main, ["--dry-run", "--verbose", "--yes"])

        assert result.exit_code == 0
        # Verbose should show more details
        assert "example.com" in result.output


class TestCLIIntegration:
    """Integration tests for CLI with full workflow."""

    def test_full_workflow_dry_run(self, cli_runner, mock_aws_services, route53_client, ses_client):
        """Test full workflow in dry-run mode."""
        # Setup: Create zone with partial configuration
        response = route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )
        zone_id = response["HostedZone"]["Id"]

        # Add Google-only SPF
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

        result = cli_runner.invoke(main, ["--dry-run", "--verbose", "--yes"])

        assert result.exit_code == 0

        # Should identify missing SES in SPF
        assert "amazonses.com" in result.output or "SES" in result.output

        # Should identify missing DMARC
        assert "DMARC" in result.output

    def test_region_flag(self, cli_runner, mock_aws_services, route53_client):
        """Test --region flag."""
        route53_client.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-1",
        )

        result = cli_runner.invoke(
            main,
            ["--dry-run", "--region", "eu-west-1", "--yes"],
        )

        assert result.exit_code == 0
        assert "eu-west-1" in result.output
