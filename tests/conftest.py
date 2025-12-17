"""Pytest configuration and fixtures for SES domain setup tests."""

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def aws_credentials():
    """Mock AWS credentials for testing."""
    import os
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def mock_aws_services(aws_credentials):
    """Create mocked AWS services."""
    with mock_aws():
        yield


@pytest.fixture
def route53_client(mock_aws_services):
    """Create a mocked Route53 client."""
    return boto3.client("route53", region_name="us-east-1")


@pytest.fixture
def ses_client(mock_aws_services):
    """Create a mocked SES client."""
    return boto3.client("ses", region_name="us-east-1")


@pytest.fixture
def sample_hosted_zone(route53_client):
    """Create a sample hosted zone for testing."""
    response = route53_client.create_hosted_zone(
        Name="example.com",
        CallerReference="test-ref-123",
        HostedZoneConfig={
            "Comment": "Test zone",
            "PrivateZone": False,
        },
    )
    zone_id = response["HostedZone"]["Id"].replace("/hostedzone/", "")
    return {
        "Id": zone_id,
        "Name": "example.com",
    }


@pytest.fixture
def sample_spf_record():
    """Sample SPF record with Google."""
    return {
        "Name": "example.com.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
            {"Value": '"v=spf1 include:_spf.google.com ~all"'},
        ],
    }


@pytest.fixture
def sample_dmarc_record():
    """Sample DMARC record."""
    return {
        "Name": "_dmarc.example.com.",
        "Type": "TXT",
        "TTL": 300,
        "ResourceRecords": [
            {"Value": '"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"'},
        ],
    }


@pytest.fixture
def zone_with_records(route53_client, sample_hosted_zone, sample_spf_record, sample_dmarc_record):
    """Create a hosted zone with SPF and DMARC records."""
    zone_id = sample_hosted_zone["Id"]

    # Add SPF record
    route53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": sample_spf_record,
                },
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": sample_dmarc_record,
                },
            ],
        },
    )

    return sample_hosted_zone
