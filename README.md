# AWS SES Domain Setup Tool

Automates AWS SES domain verification and DNS record management for all domains in Route 53. Includes Gmail compatibility auditing for organizations using Google Workspace alongside Amazon SES.

## Features

- **Automatic SES Verification**: Initiates domain verification in SES for all Route 53 hosted zones
- **DKIM Configuration**: Retrieves DKIM tokens and creates required CNAME records
- **SPF Auditing**: Checks SPF records for Gmail and SES compatibility
- **DMARC Auditing**: Validates DMARC policies and warns on weak configurations
- **Gmail Support**: Ensures SPF records include Google Workspace (`include:_spf.google.com`)
- **Safety First**: Never deletes records, backs up before changes, requires confirmation
- **Rich Output**: Colored terminal output with status tables and suggestions

## Prerequisites

### IAM Permissions

Your AWS credentials need the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets",
        "route53:GetHostedZone"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ses:VerifyDomainIdentity",
        "ses:VerifyDomainDkim",
        "ses:GetIdentityVerificationAttributes",
        "ses:GetIdentityDkimAttributes"
      ],
      "Resource": "*"
    }
  ]
}
```

### Python Requirements

- Python 3.11+
- pipenv

## Installation

```bash
# Clone the repository
git clone git@github.com:jon-the-dev/skynet-aws-ses-stack.git
cd skynet-aws-ses-stack

# Install dependencies
pipenv install

# For development (includes testing tools)
pipenv install --dev

# Activate the virtual environment
pipenv shell
```

## Usage

### Basic Usage

```bash
# Preview all changes (dry run)
python ses_domain_setup.py --dry-run

# Run setup for all domains (will prompt for confirmation)
python ses_domain_setup.py

# Run setup with automatic confirmation
python ses_domain_setup.py --yes
```

### Targeting Specific Domains

```bash
# Setup a specific domain
python ses_domain_setup.py --domain example.com

# Dry run for a specific domain
python ses_domain_setup.py --domain example.com --dry-run
```

### Audit-Only Mode

```bash
# Only audit SPF/DMARC without making SES changes
python ses_domain_setup.py --audit

# Audit a specific domain
python ses_domain_setup.py --audit --domain example.com
```

### Verification Status Check

```bash
# Only check current SES verification status
python ses_domain_setup.py --verify-only
```

### Other Options

```bash
# Use a different AWS region for SES
python ses_domain_setup.py --region eu-west-1

# Verbose output with domain details
python ses_domain_setup.py --verbose

# Custom output report filename
python ses_domain_setup.py --output my_report.json

# Show help
python ses_domain_setup.py --help
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview changes without applying them |
| `--domain TEXT` | Target a specific domain instead of all |
| `--region TEXT` | AWS region for SES (default: us-east-1) |
| `--verify-only` | Only check verification status |
| `--audit` | Only audit SPF/DMARC without making changes |
| `--yes, -y` | Skip confirmation prompts |
| `--verbose, -v` | Show detailed output for each domain |
| `--output, -o TEXT` | Output JSON report filename |
| `--version` | Show version |
| `--help` | Show help message |

## Output

### Summary Table

The tool displays a colored summary table:

```
┌──────────────────┬──────────────┬─────────┬─────────────┬───────────┐
│ Domain           │ SES Verified │ DKIM    │ SPF         │ DMARC     │
├──────────────────┼──────────────┼─────────┼─────────────┼───────────┤
│ example.com      │ ✓ success    │ ✓ success │ Gmail+SES │ p=quarantine │
│ other.com        │ ○ pending    │ ○ pending │ ↑ needs_update │ ! warning │
└──────────────────┴──────────────┴─────────┴─────────────┴───────────┘
```

**Status Icons:**
- ✓ (green) = Success/OK
- ○ (yellow) = Pending
- ↑ (yellow) = Needs update
- ! (yellow) = Warning
- ✗ (red) = Missing/Failed

### JSON Report

A detailed JSON report (`ses_setup_report.json`) is generated with:

- Complete status for each domain
- SPF and DMARC audit results
- Suggested DNS records
- All findings and recommendations

## DNS Records Explained

### SES Verification TXT Record

```
_amazonses.example.com TXT "verification-token-here"
```

This record proves domain ownership to AWS SES.

### DKIM CNAME Records

```
token1._domainkey.example.com CNAME token1.dkim.amazonses.com
token2._domainkey.example.com CNAME token2.dkim.amazonses.com
token3._domainkey.example.com CNAME token3.dkim.amazonses.com
```

These records enable DKIM signing for emails sent through SES.

### SPF Record

```
v=spf1 include:_spf.google.com include:amazonses.com ~all
```

- `include:_spf.google.com` - Authorizes Google Workspace to send email
- `include:amazonses.com` - Authorizes Amazon SES to send email
- `~all` - Soft fail for unauthorized senders

### DMARC Record

```
_dmarc.example.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

- `p=none` - Monitor only (warning: not enforcing)
- `p=quarantine` - Suspicious emails go to spam
- `p=reject` - Reject unauthorized emails (most secure)

## Development

### Running Tests

```bash
# Run all tests
pipenv run pytest

# Run with coverage
pipenv run pytest --cov=ses_domain_setup

# Run specific test file
pipenv run pytest tests/test_dns_auditor.py
```

### Code Quality

```bash
# Run flake8 linting
pipenv run flake8 ses_domain_setup tests

# Run mypy type checking
pipenv run mypy ses_domain_setup
```

## Safety Features

1. **Never deletes records** - Only creates or updates
2. **Confirmation prompts** - Requires `--yes` to skip
3. **Dry run mode** - Preview changes before applying
4. **Backup creation** - Backs up existing records to `backups/` before changes
5. **Retry logic** - Handles AWS API rate limits gracefully

## Troubleshooting

### "No public hosted zones found"

Ensure your AWS credentials have Route53 read access and you have public (not private) hosted zones.

### SES Verification Stuck in Pending

1. Verify the TXT record was created correctly in Route53
2. DNS propagation can take up to 72 hours
3. Check the record format: `_amazonses.domain.com` with the token as the value

### DKIM Not Verifying

1. Verify all 3 CNAME records were created
2. Check the record format matches exactly
3. DNS propagation can take up to 72 hours

## Terraform Infrastructure

This repo also includes Terraform for deploying a contact form API using SES.

### Deploy Contact Form API

```bash
cd terraform
terraform init
terraform apply
```

This creates:
- Lambda function for sending emails
- API Gateway HTTP endpoint (`POST /send`)
- IAM roles with least-privilege SES permissions
- CloudWatch logging

### Using SES in Other Services

A reusable Terraform module is provided at `terraform/modules/ses-sender/`:

```hcl
# In your service's Terraform
module "ses_sender" {
  source = "git@github.com:jon-the-dev/skynet-aws-ses-stack.git//terraform/modules/ses-sender"

  role_name     = aws_iam_role.my_lambda_role.name
  sender_domain = "team-skynet.io"  # Allows *@team-skynet.io
}
```

Add environment variables to your Lambda:

```hcl
environment {
  variables = {
    SES_SENDER_EMAIL = "myservice@team-skynet.io"
    SES_REGION       = "us-east-1"
  }
}
```

Copy `terraform/modules/ses-sender/ses_helper.py` into your Lambda and use:

```python
from ses_helper import send_email

send_email(
    to="devops@team-skynet.io",
    subject="Alert from My Service",
    body="Something happened!"
)
```

See `terraform/modules/ses-sender/README.md` for full documentation.

## License

AGPL-3.0
