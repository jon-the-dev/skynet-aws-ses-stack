# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-12-17

### Added

- MX record auditing for Gmail/Google Workspace compatibility detection
- `MXAuditResult` model for capturing MX audit state
- `audit_mx_record()` function to analyze MX records and detect Gmail servers
- `GMAIL_MX_SERVERS` constant with standard Google Workspace MX hostnames
- MX status column in summary table output
- MX details in domain detail view (shows mail server list)
- MX statistics in JSON report (`mx_ok`, `mx_gmail` counts)
- Comprehensive test coverage for MX auditing functionality

### Changed

- Summary panel now displays MX record status alongside SPF/DKIM/DMARC
- Domain status model includes MX audit results in JSON serialization

## [0.1.0] - 2025-12-16

### Added

- Initial release of AWS SES Domain Setup Tool
- CLI with `--dry-run`, `--domain`, `--audit`, `--verify-only` options
- Route53 hosted zone discovery and DNS record management
- SES domain verification and DKIM configuration
- SPF record parsing and auditing with SES/Google include detection
- DMARC record parsing and policy analysis
- Rich console output with colored status tables
- JSON report generation with backup functionality
- Terraform module for contact form API using SES
- Comprehensive test suite with moto AWS mocking
