#!/usr/bin/env python3
"""
AWS SES Domain Setup Tool.

Entry point script for running the SES domain setup CLI.

Usage:
    python ses_domain_setup.py [OPTIONS]
    python ses_domain_setup.py --help

Examples:
    # Preview all changes (dry run)
    python ses_domain_setup.py --dry-run

    # Setup a specific domain
    python ses_domain_setup.py --domain example.com

    # Only audit SPF/DMARC records
    python ses_domain_setup.py --audit

    # Check verification status only
    python ses_domain_setup.py --verify-only

    # Skip confirmations
    python ses_domain_setup.py --yes
"""

from ses_domain_setup.cli import main

if __name__ == "__main__":
    main()
