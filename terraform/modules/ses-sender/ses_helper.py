"""
SES Email Helper - Copy this into your Lambda functions.

Usage:
    from ses_helper import send_email

    # Simple usage
    send_email(
        to="devops@team-skynet.io",
        subject="Alert: Something happened",
        body="Details here..."
    )

    # With reply-to
    send_email(
        to="devops@team-skynet.io",
        subject="Contact Form Submission",
        body="Message from user...",
        reply_to="user@example.com",
        from_name="Contact Form"
    )
"""

import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Configuration - set via environment variables
SES_SENDER = os.environ.get("SES_SENDER_EMAIL", "noreply@team-skynet.io")
SES_REGION = os.environ.get("SES_REGION", "us-east-1")

_ses_client = None


def get_ses_client():
    """Get or create SES client (singleton)."""
    global _ses_client
    if _ses_client is None:
        _ses_client = boto3.client("ses", region_name=SES_REGION)
    return _ses_client


def send_email(
    to: str | list[str],
    subject: str,
    body: str,
    html_body: str | None = None,
    reply_to: str | None = None,
    from_name: str = "Team Skynet",
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
) -> dict:
    """
    Send an email via AWS SES.

    Args:
        to: Recipient email(s)
        subject: Email subject
        body: Plain text body
        html_body: Optional HTML body
        reply_to: Optional reply-to address
        from_name: Display name for sender
        cc: Optional CC recipients
        bcc: Optional BCC recipients

    Returns:
        SES response dict with MessageId

    Raises:
        ClientError: If SES fails to send
    """
    client = get_ses_client()

    # Normalize to list
    to_addresses = [to] if isinstance(to, str) else to

    # Build destination
    destination = {"ToAddresses": to_addresses}
    if cc:
        destination["CcAddresses"] = cc
    if bcc:
        destination["BccAddresses"] = bcc

    # Build message body
    message_body = {
        "Text": {"Data": body, "Charset": "UTF-8"}
    }
    if html_body:
        message_body["Html"] = {"Data": html_body, "Charset": "UTF-8"}

    # Build full request
    kwargs = {
        "Source": f"{from_name} <{SES_SENDER}>",
        "Destination": destination,
        "Message": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": message_body,
        },
    }

    if reply_to:
        kwargs["ReplyToAddresses"] = [reply_to]

    try:
        response = client.send_email(**kwargs)
        logger.info(f"Email sent: {response['MessageId']} to {to_addresses}")
        return response
    except ClientError as e:
        logger.error(f"Failed to send email: {e}")
        raise


def send_templated_email(
    to: str | list[str],
    template_name: str,
    template_data: dict,
    from_name: str = "Team Skynet",
) -> dict:
    """
    Send an email using an SES template.

    Args:
        to: Recipient email(s)
        template_name: Name of SES email template
        template_data: Data to populate template
        from_name: Display name for sender

    Returns:
        SES response dict with MessageId
    """
    import json

    client = get_ses_client()
    to_addresses = [to] if isinstance(to, str) else to

    response = client.send_templated_email(
        Source=f"{from_name} <{SES_SENDER}>",
        Destination={"ToAddresses": to_addresses},
        Template=template_name,
        TemplateData=json.dumps(template_data),
    )

    logger.info(f"Templated email sent: {response['MessageId']}")
    return response
