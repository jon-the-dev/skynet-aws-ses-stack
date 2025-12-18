"""Lambda function to send emails via AWS SES."""

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get configuration from environment
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "noreply@team-skynet.io")
RECIPIENT_EMAIL = os.environ.get("RECIPIENT_EMAIL", "devops@team-skynet.io")
AWS_SES_REGION = os.environ.get("AWS_SES_REGION", "us-east-1")

# Initialize SES client
ses_client = boto3.client("ses", region_name=AWS_SES_REGION)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Lambda handler for sending emails via SES.

    Expected JSON body:
    {
        "subject": "Email subject",
        "message": "Email body content",
        "from_name": "Sender's name (optional)",
        "from_email": "Sender's email for reply-to (optional)"
    }
    """
    # Log only non-sensitive metadata, not the full event body
    logger.info(
        f"Request received: method={event.get('httpMethod', 'N/A')}, "
        f"path={event.get('path', 'N/A')}, "
        f"requestId={event.get('requestContext', {}).get('requestId', 'N/A')}"
    )

    # Parse request body
    try:
        if event.get("body"):
            body = json.loads(event["body"]) if isinstance(event["body"], str) else event["body"]
        else:
            body = event
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in request body: {e}")
        return _response(400, {"error": "Invalid JSON in request body"})

    # Validate required fields
    subject = body.get("subject")
    message = body.get("message")

    if not subject or not message:
        return _response(400, {"error": "Missing required fields: subject and message"})

    # Optional fields
    from_name = body.get("from_name", "Contact Form")
    from_email = body.get("from_email", "")

    # Build email content
    email_body = f"""
New message from contact form:

From: {from_name}
Email: {from_email or 'Not provided'}

Message:
{message}
"""

    # Add reply-to if provided
    reply_to = [from_email] if from_email else []

    try:
        response = ses_client.send_email(
            Source=f"{from_name} <{SENDER_EMAIL}>",
            Destination={
                "ToAddresses": [RECIPIENT_EMAIL],
            },
            Message={
                "Subject": {
                    "Data": f"[Contact Form] {subject}",
                    "Charset": "UTF-8",
                },
                "Body": {
                    "Text": {
                        "Data": email_body,
                        "Charset": "UTF-8",
                    },
                },
            },
            ReplyToAddresses=reply_to if reply_to else [SENDER_EMAIL],
        )

        message_id = response.get("MessageId")
        logger.info(f"Email sent successfully. MessageId: {message_id}")

        return _response(200, {
            "success": True,
            "message": "Email sent successfully",
            "messageId": message_id,
        })

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        logger.error(f"SES error: {error_code} - {error_message}")

        # Don't expose internal errors to client
        if error_code == "MessageRejected":
            return _response(400, {"error": "Email could not be sent. Please try again."})

        return _response(500, {"error": "Internal server error"})

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return _response(500, {"error": "Internal server error"})


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    """Build API Gateway response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
        },
        "body": json.dumps(body),
    }
