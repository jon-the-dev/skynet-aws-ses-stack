# SES Sender Module

Reusable Terraform module to grant SES send permissions to any Lambda/service.

## Usage in Other Stacks

### 1. Add the module to your Terraform

```hcl
# In your service's Terraform
module "ses_sender" {
  source = "git::https://github.com/your-org/skynet-aws-ses-stack.git//terraform/modules/ses-sender"

  role_name    = aws_iam_role.my_lambda_role.name
  sender_email = "noreply@team-skynet.io"
}
```

Or allow any email from the domain:

```hcl
module "ses_sender" {
  source = "git::https://github.com/your-org/skynet-aws-ses-stack.git//terraform/modules/ses-sender"

  role_name     = aws_iam_role.my_lambda_role.name
  sender_domain = "team-skynet.io"  # Allows *@team-skynet.io
}
```

### 2. Add environment variables to your Lambda

```hcl
resource "aws_lambda_function" "my_function" {
  # ... other config ...

  environment {
    variables = {
      SES_SENDER_EMAIL = "noreply@team-skynet.io"
      SES_REGION       = "us-east-1"
    }
  }
}
```

### 3. Copy `ses_helper.py` into your Lambda

```python
from ses_helper import send_email

def handler(event, context):
    # Send a simple email
    send_email(
        to="devops@team-skynet.io",
        subject="Alert from My Service",
        body="Something happened!"
    )

    # Send with HTML and reply-to
    send_email(
        to=["user1@example.com", "user2@example.com"],
        subject="Weekly Report",
        body="Plain text version",
        html_body="<h1>HTML version</h1>",
        reply_to="reports@team-skynet.io"
    )
```

## Variables

| Name | Description | Default |
|------|-------------|---------|
| `role_name` | IAM role name to attach policy to | (required) |
| `sender_email` | Specific email to allow sending from | `noreply@team-skynet.io` |
| `sender_domain` | Domain to allow sending from (overrides sender_email) | `""` |
| `ses_region` | AWS region for SES | `us-east-1` |

## Important Notes

### Sandbox Mode
If your SES account is in sandbox mode:
- You can only send TO verified email addresses
- Verify recipient emails: `aws ses verify-email-identity --email-address user@example.com`
- Request production access for unrestricted sending

### Verified Domain Required
The sender domain (`team-skynet.io`) must be verified in SES before sending.
Use the `ses_domain_setup.py` tool to verify domains.

## Example: Adding to Existing Lambda Stack

```hcl
# existing_service/main.tf

resource "aws_iam_role" "lambda_role" {
  name = "my-service-lambda-role"
  # ... assume role policy ...
}

# Add SES permissions
module "ses_sender" {
  source = "git::https://github.com/your-org/skynet-aws-ses-stack.git//terraform/modules/ses-sender"

  role_name     = aws_iam_role.lambda_role.name
  sender_domain = "team-skynet.io"
}

resource "aws_lambda_function" "my_function" {
  function_name = "my-service"
  role          = aws_iam_role.lambda_role.arn
  # ...

  environment {
    variables = {
      SES_SENDER_EMAIL = "alerts@team-skynet.io"
      SES_REGION       = "us-east-1"
    }
  }
}
```
