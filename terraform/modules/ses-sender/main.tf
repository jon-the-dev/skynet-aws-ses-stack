# Reusable module for granting SES send permissions to any IAM role
# Usage in other stacks:
#
# module "ses_sender" {
#   source       = "git::https://github.com/your-org/skynet-aws-ses-stack.git//terraform/modules/ses-sender"
#   role_name    = aws_iam_role.my_lambda_role.name
#   sender_email = "noreply@team-skynet.io"
# }

variable "role_name" {
  description = "Name of the IAM role to attach SES permissions to"
  type        = string
}

variable "sender_email" {
  description = "Email address allowed to send from (must be from verified domain)"
  type        = string
  default     = "noreply@team-skynet.io"
}

variable "sender_domain" {
  description = "Verified domain to allow sending from (alternative to sender_email)"
  type        = string
  default     = ""
}

variable "ses_region" {
  description = "AWS region for SES"
  type        = string
  default     = "us-east-1"
}

# Policy allowing SES send
resource "aws_iam_role_policy" "ses_send" {
  name = "ses-send-${replace(var.sender_email, "@", "-at-")}"
  role = var.role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "*"
        Condition = var.sender_domain != "" ? {
          StringLike = {
            "ses:FromAddress" = "*@${var.sender_domain}"
          }
          } : {
          StringEquals = {
            "ses:FromAddress" = var.sender_email
          }
        }
      }
    ]
  })
}

output "policy_name" {
  value = aws_iam_role_policy.ses_send.name
}
