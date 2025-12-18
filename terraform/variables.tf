variable "aws_region" {
  description = "AWS region for SES and Lambda"
  type        = string
  default     = "us-east-1"
}

variable "sender_email" {
  description = "Email address to send from (must be from verified domain)"
  type        = string
  default     = "noreply@team-skynet.io"
}

variable "recipient_email" {
  description = "Email address to receive contact form submissions"
  type        = string
  default     = "devops@team-skynet.io"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "ses-contact-form"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "allowed_origins" {
  description = "CORS allowed origins for API Gateway"
  type        = list(string)
  default     = ["https://team-skynet.io", "https://www.team-skynet.io"]
}
