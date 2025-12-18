terraform {
  required_version = ">= 1.0"

  backend "s3" {
    bucket = "skynet-tf-state-prod"
    key    = "ses-contact-form/terraform.tfstate"
    region = "us-west-2"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

locals {
  function_name = "${var.project_name}-${var.environment}"
}

# Get current AWS account ID for IAM policy scoping
data "aws_caller_identity" "current" {}
