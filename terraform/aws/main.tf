# AWS Infrastructure with Intentional Misconfigurations for Security Testing
# WARNING: This infrastructure is intentionally insecure. Do NOT use in production.

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "CloudSecurityPostureDashboard"
      Environment = "SecurityTesting"
      ManagedBy   = "Terraform"
      Purpose     = "IntentionalMisconfigurations"
    }
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Output the account ID for reference
output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS Account ID where resources are deployed"
}

# TODO: Add misconfigured resources here
# Examples to implement:
# - S3 bucket with public access
# - Security group allowing 0.0.0.0/0 on port 22
# - IAM role with overly permissive policies
# - Unencrypted EBS volumes
# - RDS instance without encryption
# - CloudTrail disabled
