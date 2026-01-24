variable "aws_region" {
  description = "AWS region for deploying test resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cloud-security-posture"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "security-testing"
}

variable "owner_email" {
  description = "Email of the resource owner (for tagging)"
  type        = string
  default     = "" # Add your email here
}

# Add more variables as needed for your misconfigurations
