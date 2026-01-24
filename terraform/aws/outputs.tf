output "deployment_region" {
  description = "AWS region where resources are deployed"
  value       = var.aws_region
}

output "project_name" {
  description = "Project name used for resource naming"
  value       = var.project_name
}

# Add specific resource outputs as you create them
# Examples:
# output "s3_bucket_name" {
#   description = "Name of the intentionally misconfigured S3 bucket"
#   value       = aws_s3_bucket.misconfigured_bucket.id
# }

# output "security_group_id" {
#   description = "ID of the overly permissive security group"
#   value       = aws_security_group.permissive_sg.id
# }
