# AWS Infrastructure with Intentional Misconfigurations for Security Testing
# WARNING: This infrastructure is intentionally insecure. Do NOT use in production.

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
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

# =============================================================================
# MISCONFIGURATION #1: S3 Bucket Without Security Best Practices
# =============================================================================
#
# WHAT'S WRONG WITH THIS BUCKET:
# 1. No server-side encryption - data stored in plain text
# 2. No versioning - if files are deleted, they're gone forever
# 3. No access logging - we can't see who accessed the bucket
# 4. Public access not explicitly blocked (we'll configure this separately)
#
# WHAT PROWLER WILL DETECT:
# - s3_bucket_default_encryption - "S3 Bucket does not have default encryption"
# - s3_bucket_versioning - "S3 Bucket has versioning disabled"
# - s3_bucket_public_access - various public access findings
# =============================================================================

# Generate a random suffix to make bucket name unique globally
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# The misconfigured S3 bucket
resource "aws_s3_bucket" "insecure_bucket" {
  # Bucket names must be globally unique across ALL of AWS
  # We add random characters to ensure uniqueness
  bucket = "security-test-${var.environment}-${random_id.bucket_suffix.hex}"

  # Tags help identify what this resource is for
  tags = {
    Name            = "Intentionally Insecure Bucket"
    SecurityStatus  = "Misconfigured"
    TestingPurpose  = "ProwlerDetection"
  }
}

# MISCONFIGURATION: Disable the "Block Public Access" settings
# In production, ALL of these should be TRUE to prevent data leaks
resource "aws_s3_bucket_public_access_block" "insecure_bucket_public_access" {
  bucket = aws_s3_bucket.insecure_bucket.id

  # Setting these to FALSE is DANGEROUS in production!
  # This allows the bucket to potentially be made public
  block_public_acls       = false  # Should be: true
  block_public_policy     = false  # Should be: true
  ignore_public_acls      = false  # Should be: true
  restrict_public_buckets = false  # Should be: true
}

# Output the bucket name so we can reference it later
output "insecure_bucket_name" {
  value       = aws_s3_bucket.insecure_bucket.id
  description = "Name of the intentionally misconfigured S3 bucket"
}

output "insecure_bucket_arn" {
  value       = aws_s3_bucket.insecure_bucket.arn
  description = "ARN of the intentionally misconfigured S3 bucket"
}

# =============================================================================
# MISCONFIGURATION #2: S3 Bucket with PUBLIC READ Policy
# =============================================================================
#
# WHAT'S WRONG:
# - Anyone on the internet can read all objects in this bucket
# - This is a common cause of data breaches (leaked customer data, credentials)
#
# REAL-WORLD EXAMPLES:
# - Capital One breach (2019) - 100M customer records exposed
# - Twitch leak (2021) - source code exposed via misconfigured S3
#
# WHAT PROWLER WILL DETECT:
# - s3_bucket_policy_public_write_access
# - s3_bucket_public_access
# =============================================================================

resource "aws_s3_bucket" "public_read_bucket" {
  bucket = "public-read-test-${random_id.bucket_suffix.hex}"

  tags = {
    Name            = "Public Read Bucket"
    SecurityStatus  = "Misconfigured"
    TestingPurpose  = "PublicAccessDetection"
  }
}

# Allow public access (DANGEROUS!)
resource "aws_s3_bucket_public_access_block" "public_read_bucket_access" {
  bucket = aws_s3_bucket.public_read_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# This policy allows ANYONE to read objects from the bucket
resource "aws_s3_bucket_policy" "public_read_policy" {
  bucket = aws_s3_bucket.public_read_bucket.id

  # Wait for public access block to be configured first
  depends_on = [aws_s3_bucket_public_access_block.public_read_bucket_access]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"              # DANGEROUS: "*" means ANYONE
        Action    = "s3:GetObject"   # Can read any object
        Resource  = "${aws_s3_bucket.public_read_bucket.arn}/*"
      }
    ]
  })
}

output "public_read_bucket_name" {
  value       = aws_s3_bucket.public_read_bucket.id
  description = "Bucket with public read access (intentionally insecure)"
}

# =============================================================================
# MISCONFIGURATION #3: S3 Bucket with Website Hosting (No HTTPS)
# =============================================================================
#
# WHAT'S WRONG:
# - Static website hosting uses HTTP only (not HTTPS)
# - Data transmitted in plain text can be intercepted
# - No encryption in transit
#
# WHAT PROWLER WILL DETECT:
# - s3_bucket_secure_transport_policy (no HTTPS enforcement)
# - s3_bucket_public_access
# =============================================================================

resource "aws_s3_bucket" "website_bucket" {
  bucket = "website-test-${random_id.bucket_suffix.hex}"

  tags = {
    Name            = "Website Hosting Bucket"
    SecurityStatus  = "Misconfigured"
    TestingPurpose  = "WebsiteSecurityDetection"
  }
}

resource "aws_s3_bucket_public_access_block" "website_bucket_access" {
  bucket = aws_s3_bucket.website_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Enable static website hosting
resource "aws_s3_bucket_website_configuration" "website_config" {
  bucket = aws_s3_bucket.website_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

output "website_bucket_name" {
  value       = aws_s3_bucket.website_bucket.id
  description = "Website hosting bucket (no HTTPS)"
}

output "website_endpoint" {
  value       = aws_s3_bucket_website_configuration.website_config.website_endpoint
  description = "Website URL (HTTP only - insecure)"
}

# =============================================================================
# MISCONFIGURATION #4: S3 Bucket with Overly Permissive Cross-Account Access
# =============================================================================
#
# WHAT'S WRONG:
# - Allows ANY AWS account to access the bucket
# - Should restrict to specific trusted accounts only
#
# WHAT PROWLER WILL DETECT:
# - s3_bucket_policy_public_write_access (overly permissive principal)
# =============================================================================

resource "aws_s3_bucket" "cross_account_bucket" {
  bucket = "cross-account-test-${random_id.bucket_suffix.hex}"

  tags = {
    Name            = "Cross Account Access Bucket"
    SecurityStatus  = "Misconfigured"
    TestingPurpose  = "CrossAccountDetection"
  }
}

resource "aws_s3_bucket_public_access_block" "cross_account_bucket_access" {
  bucket = aws_s3_bucket.cross_account_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Overly permissive policy - allows any authenticated AWS user
resource "aws_s3_bucket_policy" "cross_account_policy" {
  bucket = aws_s3_bucket.cross_account_bucket.id

  depends_on = [aws_s3_bucket_public_access_block.cross_account_bucket_access]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAnyAWSUser"
        Effect    = "Allow"
        # This allows ANY authenticated AWS user (any account!)
        Principal = { AWS = "*" }
        Action = [
          "s3:GetObject",
          "s3:PutObject",      # Can upload files!
          "s3:DeleteObject"    # Can delete files!
        ]
        Resource = "${aws_s3_bucket.cross_account_bucket.arn}/*"
      }
    ]
  })
}

output "cross_account_bucket_name" {
  value       = aws_s3_bucket.cross_account_bucket.id
  description = "Bucket with overly permissive cross-account access"
}

# =============================================================================
# SUMMARY OF MISCONFIGURATIONS
# =============================================================================
#
# Bucket 1: insecure_bucket
#   - No encryption
#   - No versioning
#   - No logging
#   - Public access block disabled
#
# Bucket 2: public_read_bucket
#   - Anyone on internet can read files
#   - Public bucket policy
#
# Bucket 3: website_bucket
#   - Static website hosting
#   - HTTP only (no HTTPS)
#
# Bucket 4: cross_account_bucket
#   - Any AWS user can read/write/delete
#   - Overly permissive IAM policy
#
# =============================================================================
