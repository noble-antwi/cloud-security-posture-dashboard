# Usage Guide

This guide explains the complete workflow for using the Cloud Security Posture Dashboard.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Understanding the Workflow](#understanding-the-workflow)
3. [Step 1: Deploy Test Infrastructure](#step-1-deploy-test-infrastructure)
4. [Step 2: Run Security Scans](#step-2-run-security-scans)
5. [Step 3: Aggregate Findings](#step-3-aggregate-findings)
6. [Step 4: Launch Dashboard](#step-4-launch-dashboard)
7. [Multi-Account Scanning](#multi-account-scanning)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Scan your AWS accounts
./scripts/scanning/run_multi_account_scan.sh --profiles "homelab-mgmt,homelab-prod" --quick

# 2. Aggregate findings
python scripts/scanning/aggregate_findings.py

# 3. Launch dashboard
python dashboard/app.py

# 4. Open browser
# http://localhost:51000
```

---

## Understanding the Workflow

The project follows a pipeline architecture where each step depends on the previous:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              WORKFLOW PIPELINE                               │
└─────────────────────────────────────────────────────────────────────────────┘

   STEP 1              STEP 2              STEP 3              STEP 4
┌──────────┐      ┌──────────────┐     ┌─────────────┐     ┌────────────┐
│  DEPLOY  │ ───▶ │    SCAN      │ ───▶│  AGGREGATE  │ ───▶│ VISUALIZE  │
│(Optional)│      │              │     │             │     │            │
│Terraform │      │Prowler/Scout │     │Python Script│     │Flask + JS  │
└──────────┘      └──────────────┘     └─────────────┘     └────────────┘
     │                   │                    │                   │
     ▼                   ▼                    ▼                   ▼
  Creates           Connects to         Reads raw JSON      Reads unified
  insecure          AWS/Azure,          from scanners,      JSON, displays
  resources         runs 500+           normalizes to       charts, filters,
  for testing       security checks     common format       remediation
```

### Why This Architecture?

| Step | Purpose | Can Skip? |
|------|---------|-----------|
| **Deploy** | Create intentionally insecure resources for testing | Yes (scan real accounts) |
| **Scan** | Collect security findings from cloud accounts | No (required) |
| **Aggregate** | Normalize data from multiple tools into one format | No (required) |
| **Visualize** | Display findings with filters and remediation | No (required) |

### Separation of Concerns

- **Scans are expensive** - They make API calls and take 10-30 minutes
- **Aggregation is cheap** - Just processes local files (seconds)
- **You can re-aggregate without re-scanning** - Useful when updating the aggregator logic
- **Different schedules** - Run daily scans, aggregate on-demand

---

## Step 1: Deploy Test Infrastructure

> **Optional**: Skip this step if you want to scan your real AWS/Azure accounts.

### AWS Test Resources

```bash
cd terraform/aws
terraform init
terraform apply
```

This creates intentionally misconfigured S3 buckets:
- `insecure_bucket` - No encryption, no versioning
- `public_read_bucket` - Public read access
- `website_bucket` - Static website hosting enabled
- `cross_account_bucket` - Overly permissive bucket policy

### Azure Test Resources

```bash
cd terraform/azure
terraform init
terraform apply
```

This creates intentionally misconfigured Azure resources:
- Storage account without secure transfer
- Network Security Group with open ports
- Key Vault with public access

### Cleanup After Testing

**Important**: Always destroy test resources when done.

```bash
cd terraform/aws && terraform destroy
cd terraform/azure && terraform destroy
```

---

## Step 2: Run Security Scans

### Option A: Using the Multi-Account Script (Recommended)

The script handles everything automatically:

```bash
# Scan multiple AWS accounts
./scripts/scanning/run_multi_account_scan.sh --profiles "homelab-mgmt,homelab-prod"

# Quick scan (S3 only, faster for testing)
./scripts/scanning/run_multi_account_scan.sh --profiles "homelab-mgmt" --quick

# Scan specific service
./scripts/scanning/run_multi_account_scan.sh --profiles "homelab-mgmt" --service iam
```

**What the script does:**
1. Loops through each AWS profile
2. Sets the correct `AWS_PROFILE` environment variable
3. Runs Prowler with appropriate flags
4. Organizes output into `output/{account_id}/` folders

### Option B: Manual Scanning

**AWS with Prowler:**
```bash
# Full scan (all services, 10-30 min)
prowler aws

# S3 only (faster, ~2 min)
prowler aws --service s3

# Specific profile
AWS_PROFILE=homelab-prod prowler aws --service s3
```

**Azure with ScoutSuite:**
```bash
# Login to Azure first
az login

# Run ScoutSuite
scout azure --cli
```

### Scan Output Location

| Scanner | Output Directory | File Pattern |
|---------|-----------------|--------------|
| Prowler | `output/` | `prowler-output-{account}-{timestamp}.json` |
| ScoutSuite | `scoutsuite-report/` | `scoutsuite_results_azure-*.js` |

---

## Step 3: Aggregate Findings

The aggregator processes raw scanner output and creates a unified format:

```bash
python scripts/scanning/aggregate_findings.py
```

### What It Does

1. **Reads Prowler JSON** - Parses AWS security findings
2. **Reads ScoutSuite JS** - Parses Azure security findings
3. **Normalizes Data** - Converts to common schema
4. **Extracts Remediation** - Structures CLI, Terraform, Console options
5. **Generates Summary** - Counts by severity, provider, account
6. **Exports Results** - Saves to `scan-results/aggregated/`

### Output Files

```
scan-results/aggregated/
├── aggregated_findings_YYYYMMDD_HHMMSS.json   # All findings
├── aggregated_findings_YYYYMMDD_HHMMSS.csv    # CSV export
└── findings_summary_YYYYMMDD_HHMMSS.json      # Statistics
```

### Sample Output

```
==================================================
FINDINGS SUMMARY
==================================================

Total Findings: 506

By Severity:
  Low: 60
  Medium: 405
  High: 41

By Cloud Provider:
  AWS: 479
  Azure: 27

By Account:
  625439398171: 479
  123456789012: 27

==================================================
```

---

## Step 4: Launch Dashboard

```bash
python dashboard/app.py
```

Open **http://localhost:51000** in your browser.

### Dashboard Features

| Page | Description |
|------|-------------|
| **Home** | Summary cards, severity chart, provider chart |
| **All Findings** | Searchable table with filters |

### Filters Available

- **Search** - Text search across title, resource, issue
- **Severity** - Critical, High, Medium, Low
- **Provider** - AWS, Azure, GCP
- **Account** - Filter by AWS account ID

### Remediation Options

Each finding shows multiple remediation approaches:

| Tab | Description |
|-----|-------------|
| **AWS CLI** | Copy-paste commands |
| **Terraform** | Infrastructure as Code |
| **CloudFormation** | AWS native IaC |
| **Console** | Step-by-step manual instructions |
| **Documentation** | Link to official docs |

---

## Multi-Account Scanning

### Setting Up AWS Profiles

Edit `~/.aws/credentials`:

```ini
[homelab-mgmt]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
region = us-east-1

[homelab-prod]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
region = us-east-1

[homelab-dev]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
region = us-west-2
```

### Running Multi-Account Scans

```bash
# Scan all profiles
./scripts/scanning/run_multi_account_scan.sh --profiles "homelab-mgmt,homelab-prod,homelab-dev"

# Quick scan for testing
./scripts/scanning/run_multi_account_scan.sh --profiles "homelab-mgmt,homelab-prod" --quick
```

### Directory Structure After Multi-Account Scan

```
output/
├── 625439398171/                    # Account 1
│   └── prowler-output-*.json
├── 123456789012/                    # Account 2
│   └── prowler-output-*.json
└── 987654321098/                    # Account 3
    └── prowler-output-*.json
```

The aggregator automatically detects this structure and processes all accounts.

---

## Troubleshooting

### "No aggregated findings files found"

**Cause**: Aggregator hasn't been run yet.

**Solution**:
```bash
python scripts/scanning/aggregate_findings.py
```

### "No Prowler files found"

**Cause**: No scan has been run yet.

**Solution**:
```bash
./scripts/scanning/run_multi_account_scan.sh --profiles "your-profile" --quick
```

### Dashboard shows 0 findings

**Cause**: Scan found no failures (everything passed).

**Solution**: This is actually good! Your accounts are secure. To test the dashboard, deploy the test infrastructure.

### Profile not found

**Cause**: AWS profile not configured.

**Solution**: Add profile to `~/.aws/credentials`:
```ini
[your-profile]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

### Permission errors during scan

**Cause**: IAM user lacks required permissions.

**Solution**: Attach the `SecurityAudit` AWS managed policy to your IAM user.

---

## Next Steps

After completing the basic workflow:

1. **Schedule Regular Scans** - Use cron to run scans daily
2. **Add More Accounts** - Expand to all your AWS accounts
3. **Review Findings** - Prioritize Critical and High severity
4. **Apply Remediations** - Use the guidance to fix issues
5. **Track Progress** - Compare findings over time

---

## Command Reference

| Command | Description |
|---------|-------------|
| `./scripts/scanning/run_multi_account_scan.sh --profiles "a,b"` | Scan multiple accounts |
| `./scripts/scanning/run_multi_account_scan.sh --quick` | Quick S3-only scan |
| `python scripts/scanning/aggregate_findings.py` | Process scan results |
| `python dashboard/app.py` | Launch web dashboard |
| `prowler aws --service s3` | Manual Prowler scan |
| `scout azure --cli` | Manual ScoutSuite scan |
