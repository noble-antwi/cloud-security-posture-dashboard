#!/usr/bin/env python3
"""
AWS Security Findings Remediation Engine

This script automatically remediates security findings detected by Prowler.
It reads the aggregated findings JSON and applies the appropriate fix for each
supported finding type using AWS CLI commands.

HOW IT WORKS:
=============
1. Load findings from the aggregated JSON file
2. Group findings by type (finding_id)
3. For each finding, look up the remediation function in REMEDIATION_MAP
4. Execute the AWS CLI command to fix the issue
5. Log success/failure for each remediation

SAFETY FEATURES:
================
- DRY RUN MODE (default): Shows what would be done without making changes
- Confirmation prompt before applying changes
- Detailed logging of all actions
- Error handling for each remediation

USAGE:
======
    # Dry run (see what would be fixed, no changes made)
    python remediate.py

    # Actually apply fixes
    python remediate.py --apply

    # Fix specific finding types only
    python remediate.py --apply --finding-type s3_bucket_default_encryption

    # Fix specific resource only
    python remediate.py --apply --resource my-bucket-name

Author: Cloud Security Dashboard Project
"""

import json
import subprocess
import argparse
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Callable, Optional


# =============================================================================
# REMEDIATION FUNCTIONS
# =============================================================================
# Each function takes a finding dict and returns (success: bool, message: str)
# These functions contain the actual AWS CLI commands that fix the issues.
# =============================================================================

def fix_s3_default_encryption(finding: Dict, dry_run: bool = True) -> tuple:
    """
    Enable default AES-256 encryption on an S3 bucket.

    What this fixes:
    - s3_bucket_default_encryption
    - s3_bucket_server_side_encryption_enabled

    AWS CLI command:
    aws s3api put-bucket-encryption --bucket BUCKET_NAME \
        --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
    """
    bucket_name = finding.get('resource')

    if not bucket_name or bucket_name == finding.get('account_id'):
        return False, "Cannot determine bucket name from finding"

    # The AWS CLI command to enable encryption
    encryption_config = {
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }

    command = [
        "aws", "s3api", "put-bucket-encryption",
        "--bucket", bucket_name,
        "--server-side-encryption-configuration", json.dumps(encryption_config)
    ]

    if dry_run:
        return True, f"[DRY RUN] Would enable AES-256 encryption on bucket: {bucket_name}"

    # Execute the command
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        return True, f"Successfully enabled encryption on bucket: {bucket_name}"
    else:
        return False, f"Failed to enable encryption on {bucket_name}: {result.stderr}"


def fix_s3_public_access_block(finding: Dict, dry_run: bool = True) -> tuple:
    """
    Block all public access to an S3 bucket.

    What this fixes:
    - s3_bucket_public_access
    - s3_bucket_level_public_access_block
    - s3_bucket_policy_public_write_access
    - s3_bucket_acl_prohibited

    AWS CLI command:
    aws s3api put-public-access-block --bucket BUCKET_NAME \
        --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
    """
    bucket_name = finding.get('resource')

    if not bucket_name or bucket_name == finding.get('account_id'):
        return False, "Cannot determine bucket name from finding"

    command = [
        "aws", "s3api", "put-public-access-block",
        "--bucket", bucket_name,
        "--public-access-block-configuration",
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ]

    if dry_run:
        return True, f"[DRY RUN] Would block public access on bucket: {bucket_name}"

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        return True, f"Successfully blocked public access on bucket: {bucket_name}"
    else:
        return False, f"Failed to block public access on {bucket_name}: {result.stderr}"


def fix_s3_versioning(finding: Dict, dry_run: bool = True) -> tuple:
    """
    Enable versioning on an S3 bucket.

    What this fixes:
    - s3_bucket_versioning_enabled

    AWS CLI command:
    aws s3api put-bucket-versioning --bucket BUCKET_NAME \
        --versioning-configuration Status=Enabled
    """
    bucket_name = finding.get('resource')

    if not bucket_name or bucket_name == finding.get('account_id'):
        return False, "Cannot determine bucket name from finding"

    command = [
        "aws", "s3api", "put-bucket-versioning",
        "--bucket", bucket_name,
        "--versioning-configuration", "Status=Enabled"
    ]

    if dry_run:
        return True, f"[DRY RUN] Would enable versioning on bucket: {bucket_name}"

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        return True, f"Successfully enabled versioning on bucket: {bucket_name}"
    else:
        return False, f"Failed to enable versioning on {bucket_name}: {result.stderr}"


def fix_s3_logging(finding: Dict, dry_run: bool = True) -> tuple:
    """
    Note: Enabling S3 logging requires a target bucket for logs.
    This remediation is marked as manual because it needs user input.

    What this fixes:
    - s3_bucket_logging_enabled
    """
    bucket_name = finding.get('resource')

    return False, f"[MANUAL] S3 logging for {bucket_name} requires a target bucket. " \
                  f"Run: aws s3api put-bucket-logging --bucket {bucket_name} " \
                  f"--bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"YOUR-LOG-BUCKET\",\"TargetPrefix\":\"{bucket_name}/\"}}}}'"


def fix_iam_access_analyzer(finding: Dict, dry_run: bool = True) -> tuple:
    """
    Enable IAM Access Analyzer in a region.

    What this fixes:
    - accessanalyzer_enabled

    AWS CLI command:
    aws accessanalyzer create-analyzer --analyzer-name security-analyzer --type ACCOUNT --region REGION
    """
    region = finding.get('region', 'us-east-1')
    analyzer_name = f"security-analyzer-{region}"

    command = [
        "aws", "accessanalyzer", "create-analyzer",
        "--analyzer-name", analyzer_name,
        "--type", "ACCOUNT",
        "--region", region
    ]

    if dry_run:
        return True, f"[DRY RUN] Would create IAM Access Analyzer in region: {region}"

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        return True, f"Successfully created IAM Access Analyzer in region: {region}"
    elif "ConflictException" in result.stderr:
        return True, f"IAM Access Analyzer already exists in region: {region}"
    else:
        return False, f"Failed to create IAM Access Analyzer in {region}: {result.stderr}"


def fix_account_level_public_access_block(finding: Dict, dry_run: bool = True) -> tuple:
    """
    Enable S3 Block Public Access at the account level.

    What this fixes:
    - s3_account_level_public_access_blocks

    AWS CLI command:
    aws s3control put-public-access-block --account-id ACCOUNT_ID \
        --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
    """
    account_id = finding.get('account_id')

    if not account_id:
        return False, "Cannot determine account ID from finding"

    command = [
        "aws", "s3control", "put-public-access-block",
        "--account-id", account_id,
        "--public-access-block-configuration",
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ]

    if dry_run:
        return True, f"[DRY RUN] Would enable account-level S3 public access block for account: {account_id}"

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        return True, f"Successfully enabled account-level S3 public access block"
    else:
        return False, f"Failed to enable account-level public access block: {result.stderr}"


# =============================================================================
# REMEDIATION MAP
# =============================================================================
# Maps Prowler finding IDs to their remediation functions.
# If a finding ID is not in this map, it will be skipped (no auto-remediation).
# =============================================================================

REMEDIATION_MAP: Dict[str, Callable] = {
    # S3 Encryption findings
    "s3_bucket_default_encryption": fix_s3_default_encryption,
    "s3_bucket_server_side_encryption_enabled": fix_s3_default_encryption,

    # S3 Public Access findings
    "s3_bucket_public_access": fix_s3_public_access_block,
    "s3_bucket_level_public_access_block": fix_s3_public_access_block,
    "s3_bucket_policy_public_write_access": fix_s3_public_access_block,
    "s3_bucket_acl_prohibited": fix_s3_public_access_block,
    "s3_bucket_no_mfa_delete": fix_s3_versioning,  # MFA delete requires versioning first

    # S3 Versioning findings
    "s3_bucket_versioning_enabled": fix_s3_versioning,

    # S3 Logging (manual)
    "s3_bucket_logging_enabled": fix_s3_logging,

    # IAM Access Analyzer
    "accessanalyzer_enabled": fix_iam_access_analyzer,

    # Account-level S3 settings
    "s3_account_level_public_access_blocks": fix_account_level_public_access_block,
}


# =============================================================================
# MAIN REMEDIATION ENGINE
# =============================================================================

class RemediationEngine:
    """
    Main engine that orchestrates the remediation process.

    Workflow:
    1. Load findings from JSON file
    2. Filter findings based on user options
    3. Apply remediations (or show dry run)
    4. Generate summary report
    """

    def __init__(self, findings_dir: Path, dry_run: bool = True):
        self.findings_dir = findings_dir
        self.dry_run = dry_run
        self.results = {
            "fixed": [],
            "failed": [],
            "skipped": [],
            "manual": []
        }

    def load_latest_findings(self) -> List[Dict]:
        """Load the most recent aggregated findings JSON file."""
        json_files = list(self.findings_dir.glob("aggregated_findings_*.json"))

        if not json_files:
            raise FileNotFoundError(f"No aggregated findings found in {self.findings_dir}")

        # Get the most recent file
        latest_file = max(json_files, key=os.path.getctime)
        print(f"Loading findings from: {latest_file.name}")

        with open(latest_file, 'r') as f:
            return json.load(f)

    def filter_findings(self, findings: List[Dict],
                       finding_type: Optional[str] = None,
                       resource: Optional[str] = None,
                       severity: Optional[str] = None) -> List[Dict]:
        """Filter findings based on user criteria."""
        filtered = findings

        if finding_type:
            filtered = [f for f in filtered if f.get('finding_id') == finding_type]

        if resource:
            filtered = [f for f in filtered if f.get('resource') == resource]

        if severity:
            filtered = [f for f in filtered if f.get('severity', '').lower() == severity.lower()]

        return filtered

    def remediate_finding(self, finding: Dict) -> None:
        """Attempt to remediate a single finding."""
        finding_id = finding.get('finding_id', 'unknown')
        resource = finding.get('resource', 'unknown')

        # Check if we have a remediation for this finding type
        if finding_id not in REMEDIATION_MAP:
            self.results["skipped"].append({
                "finding_id": finding_id,
                "resource": resource,
                "reason": "No automated remediation available"
            })
            return

        # Get the remediation function and execute it
        remediation_func = REMEDIATION_MAP[finding_id]
        success, message = remediation_func(finding, dry_run=self.dry_run)

        if "[MANUAL]" in message:
            self.results["manual"].append({
                "finding_id": finding_id,
                "resource": resource,
                "message": message
            })
        elif success:
            self.results["fixed"].append({
                "finding_id": finding_id,
                "resource": resource,
                "message": message
            })
        else:
            self.results["failed"].append({
                "finding_id": finding_id,
                "resource": resource,
                "message": message
            })

        # Print status
        status_icon = "✓" if success else "✗"
        print(f"  {status_icon} [{finding_id}] {resource}: {message}")

    def run(self, finding_type: Optional[str] = None,
            resource: Optional[str] = None,
            severity: Optional[str] = None) -> Dict:
        """
        Run the remediation process.

        Args:
            finding_type: Only remediate this specific finding type
            resource: Only remediate this specific resource
            severity: Only remediate findings of this severity

        Returns:
            Summary dict with counts of fixed, failed, skipped
        """
        print("\n" + "="*60)
        print("AWS SECURITY FINDINGS REMEDIATION ENGINE")
        print("="*60)

        if self.dry_run:
            print("\n⚠️  DRY RUN MODE - No changes will be made")
            print("   Run with --apply to actually fix issues\n")
        else:
            print("\n🔧 APPLY MODE - Changes WILL be made to your AWS account\n")

        # Load findings
        try:
            findings = self.load_latest_findings()
        except FileNotFoundError as e:
            print(f"Error: {e}")
            return self.results

        # Filter findings
        findings = self.filter_findings(findings, finding_type, resource, severity)

        if not findings:
            print("No findings match the specified criteria.")
            return self.results

        print(f"Found {len(findings)} findings to process\n")

        # Deduplicate findings (same finding_id + resource should only be fixed once)
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f.get('finding_id'), f.get('resource'))
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        print(f"Processing {len(unique_findings)} unique findings...\n")

        # Process each finding
        for finding in unique_findings:
            self.remediate_finding(finding)

        # Print summary
        self._print_summary()

        return self.results

    def _print_summary(self) -> None:
        """Print a summary of the remediation results."""
        print("\n" + "="*60)
        print("REMEDIATION SUMMARY")
        print("="*60)

        print(f"\n✓ Fixed:   {len(self.results['fixed'])}")
        print(f"✗ Failed:  {len(self.results['failed'])}")
        print(f"⏭ Skipped: {len(self.results['skipped'])} (no auto-remediation available)")
        print(f"📋 Manual: {len(self.results['manual'])} (requires manual intervention)")

        if self.results['manual']:
            print("\n📋 MANUAL REMEDIATION REQUIRED:")
            print("-" * 40)
            for item in self.results['manual']:
                print(f"  • {item['message']}")

        if self.results['failed']:
            print("\n❌ FAILED REMEDIATIONS:")
            print("-" * 40)
            for item in self.results['failed']:
                print(f"  • [{item['finding_id']}] {item['resource']}")
                print(f"    {item['message']}")

        if self.dry_run and self.results['fixed']:
            print("\n💡 To apply these fixes, run:")
            print("   python remediate.py --apply")


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Remediate AWS security findings detected by Prowler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python remediate.py                              # Dry run - see what would be fixed
  python remediate.py --apply                      # Actually apply all fixes
  python remediate.py --apply --severity Critical  # Fix only Critical findings
  python remediate.py --finding-type s3_bucket_default_encryption  # Fix specific type
  python remediate.py --resource my-bucket-name    # Fix specific resource
        """
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually apply remediations (default is dry run)"
    )

    parser.add_argument(
        "--finding-type",
        type=str,
        help="Only remediate this specific finding type (e.g., s3_bucket_default_encryption)"
    )

    parser.add_argument(
        "--resource",
        type=str,
        help="Only remediate this specific resource"
    )

    parser.add_argument(
        "--severity",
        type=str,
        choices=["Critical", "High", "Medium", "Low", "Informational"],
        help="Only remediate findings of this severity"
    )

    parser.add_argument(
        "--findings-dir",
        type=str,
        default=None,
        help="Path to aggregated findings directory"
    )

    args = parser.parse_args()

    # Determine findings directory
    if args.findings_dir:
        findings_dir = Path(args.findings_dir)
    else:
        # Default: look relative to this script's location
        script_dir = Path(__file__).parent.parent.parent
        findings_dir = script_dir / "scan-results" / "aggregated"

    if not findings_dir.exists():
        print(f"Error: Findings directory not found: {findings_dir}")
        print("Run the aggregator first: python scripts/scanning/aggregate_findings.py")
        return 1

    # Confirmation prompt for apply mode
    if args.apply:
        print("\n⚠️  WARNING: You are about to modify AWS resources!")
        response = input("Type 'yes' to continue: ")
        if response.lower() != 'yes':
            print("Aborted.")
            return 0

    # Run remediation
    engine = RemediationEngine(
        findings_dir=findings_dir,
        dry_run=not args.apply
    )

    engine.run(
        finding_type=args.finding_type,
        resource=args.resource,
        severity=args.severity
    )

    return 0


if __name__ == "__main__":
    exit(main())
