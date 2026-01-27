#!/usr/bin/env python3
"""
Aggregate Security Findings from Prowler and ScoutSuite

This script:
1. Reads JSON output from Prowler (AWS) and ScoutSuite (Azure)
2. Normalizes findings into a common format
3. Categorizes by severity (Critical, High, Medium, Low)
4. Exports aggregated data for dashboard consumption

HOW IT WORKS:
-------------
1. Prowler outputs JSON files to the 'output/' directory
2. This script reads those JSON files
3. Each finding is "normalized" to a common format so we can compare
   AWS findings with Azure findings using the same fields
4. Results are exported to JSON/CSV for the dashboard to consume
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# pandas is used for data manipulation and CSV export
# If not installed: pip install pandas
try:
    import pandas as pd
except ImportError:
    print("Warning: pandas not installed. CSV export will be disabled.")
    pd = None


class FindingsAggregator:
    """Aggregate and normalize security findings from multiple sources"""
    
    def __init__(self, prowler_dir: str, scoutsuite_dir: str, output_dir: str):
        self.prowler_dir = Path(prowler_dir)
        self.scoutsuite_dir = Path(scoutsuite_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings = []
    
    def load_prowler_findings(self) -> List[Dict]:
        """
        Load and parse Prowler JSON results.

        Prowler v3.x outputs a JSON file that is a LIST of findings.
        Each finding has fields like:
        - Status: "PASS" or "FAIL"
        - Severity: "critical", "high", "medium", "low"
        - CheckID: The check identifier (e.g., "s3_bucket_versioning")
        - CheckTitle: Human-readable title
        - ResourceId: The AWS resource being checked
        - StatusExtended: Detailed explanation of the issue
        """
        print("Loading Prowler findings...")

        # Prowler outputs files with pattern: prowler-output-ACCOUNTID-TIMESTAMP.json
        # We look for .json files but exclude .ocsf.json (different format)
        prowler_files = [
            f for f in self.prowler_dir.glob("prowler-output-*.json")
            if not f.name.endswith('.ocsf.json')
        ]

        if not prowler_files:
            print(f"No Prowler results found in {self.prowler_dir}")
            return []

        # Get the most recently created file
        latest_file = max(prowler_files, key=os.path.getctime)
        print(f"Reading: {latest_file}")

        # Load the JSON file
        with open(latest_file, 'r') as f:
            prowler_data = json.load(f)

        # Prowler v3.x outputs a list of finding objects
        # We only care about FAILED checks (those are the security issues)
        findings = []

        for check in prowler_data:
            # Only include findings that FAILED (not PASS)
            if check.get('Status') == 'FAIL':
                # Normalize each finding to our common format
                normalized = self._normalize_prowler_finding(check)
                findings.append(normalized)

        print(f"Loaded {len(findings)} Prowler findings (failures only)")
        return findings
    
    def load_scoutsuite_findings(self) -> List[Dict]:
        """
        Load and parse ScoutSuite JSON results.

        ScoutSuite outputs a JavaScript file with structure:
        scoutsuite_results = { ... JSON data ... }

        The JSON contains:
        - services: dict of services (storageaccounts, network, keyvault, etc.)
        - Each service has 'findings' dict with flagged security issues
        """
        print("Loading ScoutSuite findings...")

        # ScoutSuite outputs to: scoutsuite-report/scoutsuite-results/scoutsuite_results_azure-tenant-XXX.js
        results_dir = self.scoutsuite_dir / "scoutsuite-results"

        if not results_dir.exists():
            print(f"ScoutSuite results directory not found: {results_dir}")
            return []

        # Find the results file (pattern: scoutsuite_results_azure-*.js)
        result_files = list(results_dir.glob("scoutsuite_results_azure-*.js"))

        if not result_files:
            print("No ScoutSuite Azure results found")
            return []

        # Get the most recent file
        latest_file = max(result_files, key=os.path.getctime)
        print(f"Reading: {latest_file}")

        # Read and parse the JavaScript file
        try:
            with open(latest_file, 'r') as f:
                content = f.read()

            # Remove the JavaScript variable assignment to get pure JSON
            # File starts with: scoutsuite_results =\n{...} or scoutsuite_results = {...}
            if 'scoutsuite_results =' in content:
                json_str = content.split('scoutsuite_results =', 1)[1].strip()
                if json_str.startswith('\n'):
                    json_str = json_str[1:]
                scout_data = json.loads(json_str)
            else:
                print("Could not find scoutsuite_results in file")
                return []

        except json.JSONDecodeError as e:
            print(f"Error parsing ScoutSuite JSON: {e}")
            return []

        # Extract findings from services
        findings = []
        services = scout_data.get('services', {})

        for service_name, service_data in services.items():
            service_findings = service_data.get('findings', {})

            for finding_id, finding_data in service_findings.items():
                # Only include findings with flagged items (actual issues)
                flagged_items = finding_data.get('flagged_items', 0)
                if flagged_items > 0:
                    # Get the actual affected resources
                    items = finding_data.get('items', [])

                    # If no items list, create one entry for the finding itself
                    if not items:
                        normalized = self._normalize_scoutsuite_finding(
                            finding_id, finding_data, service_name, None
                        )
                        findings.append(normalized)
                    else:
                        # Create a finding entry for each affected resource
                        for item_id in items:
                            normalized = self._normalize_scoutsuite_finding(
                                finding_id, finding_data, service_name, item_id
                            )
                            findings.append(normalized)

        print(f"Loaded {len(findings)} ScoutSuite findings")
        return findings
    
    def _normalize_prowler_finding(self, check: Dict) -> Dict:
        """
        Normalize Prowler finding to our common format.

        WHY NORMALIZE?
        Different tools (Prowler, ScoutSuite, etc.) output different JSON structures.
        By normalizing to a common format, our dashboard can display findings
        from ANY tool using the same code.

        Common format fields:
        - source: Which tool found this (Prowler, ScoutSuite)
        - cloud_provider: AWS, Azure, GCP
        - finding_id: Unique identifier for the check
        - title: Human-readable title
        - severity: Critical, High, Medium, Low, Informational
        - status: PASS, FAIL
        - resource: The specific resource affected
        - region: AWS region or Azure location
        - description: What the check does
        - issue: What specifically is wrong (StatusExtended)
        - risk: Why this matters (security impact)
        - remediation: How to fix it
        - compliance: Which frameworks this maps to (CIS, NIST, etc.)
        """
        # Extract remediation info (it's nested in Prowler output)
        remediation_info = check.get('Remediation', {})
        remediation_text = ""
        if isinstance(remediation_info, dict):
            recommendation = remediation_info.get('Recommendation', {})
            if isinstance(recommendation, dict):
                remediation_text = recommendation.get('Text', '')
                remediation_url = recommendation.get('Url', '')
                if remediation_url:
                    remediation_text += f" See: {remediation_url}"
            # Also include CLI command if available
            code = remediation_info.get('Code', {})
            if isinstance(code, dict) and code.get('CLI'):
                remediation_text += f"\n\nCLI Fix: {code.get('CLI')}"

        return {
            'source': 'Prowler',
            'cloud_provider': 'AWS',
            'finding_id': check.get('CheckID', 'unknown'),
            'title': check.get('CheckTitle', ''),
            'severity': self._map_severity(check.get('Severity', 'medium')),
            'status': check.get('Status', 'UNKNOWN'),
            'resource': check.get('ResourceId', ''),
            'resource_arn': check.get('ResourceArn', ''),
            'region': check.get('Region', ''),
            'account_id': check.get('AccountId', ''),
            'description': check.get('Description', ''),
            'issue': check.get('StatusExtended', ''),  # The specific problem
            'risk': check.get('Risk', ''),  # Why this matters
            'remediation': remediation_text,
            'compliance': list(check.get('Compliance', {}).keys()),  # CIS, NIST, etc.
            'timestamp': datetime.now().isoformat()
        }
    
    def _normalize_scoutsuite_finding(self, finding_id: str, finding_data: Dict,
                                        service_name: str, item_id: Optional[str]) -> Dict:
        """
        Normalize ScoutSuite finding to common format.

        ScoutSuite finding structure:
        - description: What the check does
        - rationale: Why this matters (risk)
        - remediation: How to fix it
        - level: danger, warning, info
        - flagged_items: Count of affected resources
        - items: List of affected resource IDs

        Args:
            finding_id: The check identifier (e.g., "storageaccount-public-traffic-allowed")
            finding_data: The finding details dict
            service_name: Azure service (storageaccounts, network, keyvault, etc.)
            item_id: Specific resource ID (if applicable)
        """
        # Map ScoutSuite severity levels to our standard format
        level = finding_data.get('level', 'warning')
        severity_map = {
            'danger': 'High',
            'warning': 'Medium',
            'info': 'Low'
        }
        severity = severity_map.get(level, 'Medium')

        # Extract resource name from item_id if available
        # item_id format varies: "subscriptions.XXX.resource_groups.XXX.providers.XXX.resource_name"
        resource = item_id if item_id else f"{service_name} (multiple resources)"
        if item_id and '.' in item_id:
            # Try to get the last meaningful part as resource name
            parts = item_id.split('.')
            resource = parts[-1] if parts else item_id

        return {
            'source': 'ScoutSuite',
            'cloud_provider': 'Azure',
            'finding_id': finding_id,
            'title': finding_data.get('description', finding_id),
            'severity': severity,
            'status': 'FAIL',
            'resource': resource,
            'resource_arn': item_id or '',  # Full resource path
            'region': 'global',  # Azure doesn't always have region in findings
            'account_id': '',  # Will be populated from subscription if available
            'description': finding_data.get('description', ''),
            'issue': f"{finding_data.get('description', '')} - {finding_data.get('flagged_items', 0)} resource(s) affected",
            'risk': finding_data.get('rationale', ''),
            'remediation': finding_data.get('remediation', ''),
            'compliance': finding_data.get('references', []),  # Compliance references if available
            'timestamp': datetime.now().isoformat()
        }
    
    def _map_severity(self, severity: str) -> str:
        """Map various severity formats to standardized levels"""
        severity_upper = severity.upper()
        
        severity_mapping = {
            'CRITICAL': 'Critical',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFO': 'Informational',
            'INFORMATIONAL': 'Informational'
        }
        
        return severity_mapping.get(severity_upper, 'Medium')
    
    def aggregate_findings(self):
        """Aggregate findings from all sources"""
        print("\n" + "="*50)
        print("Aggregating Security Findings")
        print("="*50 + "\n")
        
        prowler_findings = self.load_prowler_findings()
        scoutsuite_findings = self.load_scoutsuite_findings()
        
        self.findings = prowler_findings + scoutsuite_findings
        
        print(f"\nTotal findings aggregated: {len(self.findings)}")
    
    def generate_summary(self) -> Dict:
        """
        Generate summary statistics from findings.

        This creates a summary that the dashboard can use to show:
        - Total number of issues
        - Breakdown by severity (how many Critical vs High vs Medium)
        - Breakdown by cloud provider (AWS vs Azure)
        - Breakdown by source tool (Prowler vs ScoutSuite)
        """
        if not self.findings:
            return {
                'total_findings': 0,
                'by_severity': {},
                'by_cloud_provider': {},
                'by_source': {},
                'timestamp': datetime.now().isoformat()
            }

        # Count findings by different categories
        # We do this manually so we don't depend on pandas for the summary
        by_severity = {}
        by_cloud_provider = {}
        by_source = {}

        for finding in self.findings:
            # Count by severity
            sev = finding.get('severity', 'Unknown')
            by_severity[sev] = by_severity.get(sev, 0) + 1

            # Count by cloud provider
            provider = finding.get('cloud_provider', 'Unknown')
            by_cloud_provider[provider] = by_cloud_provider.get(provider, 0) + 1

            # Count by source tool
            source = finding.get('source', 'Unknown')
            by_source[source] = by_source.get(source, 0) + 1

        summary = {
            'total_findings': len(self.findings),
            'by_severity': by_severity,
            'by_cloud_provider': by_cloud_provider,
            'by_source': by_source,
            'timestamp': datetime.now().isoformat()
        }

        return summary
    
    def export_results(self):
        """
        Export aggregated findings to various formats.

        Outputs:
        1. JSON file - Full findings data for the dashboard
        2. CSV file - For spreadsheet analysis (requires pandas)
        3. Summary JSON - Quick stats for dashboard widgets
        """
        print("\nExporting results...")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export to JSON (always works - no dependencies)
        json_file = self.output_dir / f"aggregated_findings_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        print(f"JSON exported: {json_file}")

        # Export to CSV (requires pandas)
        if self.findings and pd is not None:
            csv_file = self.output_dir / f"aggregated_findings_{timestamp}.csv"
            df = pd.DataFrame(self.findings)
            df.to_csv(csv_file, index=False)
            print(f"CSV exported: {csv_file}")
        elif self.findings and pd is None:
            print("CSV export skipped (pandas not installed)")

        # Export summary
        summary = self.generate_summary()
        summary_file = self.output_dir / f"findings_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"Summary exported: {summary_file}")

        # Print summary to console
        self._print_summary(summary)
    
    def _print_summary(self, summary: Dict):
        """Print findings summary to console"""
        print("\n" + "="*50)
        print("FINDINGS SUMMARY")
        print("="*50)
        
        print(f"\nTotal Findings: {summary.get('total_findings', 0)}")
        
        print("\nBy Severity:")
        for severity, count in summary.get('by_severity', {}).items():
            print(f"  {severity}: {count}")
        
        print("\nBy Cloud Provider:")
        for provider, count in summary.get('by_cloud_provider', {}).items():
            print(f"  {provider}: {count}")
        
        print("\n" + "="*50)


def main():
    """
    Main execution function.

    This script can be run from anywhere - it automatically finds the
    project root directory and locates the scan results.
    """
    # Find the project root (where this script lives)
    # We go up two levels: scripts/scanning/ -> scripts/ -> project_root/
    script_dir = Path(__file__).parent.absolute()
    project_root = script_dir.parent.parent

    # Configuration - paths relative to project root
    # Prowler outputs to: output/ (its default)
    # ScoutSuite outputs to: scoutsuite-report/ (its default)
    # We'll output aggregated results to: scan-results/aggregated/
    PROWLER_DIR = project_root / "output"
    SCOUTSUITE_DIR = project_root / "scoutsuite-report"
    OUTPUT_DIR = project_root / "scan-results" / "aggregated"

    print(f"Project root: {project_root}")
    print(f"Looking for Prowler results in: {PROWLER_DIR}")
    print(f"Looking for ScoutSuite results in: {SCOUTSUITE_DIR}")
    print(f"Output will be saved to: {OUTPUT_DIR}")

    # Initialize aggregator
    aggregator = FindingsAggregator(
        prowler_dir=str(PROWLER_DIR),
        scoutsuite_dir=str(SCOUTSUITE_DIR),
        output_dir=str(OUTPUT_DIR)
    )

    # Run aggregation
    aggregator.aggregate_findings()
    aggregator.export_results()

    print("\nAggregation complete!")
    print("Next step: Launch the dashboard to visualize findings")


if __name__ == "__main__":
    main()
