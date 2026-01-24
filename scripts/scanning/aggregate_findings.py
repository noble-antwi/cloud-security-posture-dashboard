#!/usr/bin/env python3
"""
Aggregate Security Findings from Prowler and ScoutSuite

This script:
1. Reads JSON output from Prowler (AWS) and ScoutSuite (Azure)
2. Normalizes findings into a common format
3. Categorizes by severity (Critical, High, Medium, Low)
4. Exports aggregated data for dashboard consumption
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import pandas as pd


class FindingsAggregator:
    """Aggregate and normalize security findings from multiple sources"""
    
    def __init__(self, prowler_dir: str, scoutsuite_dir: str, output_dir: str):
        self.prowler_dir = Path(prowler_dir)
        self.scoutsuite_dir = Path(scoutsuite_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings = []
    
    def load_prowler_findings(self) -> List[Dict]:
        """Load and parse Prowler JSON results"""
        print("Loading Prowler findings...")
        
        # Find the most recent Prowler JSON file
        prowler_files = list(self.prowler_dir.glob("prowler_scan_*.json"))
        
        if not prowler_files:
            print("No Prowler results found")
            return []
        
        latest_file = max(prowler_files, key=os.path.getctime)
        print(f"Reading: {latest_file}")
        
        with open(latest_file, 'r') as f:
            prowler_data = json.load(f)
        
        # TODO: Parse Prowler JSON structure and normalize
        # Prowler format varies by version - adjust parsing as needed
        findings = []
        
        # Example parsing (adjust based on actual Prowler output structure):
        # for check in prowler_data.get('checks', []):
        #     if check.get('Status') == 'FAIL':
        #         findings.append(self._normalize_prowler_finding(check))
        
        print(f"Loaded {len(findings)} Prowler findings")
        return findings
    
    def load_scoutsuite_findings(self) -> List[Dict]:
        """Load and parse ScoutSuite JSON results"""
        print("Loading ScoutSuite findings...")
        
        # Find ScoutSuite results directory
        scout_dirs = list(self.scoutsuite_dir.glob("azure_*"))
        
        if not scout_dirs:
            print("No ScoutSuite results found")
            return []
        
        latest_dir = max(scout_dirs, key=os.path.getctime)
        results_file = latest_dir / "scoutsuite-results" / "scoutsuite_results.js"
        
        if not results_file.exists():
            print(f"Results file not found: {results_file}")
            return []
        
        print(f"Reading: {results_file}")
        
        # TODO: Parse ScoutSuite results
        findings = []
        
        print(f"Loaded {len(findings)} ScoutSuite findings")
        return findings
    
    def _normalize_prowler_finding(self, check: Dict) -> Dict:
        """Normalize Prowler finding to common format"""
        return {
            'source': 'Prowler',
            'cloud_provider': 'AWS',
            'finding_id': check.get('CheckID', 'unknown'),
            'title': check.get('CheckTitle', ''),
            'severity': self._map_severity(check.get('Severity', 'Medium')),
            'status': check.get('Status', 'UNKNOWN'),
            'resource': check.get('ResourceId', ''),
            'region': check.get('Region', ''),
            'description': check.get('Description', ''),
            'remediation': check.get('Remediation', ''),
            'timestamp': datetime.now().isoformat()
        }
    
    def _normalize_scoutsuite_finding(self, finding: Dict) -> Dict:
        """Normalize ScoutSuite finding to common format"""
        return {
            'source': 'ScoutSuite',
            'cloud_provider': 'Azure',
            'finding_id': finding.get('id', 'unknown'),
            'title': finding.get('description', ''),
            'severity': finding.get('level', 'warning'),
            'status': 'FAIL',
            'resource': finding.get('resource', ''),
            'region': finding.get('region', 'global'),
            'description': finding.get('rationale', ''),
            'remediation': finding.get('remediation', ''),
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
        """Generate summary statistics"""
        if not self.findings:
            return {}
        
        df = pd.DataFrame(self.findings)
        
        summary = {
            'total_findings': len(self.findings),
            'by_severity': df['severity'].value_counts().to_dict(),
            'by_cloud_provider': df['cloud_provider'].value_counts().to_dict(),
            'by_source': df['source'].value_counts().to_dict(),
            'timestamp': datetime.now().isoformat()
        }
        
        return summary
    
    def export_results(self):
        """Export aggregated findings to various formats"""
        print("\nExporting results...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Export to JSON
        json_file = self.output_dir / f"aggregated_findings_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        print(f"JSON exported: {json_file}")
        
        # Export to CSV
        if self.findings:
            csv_file = self.output_dir / f"aggregated_findings_{timestamp}.csv"
            df = pd.DataFrame(self.findings)
            df.to_csv(csv_file, index=False)
            print(f"CSV exported: {csv_file}")
        
        # Export summary
        summary = self.generate_summary()
        summary_file = self.output_dir / f"findings_summary_{timestamp}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"Summary exported: {summary_file}")
        
        # Print summary
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
    """Main execution function"""
    
    # Configuration
    PROWLER_DIR = "../../scan-results/prowler"
    SCOUTSUITE_DIR = "../../scan-results/scoutsuite"
    OUTPUT_DIR = "../../scan-results/aggregated"
    
    # Initialize aggregator
    aggregator = FindingsAggregator(
        prowler_dir=PROWLER_DIR,
        scoutsuite_dir=SCOUTSUITE_DIR,
        output_dir=OUTPUT_DIR
    )
    
    # Run aggregation
    aggregator.aggregate_findings()
    aggregator.export_results()
    
    print("\n✓ Aggregation complete!")
    print("Next step: Launch the dashboard to visualize findings")


if __name__ == "__main__":
    main()
