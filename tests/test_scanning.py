"""
Unit tests for scanning aggregation functionality
"""

import pytest
import json
from pathlib import Path
from scripts.scanning.aggregate_findings import FindingsAggregator


class TestFindingsAggregator:
    """Test suite for FindingsAggregator class"""
    
    @pytest.fixture
    def sample_prowler_finding(self):
        """Sample Prowler finding for testing"""
        return {
            'CheckID': 'check_s3_bucket_public_access',
            'CheckTitle': 'Check if S3 buckets have public access',
            'Severity': 'CRITICAL',
            'Status': 'FAIL',
            'ResourceId': 'arn:aws:s3:::my-public-bucket',
            'Region': 'us-east-1',
            'Description': 'Bucket allows public access',
            'Remediation': 'Disable public access on the bucket'
        }
    
    @pytest.fixture
    def aggregator(self, tmp_path):
        """Create aggregator instance with temporary directories"""
        prowler_dir = tmp_path / "prowler"
        scoutsuite_dir = tmp_path / "scoutsuite"
        output_dir = tmp_path / "output"
        
        prowler_dir.mkdir()
        scoutsuite_dir.mkdir()
        
        return FindingsAggregator(
            prowler_dir=str(prowler_dir),
            scoutsuite_dir=str(scoutsuite_dir),
            output_dir=str(output_dir)
        )
    
    def test_normalize_prowler_finding(self, aggregator, sample_prowler_finding):
        """Test Prowler finding normalization"""
        normalized = aggregator._normalize_prowler_finding(sample_prowler_finding)
        
        assert normalized['source'] == 'Prowler'
        assert normalized['cloud_provider'] == 'AWS'
        assert normalized['severity'] == 'Critical'
        assert normalized['finding_id'] == 'check_s3_bucket_public_access'
    
    def test_severity_mapping(self, aggregator):
        """Test severity level mapping"""
        assert aggregator._map_severity('CRITICAL') == 'Critical'
        assert aggregator._map_severity('high') == 'High'
        assert aggregator._map_severity('Medium') == 'Medium'
        assert aggregator._map_severity('LOW') == 'Low'
        assert aggregator._map_severity('unknown') == 'Medium'  # Default
    
    def test_aggregate_findings_empty(self, aggregator):
        """Test aggregation with no findings"""
        aggregator.aggregate_findings()
        assert len(aggregator.findings) == 0
    
    def test_generate_summary(self, aggregator, sample_prowler_finding):
        """Test summary generation"""
        # Add a sample finding
        aggregator.findings = [
            aggregator._normalize_prowler_finding(sample_prowler_finding)
        ]
        
        summary = aggregator.generate_summary()
        
        assert summary['total_findings'] == 1
        assert 'Critical' in summary['by_severity']
        assert summary['by_cloud_provider']['AWS'] == 1


# TODO: Add more test cases
# - Test with actual Prowler JSON files
# - Test ScoutSuite parsing
# - Test export functionality
# - Test error handling
