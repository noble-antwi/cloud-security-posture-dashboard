# Architecture Documentation

## Overview

The Cloud Security Posture Dashboard is designed as a modular, scalable system for multi-cloud security assessment and remediation.

## System Components

### 1. Infrastructure Layer (Terraform)
**Purpose**: Deploy intentionally misconfigured cloud resources for testing

**Components**:
- `terraform/aws/`: AWS infrastructure definitions
- `terraform/azure/`: Azure infrastructure definitions

**Key Resources**:
- Misconfigured S3 buckets, storage accounts
- Overly permissive security groups and NSGs
- Unencrypted volumes and databases
- IAM/RBAC misconfigurations

### 2. Scanning Layer
**Purpose**: Automated security assessment using industry-standard tools

**Tools**:
- **Prowler**: Comprehensive AWS security scanning
  - CIS Benchmark compliance
  - Best practice checks
  - JSON/CSV/HTML output
  
- **ScoutSuite**: Multi-cloud security auditing
  - Azure and AWS support
  - Web-based report generation
  - Detailed finding categorization

**Outputs**:
- JSON files with structured findings
- HTML reports for manual review
- CSV exports for data analysis

### 3. Aggregation Layer (Python)
**Purpose**: Normalize and consolidate findings from multiple sources

**Functions**:
- Parse Prowler and ScoutSuite outputs
- Normalize to common schema
- Categorize by severity
- Generate summary statistics
- Export to dashboard-consumable formats

**Schema**:
```json
{
  "source": "Prowler|ScoutSuite",
  "cloud_provider": "AWS|Azure",
  "finding_id": "string",
  "title": "string",
  "severity": "Critical|High|Medium|Low|Informational",
  "status": "PASS|FAIL|WARN",
  "resource": "string",
  "region": "string",
  "description": "string",
  "remediation": "string",
  "timestamp": "ISO-8601"
}
```

### 4. Dashboard Layer
**Purpose**: Visualize findings and track remediation progress

**Options**:

**Option A: Grafana**
- Pros: Professional-grade visualization, time-series support
- Cons: Requires setup, learning curve
- Best for: Enterprise-style dashboards

**Option B: Custom Web App (Flask/Dash)**
- Pros: Full customization, lightweight
- Cons: More development effort
- Best for: Tailored user experience

**Key Visualizations**:
- Total findings count
- Severity distribution (pie/donut chart)
- Findings by cloud provider (bar chart)
- Trend analysis (line chart)
- Resource-level breakdown (table)

### 5. Remediation Layer (Terraform)
**Purpose**: Automated fixing of identified security issues

**Approach**:
- Terraform scripts to correct misconfigurations
- Dry-run mode for validation
- Selective remediation by severity or finding ID
- Audit trail of changes

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. DEPLOYMENT PHASE                                          │
│    Terraform → Deploy misconfigured cloud resources         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. SCANNING PHASE                                            │
│    Prowler/ScoutSuite → Scan cloud environments             │
│    Output: JSON files with findings                         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. AGGREGATION PHASE                                         │
│    Python scripts → Parse and normalize findings            │
│    Output: Consolidated JSON/CSV                            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. VISUALIZATION PHASE                                       │
│    Dashboard → Display findings with charts                 │
│    User: Review and prioritize remediation                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. REMEDIATION PHASE                                         │
│    Terraform scripts → Fix security issues                  │
│    Re-scan → Verify corrections                             │
└─────────────────────────────────────────────────────────────┘
```

## Security Considerations

### Credential Management
- Never hardcode AWS/Azure credentials
- Use environment variables or credential files
- Leverage IAM roles for AWS, managed identities for Azure
- Rotate credentials regularly

### Data Handling
- Scan results may contain sensitive information
- Store outputs in secure directories
- Add to .gitignore to prevent accidental commits
- Implement access controls on dashboard

### Cost Management
- Use smallest viable instance sizes
- Implement resource tagging
- Set up billing alerts
- Clean up resources after testing

## Scalability Considerations

### For Production Use
- Implement database backend (PostgreSQL, MongoDB)
- Add caching layer (Redis)
- Container deployment (Docker, Kubernetes)
- API for programmatic access
- User authentication and authorization
- Scheduled scanning (cron jobs, Lambda functions)

### Performance Optimization
- Parallel scanning for multiple accounts
- Incremental scans (delta detection)
- Result caching and deduplication
- Dashboard pagination and filtering

## Technology Decisions

### Why Terraform?
- Industry standard for IaC
- Multi-cloud support
- State management
- Reusable modules

### Why Prowler + ScoutSuite?
- Open-source and well-maintained
- Comprehensive check coverage
- Active community
- Structured output formats

### Why Python?
- Rich ecosystem for data processing
- Easy integration with cloud SDKs
- Excellent libraries (pandas, boto3)
- Clear, readable code

## Future Enhancements

1. **Additional Cloud Providers**: GCP, OCI support
2. **Compliance Frameworks**: HIPAA, SOC 2, PCI-DSS mappings
3. **Alerting**: Email/Slack notifications for critical findings
4. **Automation**: Auto-remediation for low-risk issues
5. **Reporting**: PDF report generation
6. **Integrations**: JIRA, ServiceNow ticket creation
7. **ML-based prioritization**: Risk scoring based on context

---

For implementation details, see the deployment guide and code documentation.
