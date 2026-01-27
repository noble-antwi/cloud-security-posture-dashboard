# Cloud Security Posture Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/Cloud-AWS-FF9900?logo=amazon-aws)](https://aws.amazon.com/)
[![Azure](https://img.shields.io/badge/Cloud-Azure-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?logo=terraform)](https://www.terraform.io/)
[![Prowler](https://img.shields.io/badge/Scanner-Prowler-00D4AA)](https://github.com/prowler-cloud/prowler)
[![ScoutSuite](https://img.shields.io/badge/Scanner-ScoutSuite-FF6B6B)](https://github.com/nccgroup/ScoutSuite)

A comprehensive **multi-cloud security assessment platform** that automates the deployment of intentionally misconfigured resources, performs security scanning, aggregates findings into a unified format, and visualizes results through an interactive dashboard with remediation guidance.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Security Scanners](#security-scanners)
- [Remediation Engine](#remediation-engine)
- [Dashboard](#dashboard)
- [Cleanup](#cleanup)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Overview

Cloud Security Posture Dashboard is an end-to-end security auditing solution designed for:

| Capability | Description |
|------------|-------------|
| **Deploy** | Provision intentionally misconfigured cloud resources using Terraform |
| **Scan** | Automated security assessment using Prowler (AWS) and ScoutSuite (Azure) |
| **Aggregate** | Normalize findings from multiple tools into a unified schema |
| **Visualize** | Interactive web dashboard with charts, filters, and detailed findings |
| **Remediate** | Automated remediation scripts with CLI commands |

### Use Cases

- **Security Engineers**: Validate scanning tools and remediation workflows
- **Cloud Engineers**: Learn common misconfigurations and how to detect them
- **Students/Learners**: Hands-on practice with cloud security in a safe environment
- **DevSecOps Teams**: Template for building security automation pipelines

---

## Features

### Multi-Cloud Support
- **AWS**: S3 buckets with encryption, versioning, and access policy issues
- **Azure**: Storage accounts, NSGs, and Key Vaults with security misconfigurations

### Security Scanning
- **Prowler** (AWS): 500+ security checks, CIS Benchmark compliance
- **ScoutSuite** (Azure): Comprehensive Azure security assessment

### Findings Aggregation
- Unified JSON/CSV output format
- Normalized severity levels (Critical, High, Medium, Low)
- Compliance framework mapping (CIS 2.0, CIS 1.4, CIS 1.5)

### Interactive Dashboard
- Real-time visualization on port 51000
- Summary cards with severity breakdown
- Doughnut chart for severity distribution
- Bar chart for cloud provider comparison
- Searchable and filterable findings table
- Detailed findings view with remediation guidance

### Automated Remediation
- Python-based remediation engine
- AWS CLI commands for common fixes
- Dry-run mode for safe testing
- Batch remediation support

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MULTI-CLOUD ENVIRONMENTS                            │
│                                                                             │
│   ┌─────────────────────────────┐     ┌─────────────────────────────┐      │
│   │         AWS Account         │     │      Azure Subscription      │      │
│   │  ┌───────────────────────┐  │     │  ┌───────────────────────┐  │      │
│   │  │ • insecure_bucket     │  │     │  │ • insecure_storage    │  │      │
│   │  │ • public_read_bucket  │  │     │  │ • no_recovery_storage │  │      │
│   │  │ • website_bucket      │  │     │  │ • insecure_nsg        │  │      │
│   │  │ • cross_account_bucket│  │     │  │ • insecure_keyvault   │  │      │
│   │  └───────────────────────┘  │     │  └───────────────────────┘  │      │
│   └──────────────┬──────────────┘     └──────────────┬──────────────┘      │
└──────────────────┼──────────────────────────────────┼───────────────────────┘
                   │                                   │
                   ▼                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SECURITY SCANNING LAYER                            │
│                                                                             │
│   ┌─────────────────────────────┐     ┌─────────────────────────────┐      │
│   │          Prowler            │     │        ScoutSuite           │      │
│   │  • 500+ AWS checks          │     │  • Multi-cloud support      │      │
│   │  • CIS Benchmark            │     │  • Azure comprehensive      │      │
│   │  • JSON output              │     │  • HTML + JS output         │      │
│   └──────────────┬──────────────┘     └──────────────┬──────────────┘      │
└──────────────────┼──────────────────────────────────┼───────────────────────┘
                   │                                   │
                   └─────────────────┬─────────────────┘
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AGGREGATION LAYER (Python)                          │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                    aggregate_findings.py                             │  │
│   │  • Parse Prowler JSON + ScoutSuite JS                               │  │
│   │  • Normalize to unified schema                                      │  │
│   │  • Calculate severity statistics                                    │  │
│   │  • Export to JSON/CSV                                               │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                      ▼
┌─────────────────────────────────┐  ┌─────────────────────────────────────────┐
│      VISUALIZATION (Flask)      │  │         REMEDIATION ENGINE              │
│                                 │  │                                         │
│  • Summary dashboard            │  │  • Automated AWS CLI fixes              │
│  • Severity charts              │  │  • Dry-run mode                         │
│  • Findings table               │  │  • Batch remediation                    │
│  • Search & filter              │  │  • Logging & reporting                  │
│  • Remediation guidance         │  │                                         │
└─────────────────────────────────┘  └─────────────────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Cloud Platforms** | AWS, Azure | Target environments for security testing |
| **Infrastructure as Code** | Terraform | Deploy misconfigured test resources |
| **AWS Scanner** | Prowler 3.x | AWS security assessment (500+ checks) |
| **Azure Scanner** | ScoutSuite | Azure security assessment |
| **Backend** | Python 3.9+ | Aggregation, normalization, remediation |
| **Web Framework** | Flask | Dashboard server |
| **Frontend** | Bootstrap 5, Chart.js | UI components and visualizations |
| **Data Format** | JSON, CSV | Normalized findings storage |

---

## Prerequisites

### Required Accounts
- **AWS Account** with IAM permissions for S3 and security audits
- **Azure Account** with subscription and service principal (optional)

### Required Tools

| Tool | Version | Installation |
|------|---------|--------------|
| Python | >= 3.9 | [python.org](https://www.python.org/downloads/) |
| Terraform | >= 1.0.0 | [terraform.io](https://www.terraform.io/downloads) |
| AWS CLI | >= 2.0 | [AWS CLI Install](https://aws.amazon.com/cli/) |
| Azure CLI | >= 2.0 | [Azure CLI Install](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) (optional) |

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/noble-antwi/cloud-security-posture-dashboard.git
cd cloud-security-posture-dashboard
```

### 2. Set Up Python Environment

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# .\venv\Scripts\activate  # Windows

# Install dependencies
pip install prowler pandas flask scoutsuite
```

### 3. Configure Cloud Credentials

**AWS:**
```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region
```

**Azure (optional):**
```bash
az login
# Set environment variables for Terraform:
export ARM_CLIENT_ID="your-client-id"
export ARM_CLIENT_SECRET="your-client-secret"
export ARM_SUBSCRIPTION_ID="your-subscription-id"
export ARM_TENANT_ID="your-tenant-id"
```

---

## Usage

### Deploy Test Infrastructure

**AWS:**
```bash
cd terraform/aws
terraform init && terraform apply
```

**Azure:**
```bash
cd terraform/azure
terraform init && terraform apply
```

### Run Security Scans

**AWS (Prowler):**
```bash
prowler aws                    # Full scan
prowler aws --service s3       # S3 only (faster)
```

**Azure (ScoutSuite):**
```bash
scout azure --cli
```

### Aggregate Findings

```bash
python scripts/scanning/aggregate_findings.py
```

### Launch Dashboard

```bash
python dashboard/app.py
```

Open **http://localhost:51000** in your browser.

### Run Remediation (Optional)

```bash
# Dry run (preview changes)
python remediation/aws/remediate.py

# Apply fixes
python remediation/aws/remediate.py --apply
```

---

## Project Structure

```
cloud-security-posture-dashboard/
├── terraform/
│   ├── aws/
│   │   └── main.tf                    # AWS misconfigured resources
│   └── azure/
│       └── main.tf                    # Azure misconfigured resources
├── scripts/
│   └── scanning/
│       └── aggregate_findings.py      # Multi-tool findings aggregator
├── remediation/
│   └── aws/
│       └── remediate.py               # AWS remediation engine
├── dashboard/
│   ├── app.py                         # Flask application
│   ├── static/
│   │   └── style.css                  # Custom styles
│   └── templates/
│       ├── base.html                  # Base template
│       ├── index.html                 # Main dashboard
│       └── findings.html              # Detailed findings
├── output/                            # Prowler scan results
├── scoutsuite-report/                 # ScoutSuite scan results
├── scan-results/
│   └── aggregated/                    # Normalized findings (JSON/CSV)
└── README.md
```

---

## Security Scanners

### Prowler (AWS)

| Feature | Description |
|---------|-------------|
| Checks | 500+ security controls |
| Compliance | CIS, NIST, PCI-DSS, HIPAA, GDPR |
| Output | JSON, CSV, HTML |
| Speed | ~10-30 minutes full scan |

### ScoutSuite (Azure)

| Feature | Description |
|---------|-------------|
| Services | 12+ Azure services |
| Checks | Storage, Network, IAM, Key Vault |
| Output | HTML report + JavaScript data |
| Speed | ~1-5 minutes |

---

## Remediation Engine

The remediation engine automates fixing common security issues.

### Supported Remediations

| Finding | Remediation |
|---------|-------------|
| `s3_bucket_default_encryption` | Enable AES-256 encryption |
| `s3_bucket_public_access` | Block all public access |
| `s3_bucket_versioning_enabled` | Enable versioning |
| `accessanalyzer_enabled` | Create IAM Access Analyzer |

### Usage

```bash
# Preview (dry run)
python remediation/aws/remediate.py

# Apply fixes
python remediation/aws/remediate.py --apply

# Filter by severity
python remediation/aws/remediate.py --apply --severity Critical

# Filter by finding type
python remediation/aws/remediate.py --apply --finding-type s3_bucket_default_encryption
```

---

## Dashboard

### Summary View
- **Total Findings**: Aggregate count across all clouds
- **Severity Cards**: Critical (red), High (orange), Medium (yellow)
- **Charts**: Doughnut for severity, Bar for cloud providers

### Findings Table
- Sortable columns
- Severity badges
- Resource identification
- Provider tags

### Detailed View
- Expandable accordion for each finding
- Issue description and risk explanation
- Remediation steps with CLI commands
- Compliance framework references

---

## Cleanup

**Important**: Always destroy test resources to avoid charges and security risks.

```bash
# AWS
cd terraform/aws && terraform destroy

# Azure
cd terraform/azure && terraform destroy
```

---

## Roadmap

### Completed
- [x] AWS test infrastructure with Terraform
- [x] Azure test infrastructure with Terraform
- [x] Prowler integration for AWS scanning
- [x] ScoutSuite integration for Azure scanning
- [x] Multi-tool findings aggregator
- [x] Flask dashboard with Chart.js
- [x] Search and filter functionality
- [x] AWS remediation engine
- [x] CIS compliance mapping

### In Progress
- [ ] CI/CD pipeline with GitHub Actions

### Planned
- [ ] Multi-account support
- [ ] Historical trend analysis
- [ ] Alerting and notifications
- [ ] Docker containerization
- [ ] GCP support

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Disclaimer

> **Warning**: This project deploys **intentionally insecure** cloud resources for educational and testing purposes only.
>
> - Only deploy in test/sandbox accounts
> - Never use in production environments
> - Always destroy resources after testing
> - You are responsible for any charges incurred

---

## Acknowledgments

- [Prowler](https://github.com/prowler-cloud/prowler) - AWS Security Tool
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-Cloud Security Auditing
- [Terraform](https://www.terraform.io/) - Infrastructure as Code
- [Flask](https://flask.palletsprojects.com/) - Python Web Framework
- [Chart.js](https://www.chartjs.org/) - JavaScript Charting
- [Bootstrap](https://getbootstrap.com/) - CSS Framework
- [CIS Benchmarks](https://www.cisecurity.org/) - Security Best Practices

---

<div align="center">

**Built for learning cloud security through hands-on practice**

[Report Bug](https://github.com/noble-antwi/cloud-security-posture-dashboard/issues) · [Request Feature](https://github.com/noble-antwi/cloud-security-posture-dashboard/issues)

</div>
