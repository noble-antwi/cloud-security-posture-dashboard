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

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/noble-antwi/cloud-security-posture-dashboard.git
cd cloud-security-posture-dashboard
python3 -m venv venv && source venv/bin/activate
pip install prowler pandas flask scoutsuite

# 2. Scan your AWS accounts
./scripts/scanning/run_multi_account_scan.sh --profiles "your-profile" --quick

# 3. Aggregate and visualize
python scripts/scanning/aggregate_findings.py
python dashboard/app.py

# 4. Open http://localhost:51000
```

> **Detailed Guide**: See [docs/USAGE.md](docs/USAGE.md) for comprehensive documentation.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Overview](#overview)
- [How It Works](#how-it-works)
- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Multi-Account Scanning](#multi-account-scanning)
- [Project Structure](#project-structure)
- [Security Scanners](#security-scanners)
- [Remediation Guidance](#remediation-guidance)
- [Dashboard](#dashboard)
- [Cleanup](#cleanup)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Documentation](#documentation)

---

## Overview

Cloud Security Posture Dashboard is an end-to-end security auditing solution designed for:

| Capability | Description |
|------------|-------------|
| **Deploy** | Provision intentionally misconfigured cloud resources using Terraform |
| **Scan** | Automated security assessment using Prowler (AWS) and ScoutSuite (Azure) |
| **Aggregate** | Normalize findings from multiple tools into a unified schema |
| **Visualize** | Interactive web dashboard with charts, filters, and detailed findings |
| **Remediate** | Remediation guidance with multiple options (CLI, Terraform, Console) |

### Use Cases

- **Security Engineers**: Validate scanning tools and remediation workflows
- **Cloud Engineers**: Learn common misconfigurations and how to detect them
- **Students/Learners**: Hands-on practice with cloud security in a safe environment
- **DevSecOps Teams**: Template for building security automation pipelines

---

## How It Works

The project follows a **pipeline architecture** where each step produces output for the next:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   DEPLOY    │ ──▶ │    SCAN     │ ──▶ │  AGGREGATE  │ ──▶ │  DASHBOARD  │
│  (Optional) │     │             │     │             │     │             │
│  Terraform  │     │   Prowler   │     │   Python    │     │    Flask    │
│             │     │  ScoutSuite │     │   Script    │     │  Chart.js   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                   │                   │                   │
      ▼                   ▼                   ▼                   ▼
   Creates            Connects to        Reads raw JSON      Reads unified
   insecure           AWS/Azure,         normalizes to       JSON, renders
   test resources     runs 500+ checks   common format       charts & tables
```

| Step | Script/Tool | Input | Output |
|------|-------------|-------|--------|
| **Deploy** | `terraform apply` | Terraform files | Cloud resources |
| **Scan** | `run_multi_account_scan.sh` | AWS credentials | `output/*.json` |
| **Aggregate** | `aggregate_findings.py` | Raw JSON files | `scan-results/aggregated/*.json` |
| **Visualize** | `dashboard/app.py` | Aggregated JSON | Web UI on port 51000 |

**Why this separation?**
- Scans are **expensive** (API calls, 10-30 min) — run them once
- Aggregation is **cheap** (local files, seconds) — re-run anytime
- You can update dashboard logic without re-scanning

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

### Remediation Guidance
- Multiple remediation options per finding (CLI, Terraform, Console)
- Copy-to-clipboard for quick command execution
- Links to official documentation
- Company-policy friendly (choose your own approach)

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
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VISUALIZATION & GUIDANCE (Flask)                       │
│                                                                              │
│  • Summary dashboard with severity charts                                   │
│  • Searchable & filterable findings table                                   │
│  • Detailed findings view with risk explanation                             │
│  • Remediation options: AWS CLI, Terraform, Console steps                   │
│  • Copy-to-clipboard for quick command execution                            │
│  • Links to official documentation                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Cloud Platforms** | AWS, Azure | Target environments for security testing |
| **Infrastructure as Code** | Terraform | Deploy misconfigured test resources |
| **AWS Scanner** | Prowler 3.x | AWS security assessment (500+ checks) |
| **Azure Scanner** | ScoutSuite | Azure security assessment |
| **Backend** | Python 3.9+ | Aggregation, normalization, data processing |
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

---

## Multi-Account Scanning

The dashboard supports scanning and aggregating findings from multiple AWS accounts. There are three approaches you can use:

### Approach 1: AWS Profiles (Recommended for Small Teams)

Best for: Teams managing a few accounts manually with separate credentials.

**Setup:**
```bash
# Configure profiles in ~/.aws/credentials
[production]
aws_access_key_id = AKIA...
aws_secret_access_key = ...

[staging]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

**Scan:**
```bash
./scripts/scanning/run_multi_account_scan.sh --profiles "production,staging"
```

### Approach 2: Assume Role (Recommended for Enterprises)

Best for: Organizations using a central security account that assumes roles into target accounts.

**Setup:**
1. Create an IAM role (e.g., `SecurityAuditRole`) in each target account
2. Attach the `SecurityAudit` AWS managed policy
3. Configure trust policy to allow your security account to assume the role

**Scan:**
```bash
./scripts/scanning/run_multi_account_scan.sh \
  --accounts "111111111111,222222222222,333333333333" \
  --role-arn "arn:aws:iam::ACCOUNT_ID:role/SecurityAuditRole"
```

### Approach 3: AWS Organizations

Best for: Large organizations with AWS Organizations set up.

**Scan:**
```bash
./scripts/scanning/run_multi_account_scan.sh --org \
  --role-arn "arn:aws:iam::ACCOUNT_ID:role/SecurityAuditRole"
```

### Multi-Account Workflow

```bash
# 1. Run scans across accounts
./scripts/scanning/run_multi_account_scan.sh --profiles "prod,dev"

# 2. Aggregate findings (auto-detects account subdirectories)
python scripts/scanning/aggregate_findings.py

# 3. Launch dashboard (includes Account filter)
python dashboard/app.py
```

The dashboard will show an **Account filter** dropdown to view findings by account.

### Which Approach Should You Use?

| Approach | Best For | Pros | Cons |
|----------|----------|------|------|
| **AWS Profiles** | Small teams (2-5 accounts) | Simple setup, no IAM changes | Credentials in multiple places |
| **Assume Role** | Enterprises | Centralized, auditable | Requires IAM setup |
| **Organizations** | Large orgs | Auto-discovers accounts | Requires Org access |

---

## Project Structure

```
cloud-security-posture-dashboard/
├── docs/
│   └── USAGE.md                       # Detailed usage documentation
├── terraform/
│   ├── aws/
│   │   └── main.tf                    # AWS misconfigured resources
│   └── azure/
│       └── main.tf                    # Azure misconfigured resources
├── scripts/
│   └── scanning/
│       ├── aggregate_findings.py      # Multi-tool findings aggregator
│       └── run_multi_account_scan.sh  # Multi-account scanning script
├── remediation/                       # (Reserved for future use)
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

## Remediation Guidance

Instead of automated fixes, the dashboard provides **multiple remediation options** for each finding, allowing your security team to choose the approach that fits your company's policies.

### Why Multiple Options?

| Scenario | One-Size-Fits-All | Your Company's Policy |
|----------|-------------------|----------------------|
| S3 Encryption | AES-256 (default) | KMS with customer-managed keys |
| Public Access | Block everything | Allow specific IPs for partners |
| Versioning | Enable only | Enable + lifecycle policy |

### Available Remediation Formats

Each finding in the dashboard shows:

| Format | Description |
|--------|-------------|
| **AWS CLI** | Ready-to-run commands with copy button |
| **Terraform** | Infrastructure as Code snippets |
| **Console Steps** | Step-by-step portal instructions |
| **Documentation** | Links to official AWS/Azure docs |

### Using Remediation Guidance

1. Open the dashboard: `python dashboard/app.py`
2. Navigate to **All Findings**
3. Expand a finding to see remediation options
4. Choose the approach that fits your policy
5. Copy the command or follow the steps

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
- **Tabbed remediation options** (CLI, Terraform, Console)
- Copy-to-clipboard for commands
- Documentation links
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
- [x] Remediation guidance with multiple options
- [x] CIS compliance mapping
- [x] Multi-account AWS support

### In Progress
- [ ] CI/CD pipeline with GitHub Actions

### Planned
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

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Project overview and quick start |
| [docs/USAGE.md](docs/USAGE.md) | Detailed usage guide with examples |

As the project evolves, documentation is updated to reflect new features and changes.

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
