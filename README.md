# Cloud Security Posture Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/AWS-Security-orange)](https://aws.amazon.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/IaC-Terraform-purple)](https://www.terraform.io/)
[![Prowler](https://img.shields.io/badge/Scanner-Prowler-green)](https://github.com/prowler-cloud/prowler)

> An automated cloud security assessment platform that deploys intentionally misconfigured AWS resources, scans them with Prowler, and displays findings in a centralized dashboard with severity-based categorization and remediation guidance.

## Project Overview

Cloud Security Posture Dashboard is a hands-on security auditing solution designed to:
- **Deploy** intentionally misconfigured AWS resources using Terraform (for learning purposes)
- **Scan** infrastructure using Prowler to detect security vulnerabilities
- **Aggregate** findings into a normalized format for analysis
- **Visualize** security posture through an interactive web dashboard
- **Remediate** issues using provided CLI commands and guidance

**Use Case**: Security professionals, cloud engineers, and students can use this platform to understand common cloud misconfigurations, practice security scanning, and learn remediation techniques in a safe environment.

## Features

- **Terraform Infrastructure**: Deploy intentionally misconfigured S3 buckets for security testing
- **Prowler Integration**: Automated AWS security scanning with 500+ checks
- **Python Aggregator**: Normalizes scan results into a unified JSON/CSV format
- **Flask Dashboard**: Real-time visualization on port 51000
- **Interactive Charts**: Doughnut chart for severity breakdown, bar chart for cloud providers
- **Detailed Findings View**: Expandable accordion with full finding details
- **Search & Filter**: Filter findings by severity, provider, or keyword
- **Remediation Guidance**: CLI commands and documentation links for each finding
- **Compliance Mapping**: CIS benchmark framework references (CIS-2.0, CIS-1.4, CIS-1.5)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Account                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │         Terraform-Deployed Test Resources           │    │
│  │  • insecure_bucket (no encryption, no versioning)   │    │
│  │  • public_read_bucket (public read access)          │    │
│  │  • website_bucket (HTTP-only hosting)               │    │
│  │  • cross_account_bucket (overly permissive policy)  │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Security Scanning Layer                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Prowler                           │    │
│  │  • 500+ security checks                              │    │
│  │  • CIS Benchmark compliance                          │    │
│  │  • JSON output for processing                        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              Aggregation Layer (Python)                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │         scripts/scanning/aggregate_findings.py       │    │
│  │  • Parse Prowler JSON output                         │    │
│  │  • Normalize to common schema                        │    │
│  │  • Export to JSON and CSV                            │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│               Visualization Layer (Flask)                    │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              dashboard/app.py                        │    │
│  │  • Summary cards (Total, Critical, High, Medium)     │    │
│  │  • Severity doughnut chart (Chart.js)                │    │
│  │  • Provider bar chart                                │    │
│  │  • Findings table with details                       │    │
│  │  • Search and filter functionality                   │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Cloud Platform** | AWS | Target environment for security scanning |
| **Infrastructure as Code** | Terraform | Deploy misconfigured test resources |
| **Security Scanner** | Prowler 3.x | AWS security assessment (500+ checks) |
| **Backend** | Python 3.9+ | Findings aggregation and normalization |
| **Web Framework** | Flask | Dashboard server |
| **Frontend** | Bootstrap 5, Chart.js | UI components and visualizations |
| **Data Format** | JSON, CSV | Normalized findings storage |

## Prerequisites

Before running this project, ensure you have:

- **AWS Account** with IAM permissions for:
  - S3 bucket creation and management
  - Security audit read permissions (for Prowler)
- **Tools Installed**:
  - [Terraform](https://www.terraform.io/downloads) >= 1.0.0
  - [Python](https://www.python.org/downloads/) >= 3.9 (Note: Python 3.12 recommended; 3.13 has compatibility issues with Prowler 5.x)
  - [AWS CLI](https://aws.amazon.com/cli/) configured with credentials
  - [Prowler](https://github.com/prowler-cloud/prowler) (installed via pip)

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/cloud-security-posture-dashboard.git
cd cloud-security-posture-dashboard
```

### 2. Set Up Python Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install prowler pandas flask
```

### 3. Configure AWS Credentials
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and default region
```

### 4. Deploy Test Infrastructure
```bash
cd terraform/aws
terraform init
terraform plan    # Review what will be created
terraform apply   # Type 'yes' to confirm

# This creates 4 intentionally misconfigured S3 buckets
```

### 5. Run Security Scan
```bash
# Scan all services (comprehensive)
prowler aws

# Or scan specific services (faster)
prowler aws --service s3
prowler aws --service s3 iam
```

### 6. Aggregate Findings
```bash
# Process Prowler output into normalized format
python scripts/scanning/aggregate_findings.py
```

### 7. Launch Dashboard
```bash
python dashboard/app.py
```

Visit **http://localhost:51000** to view the dashboard.

## Project Structure

```
cloud-security-posture-dashboard/
├── terraform/
│   └── aws/
│       └── main.tf              # Misconfigured S3 buckets
├── scripts/
│   └── scanning/
│       └── aggregate_findings.py # Prowler output parser
├── dashboard/
│   ├── app.py                   # Flask application
│   ├── static/
│   │   └── style.css            # Custom styles
│   └── templates/
│       ├── base.html            # Base template
│       ├── index.html           # Main dashboard
│       └── findings.html        # Detailed findings view
├── output/                      # Prowler scan results
├── scan-results/
│   └── aggregated/              # Normalized findings
├── venv/                        # Python virtual environment
└── README.md
```

## Understanding the Dashboard

### Summary Cards
- **Total Findings**: All security issues detected
- **Critical**: Urgent issues requiring immediate attention (red)
- **High**: Serious security concerns (orange)
- **Medium**: Moderate issues to address (yellow)

### Severity Doughnut Chart
Visual breakdown of findings by severity level with color coding:
- Critical = Red
- High = Orange
- Medium = Yellow
- Low = Green
- Informational = Blue

### Findings Table
Each finding includes:
- **Severity Badge**: Color-coded priority
- **Title**: What was checked
- **Resource**: Affected resource (bucket name or account ID for account-level checks)
- **Provider**: Cloud provider (AWS)

### Detailed View (All Findings Page)
Expandable accordion showing:
- Full issue description
- Risk explanation
- Remediation steps with CLI commands
- Compliance framework mappings

## Test Resources Deployed

The Terraform configuration deploys 4 intentionally misconfigured S3 buckets:

| Bucket | Misconfiguration | Security Risk |
|--------|-----------------|---------------|
| `insecure_bucket` | No encryption, no versioning, public access block disabled | Data exposure, no recovery options |
| `public_read_bucket` | Public read access via bucket policy | Anyone on internet can read files |
| `website_bucket` | Static website hosting over HTTP | Data transmitted unencrypted |
| `cross_account_bucket` | Any AWS user can read/write/delete | Complete data compromise possible |

## Cleanup

**Important**: Always destroy test resources when done to avoid unexpected charges.

```bash
cd terraform/aws
terraform destroy  # Type 'yes' to confirm
```

## Roadmap

- [x] Initial project setup and architecture design
- [x] Deploy AWS test infrastructure with misconfigurations
- [x] Integrate Prowler for AWS scanning
- [x] Build findings aggregation pipeline
- [x] Develop Flask dashboard with Chart.js visualizations
- [x] Add search and filter functionality
- [x] Implement compliance framework mapping (CIS)
- [ ] Deploy Azure test infrastructure with misconfigurations
- [ ] Integrate ScoutSuite for multi-cloud scanning
- [ ] Create automated remediation scripts (Terraform)
- [ ] Implement CI/CD pipeline with GitHub Actions
- [ ] Add alerting/notification system
- [ ] Container deployment (Docker)
- [ ] Historical trend analysis

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment tool
- [Terraform](https://www.terraform.io/) - Infrastructure as Code
- [Flask](https://flask.palletsprojects.com/) - Python web framework
- [Chart.js](https://www.chartjs.org/) - JavaScript charting library
- [Bootstrap](https://getbootstrap.com/) - CSS framework
- CIS Benchmarks for cloud security best practices

## Disclaimer

This project deploys **intentionally insecure** cloud resources for educational purposes. These resources should only be deployed in test/sandbox AWS accounts. Always destroy resources after testing to avoid security risks and unexpected charges.

---

**Built for learning cloud security through hands-on practice.**
