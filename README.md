# Cloud Security Posture Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS](https://img.shields.io/badge/AWS-Security-orange)](https://aws.amazon.com/)
[![Azure](https://img.shields.io/badge/Azure-Security-blue)](https://azure.microsoft.com/)
[![Terraform](https://img.shields.io/badge/IaC-Terraform-purple)](https://www.terraform.io/)

> An automated multi-cloud security assessment platform that identifies misconfigurations across AWS and Azure environments, aggregates findings into a centralized dashboard, and provides automated remediation scripts.

![Dashboard Preview](docs/images/dashboard-preview.png)
*Dashboard screenshot will go here*

## 🎯 Project Overview

Cloud Security Posture Dashboard is an end-to-end security auditing solution designed to:
- **Detect** security misconfigurations across AWS and Azure using industry-standard tools
- **Aggregate** findings into a unified, actionable dashboard
- **Remediate** identified issues through automated Terraform scripts
- **Monitor** security posture changes over time

**Use Case**: Security teams and cloud engineers can deploy this platform to continuously monitor their multi-cloud infrastructure for common security risks and compliance violations.

## 🔑 Key Features

- ✅ **Multi-Cloud Support**: Simultaneous scanning of AWS and Azure environments
- 🔍 **Automated Security Scanning**: Integration with ScoutSuite and Prowler
- 📊 **Centralized Dashboard**: Real-time visualization of security findings
- 🛠️ **Automated Remediation**: Terraform-based Infrastructure-as-Code fixes
- 📈 **Trend Analysis**: Historical tracking of security posture improvements
- 🚨 **Risk Prioritization**: Severity-based finding categorization (Critical, High, Medium, Low)

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Cloud Environments                     │
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │   AWS Account    │      │  Azure Tenant    │        │
│  │  (Test Resources)│      │ (Test Resources) │        │
│  └────────┬─────────┘      └────────┬─────────┘        │
└───────────┼──────────────────────────┼──────────────────┘
            │                          │
            │  ┌───────────────────────┘
            │  │
            ▼  ▼
┌─────────────────────────────────────────────────────────┐
│              Security Scanning Layer                     │
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │     Prowler      │      │   ScoutSuite     │        │
│  │  (AWS Scanner)   │      │  (Multi-Cloud)   │        │
│  └────────┬─────────┘      └────────┬─────────┘        │
└───────────┼──────────────────────────┼──────────────────┘
            │                          │
            └──────────┬───────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│            Aggregation & Processing Layer                │
│              (Python Backend Scripts)                    │
│         - Parse scan results (JSON)                      │
│         - Normalize findings                             │
│         - Calculate risk scores                          │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│              Visualization Dashboard                     │
│         (Grafana / Custom Web Interface)                 │
│    - Findings by severity                                │
│    - Cloud provider comparison                           │
│    - Remediation status tracking                         │
└─────────────────────────────────────────────────────────┘
```

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Cloud Platforms** | AWS, Azure | Target environments for security scanning |
| **IaC Deployment** | Terraform | Deploy test resources with misconfigurations |
| **Security Scanning** | Prowler, ScoutSuite | Automated security assessment tools |
| **Backend Processing** | Python 3.x | Scan result aggregation and analysis |
| **Dashboard** | Grafana / Flask | Findings visualization |
| **Version Control** | Git, GitHub | Source code management |
| **CI/CD** | GitHub Actions | Automated testing and deployment |

## 📋 Prerequisites

Before running this project, ensure you have:

- **Cloud Accounts**:
  - AWS Account with IAM permissions for security audits
  - Azure Subscription with appropriate RBAC roles
- **Tools Installed**:
  - [Terraform](https://www.terraform.io/downloads) >= 1.5.0
  - [Python](https://www.python.org/downloads/) >= 3.9
  - [AWS CLI](https://aws.amazon.com/cli/) configured with credentials
  - [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) configured
  - [Prowler](https://github.com/prowler-cloud/prowler)
  - [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- **Optional**:
  - [Docker](https://www.docker.com/) for containerized deployment
  - [Grafana](https://grafana.com/) for dashboard (if not using custom web app)

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/cloud-security-posture-dashboard.git
cd cloud-security-posture-dashboard
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install scanning tools
pip install prowler
pip install scoutsuite
```

### 3. Configure Cloud Credentials
```bash
# AWS
aws configure

# Azure
az login
```

### 4. Deploy Test Infrastructure
```bash
# Deploy intentionally misconfigured AWS resources
cd terraform/aws
terraform init
terraform plan
terraform apply

# Deploy intentionally misconfigured Azure resources
cd ../azure
terraform init
terraform plan
terraform apply
```

### 5. Run Security Scans
```bash
# Run Prowler scan on AWS
cd ../../scripts/scanning
./run_prowler_scan.sh

# Run ScoutSuite scan on Azure
./run_scoutsuite_scan.sh
```

### 6. Aggregate Results & Launch Dashboard
```bash
# Process scan results
python scripts/scanning/aggregate_findings.py

# Launch dashboard
cd dashboard
python app.py
# OR start Grafana dashboard
```

Visit `http://localhost:3000` (Grafana) or `http://localhost:5000` (Flask app)

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment tool
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing
- [Terraform](https://www.terraform.io/) - Infrastructure as Code
- CIS Benchmarks for cloud security best practices

## 📬 Contact

**Noble Ackerson** - Cybersecurity & Cloud Security Engineer

- GitHub: [@YOUR_GITHUB_USERNAME](https://github.com/YOUR_USERNAME)
- LinkedIn: [Your LinkedIn Profile](https://linkedin.com/in/YOUR_PROFILE)
- Email: your.email@example.com

---

## 🗺️ Roadmap

- [x] Initial project setup and architecture design
- [ ] Deploy AWS test infrastructure with misconfigurations
- [ ] Deploy Azure test infrastructure with misconfigurations
- [ ] Integrate Prowler for AWS scanning
- [ ] Integrate ScoutSuite for multi-cloud scanning
- [ ] Build findings aggregation pipeline
- [ ] Develop dashboard (Grafana/Flask)
- [ ] Create automated remediation scripts
- [ ] Implement CI/CD pipeline
- [ ] Add compliance framework mapping (CIS, NIST)
- [ ] Container deployment (Docker/Kubernetes)
- [ ] Add alerting/notification system

---

**⭐ If you find this project useful, please consider giving it a star!**
