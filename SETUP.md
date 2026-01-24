# Setup Guide

Complete guide to set up and run the Cloud Security Posture Dashboard project.

## Prerequisites Checklist

Before starting, ensure you have:

- [ ] **AWS Account** with IAM user/role with security audit permissions
- [ ] **Azure Subscription** with appropriate RBAC access
- [ ] **Git** installed
- [ ] **Python 3.9+** installed
- [ ] **Terraform 1.5+** installed
- [ ] **AWS CLI** installed and configured
- [ ] **Azure CLI** installed and configured
- [ ] **Code editor** (VS Code recommended)

## Step-by-Step Setup

### 1. Clone and Navigate to Project

```bash
# Clone your forked repository
git clone https://github.com/YOUR_USERNAME/cloud-security-posture-dashboard.git
cd cloud-security-posture-dashboard
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install security scanning tools
pip install prowler scoutsuite
```

### 3. Configure Cloud Credentials

#### AWS Setup
```bash
# Configure AWS CLI
aws configure
# Enter:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (e.g., us-east-1)
# - Output format (json)

# Verify credentials
aws sts get-caller-identity
```

#### Azure Setup
```bash
# Login to Azure
az login

# List subscriptions
az account list --output table

# Set default subscription (if you have multiple)
az account set --subscription "YOUR_SUBSCRIPTION_ID"

# Verify login
az account show
```

### 4. Deploy Test Infrastructure (AWS First)

```bash
cd terraform/aws

# Initialize Terraform
terraform init

# Review what will be created
terraform plan

# Deploy resources (start with AWS)
terraform apply
# Type 'yes' when prompted

# Note the outputs
```

**Important**: These resources are intentionally misconfigured. Do NOT use in production.

### 5. Run Your First Security Scan

```bash
cd ../../scripts/scanning

# Make scripts executable
chmod +x run_prowler_scan.sh
chmod +x run_scoutsuite_scan.sh

# Run Prowler scan on AWS
./run_prowler_scan.sh

# This will take 5-15 minutes depending on resources
```

### 6. Aggregate Findings

```bash
# Still in scripts/scanning directory
python aggregate_findings.py

# This will:
# - Parse Prowler results
# - Create consolidated JSON/CSV
# - Generate summary statistics
```

### 7. View Results

Initial results will be in:
- `scan-results/prowler/` - Prowler HTML reports
- `scan-results/aggregated/` - Consolidated findings

**Next Steps**: Build the dashboard to visualize these findings!

---

## Troubleshooting

### AWS Credential Issues

**Problem**: `Unable to locate credentials`

**Solution**:
```bash
# Check credentials are configured
aws configure list

# Verify credentials work
aws sts get-caller-identity

# Check environment variables
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY
```

### Azure Login Issues

**Problem**: `az login` not working

**Solution**:
```bash
# Try device code flow
az login --use-device-code

# Or specify tenant
az login --tenant YOUR_TENANT_ID
```

### Terraform State Issues

**Problem**: Terraform state conflicts

**Solution**:
```bash
cd terraform/aws

# Remove local state (be careful!)
rm -rf .terraform
rm terraform.tfstate*

# Reinitialize
terraform init
```

### Prowler Installation Issues

**Problem**: `prowler: command not found`

**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall prowler
pip install --upgrade prowler

# Verify installation
prowler --version
```

### Python Module Not Found

**Problem**: `ModuleNotFoundError: No module named 'X'`

**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall requirements
pip install -r requirements.txt

# If specific module missing
pip install MODULE_NAME
```

---

## Development Workflow

### Daily Workflow

1. **Pull latest changes**
   ```bash
   git pull origin main
   ```

2. **Activate virtual environment**
   ```bash
   source venv/bin/activate
   ```

3. **Work on feature**
   ```bash
   git checkout -b feature/your-feature-name
   # Make changes
   ```

4. **Test your changes**
   ```bash
   pytest tests/
   black scripts/  # Format code
   ```

5. **Commit and push**
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin feature/your-feature-name
   ```

### Creating Pull Requests

1. Go to GitHub repository
2. Click "Pull Requests" → "New Pull Request"
3. Select your branch
4. Describe your changes
5. Submit for review

---

## Next Steps After Setup

Now that your environment is ready, here's the recommended order to build the project:

### Phase 1: AWS Foundation (Week 1)
- [ ] Create 3-5 intentional AWS misconfigurations in Terraform
- [ ] Run Prowler scans successfully
- [ ] Parse Prowler JSON output
- [ ] Create basic aggregation script

### Phase 2: Dashboard MVP (Week 1-2)
- [ ] Build simple Flask web app
- [ ] Display findings in a table
- [ ] Add basic filtering (by severity)
- [ ] Create summary statistics display

### Phase 3: Azure Expansion (Week 2)
- [ ] Add Azure misconfigurations in Terraform
- [ ] Run ScoutSuite scans
- [ ] Integrate Azure findings into aggregation
- [ ] Update dashboard for multi-cloud view

### Phase 4: Visualization & Polish (Week 2-3)
- [ ] Add charts (severity distribution, cloud comparison)
- [ ] Implement Grafana OR enhance custom dashboard
- [ ] Add remediation script stubs
- [ ] Create comprehensive documentation

### Phase 5: Advanced Features (Optional)
- [ ] Automated remediation scripts
- [ ] Historical trending
- [ ] Email alerts
- [ ] CI/CD integration

---

## Helpful Commands Reference

### Terraform
```bash
terraform init          # Initialize working directory
terraform plan          # Preview changes
terraform apply         # Apply changes
terraform destroy       # Remove all resources
terraform fmt           # Format .tf files
terraform validate      # Check configuration
```

### Python
```bash
python script.py        # Run script
pytest                  # Run tests
black .                 # Format code
flake8 .               # Lint code
pip freeze > requirements.txt  # Save dependencies
```

### Git
```bash
git status             # Check status
git add .              # Stage all changes
git commit -m "msg"    # Commit changes
git push               # Push to remote
git pull               # Pull updates
git branch             # List branches
git checkout -b name   # Create new branch
```

---

## Getting Help

- **GitHub Issues**: Report bugs or request features
- **Documentation**: Check `docs/` directory
- **Community**: Reach out to security community forums

---

## Cost Estimation

### AWS (Minimal Setup)
- S3 bucket: $0.00 (free tier)
- Security groups: Free
- IAM roles: Free
- CloudTrail: ~$2/month
- **Estimated monthly cost**: $2-5

### Azure (Minimal Setup)
- Storage account: ~$1/month
- NSG: Free
- RBAC: Free
- **Estimated monthly cost**: $1-3

**Total estimated cost**: $3-8/month

**Cost-saving tips**:
- Use smallest regions
- Delete resources when not in use
- Leverage free tiers
- Set billing alerts

---

## Success Checklist

You're ready to start building when you can:

- [ ] Successfully run `terraform apply` in terraform/aws
- [ ] Run Prowler scan without errors
- [ ] See scan results in JSON format
- [ ] Run aggregation script successfully
- [ ] View Prowler HTML report in browser
- [ ] Understand the project structure

**Ready to build? Start with Phase 1 above!**
