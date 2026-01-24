#!/bin/bash

# ScoutSuite Multi-Cloud Security Scanning Script
# This script runs ScoutSuite against Azure (and optionally AWS)

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_DIR="../../scan-results/scoutsuite"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   ScoutSuite Security Scanner         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Create output directory
mkdir -p ${OUTPUT_DIR}

# Check if ScoutSuite is installed
if ! command -v scout &> /dev/null; then
    echo -e "${RED}ScoutSuite is not installed. Installing...${NC}"
    pip install scoutsuite
fi

# Function to scan Azure
scan_azure() {
    echo -e "${YELLOW}Scanning Azure environment...${NC}"
    
    # Check if Azure CLI is logged in
    if ! az account show &> /dev/null; then
        echo -e "${RED}Not logged in to Azure. Please run 'az login'${NC}"
        return 1
    fi
    
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    echo -e "${GREEN}Scanning Azure Subscription: ${SUBSCRIPTION_ID}${NC}"
    
    scout azure \
        --report-dir ${OUTPUT_DIR}/azure_${TIMESTAMP} \
        --report-name azure_security_report \
        --force \
        || { echo -e "${RED}Azure scan failed${NC}"; return 1; }
    
    echo -e "${GREEN}Azure scan completed!${NC}"
    echo "Report: ${OUTPUT_DIR}/azure_${TIMESTAMP}/azure_security_report.html"
}

# Function to scan AWS (optional, Prowler is preferred for AWS)
scan_aws() {
    echo -e "${YELLOW}Scanning AWS environment...${NC}"
    
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}AWS credentials not configured${NC}"
        return 1
    fi
    
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    echo -e "${GREEN}Scanning AWS Account: ${ACCOUNT_ID}${NC}"
    
    scout aws \
        --report-dir ${OUTPUT_DIR}/aws_${TIMESTAMP} \
        --report-name aws_security_report \
        --force \
        || { echo -e "${RED}AWS scan failed${NC}"; return 1; }
    
    echo -e "${GREEN}AWS scan completed!${NC}"
    echo "Report: ${OUTPUT_DIR}/aws_${TIMESTAMP}/aws_security_report.html"
}

# Main execution
echo -e "${YELLOW}Which cloud provider would you like to scan?${NC}"
echo "1) Azure only"
echo "2) AWS only"
echo "3) Both Azure and AWS"
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        scan_azure
        ;;
    2)
        scan_aws
        ;;
    3)
        scan_azure
        scan_aws
        ;;
    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}═══════════════════════════════════${NC}"
echo -e "${GREEN}Scan completed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Open the HTML reports to review findings"
echo "2. Run the aggregation script to process results"
echo "3. View findings in the dashboard"
