#!/bin/bash

# Prowler AWS Security Scanning Script
# This script runs Prowler against AWS account and saves results

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_DIR="../../scan-results/prowler"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}/prowler_scan_${TIMESTAMP}"

echo -e "${GREEN}Starting Prowler AWS Security Scan...${NC}"
echo "Timestamp: ${TIMESTAMP}"
echo "Output directory: ${OUTPUT_DIR}"

# Create output directory if it doesn't exist
mkdir -p ${OUTPUT_DIR}

# Check if Prowler is installed
if ! command -v prowler &> /dev/null; then
    echo -e "${RED}Prowler is not installed. Installing...${NC}"
    pip install prowler
fi

# Check AWS credentials
echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}AWS credentials not configured. Please run 'aws configure'${NC}"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "${GREEN}Scanning AWS Account: ${ACCOUNT_ID}${NC}"

# Run Prowler scan
# Adjust these flags based on your needs:
# -M json,html,csv  : Output formats
# -F output_file    : Output file base name
# -z                : Don't display Prowler banner
echo -e "${YELLOW}Running Prowler scan... This may take several minutes.${NC}"

prowler aws \
  --output-formats json html csv \
  --output-directory ${OUTPUT_DIR} \
  --output-filename prowler_scan_${TIMESTAMP} \
  --no-banner \
  || { echo -e "${RED}Prowler scan failed${NC}"; exit 1; }

echo -e "${GREEN}Prowler scan completed successfully!${NC}"
echo -e "Results saved to: ${OUTPUT_DIR}/prowler_scan_${TIMESTAMP}"
echo ""
echo -e "${YELLOW}Summary:${NC}"
echo "- JSON: ${OUTPUT_FILE}.json"
echo "- HTML: ${OUTPUT_FILE}.html"
echo "- CSV:  ${OUTPUT_FILE}.csv"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Review the HTML report: open ${OUTPUT_FILE}.html"
echo "2. Run the aggregation script to process findings"
echo "3. View results in the dashboard"
