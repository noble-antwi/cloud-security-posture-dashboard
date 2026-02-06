#!/bin/bash
# =============================================================================
# MULTI-ACCOUNT AWS SECURITY SCANNING SCRIPT
# =============================================================================
#
# This script runs Prowler security scans across multiple AWS accounts and
# organizes the results into account-specific subdirectories.
#
# SUPPORTED APPROACHES:
# ---------------------
# 1. AWS Profiles (--profiles): Use named profiles from ~/.aws/credentials
# 2. Assume Role (--role-arn): Assume a role in each target account
# 3. AWS Organizations (--org): Auto-discover accounts from Organizations
#
# USAGE EXAMPLES:
# ---------------
# Using AWS profiles:
#   ./run_multi_account_scan.sh --profiles "prod,staging,dev"
#
# Using assume role (with account IDs):
#   ./run_multi_account_scan.sh --role-arn "arn:aws:iam::ACCOUNT_ID:role/SecurityAuditRole" \
#                               --accounts "111111111111,222222222222,333333333333"
#
# Full scan with specific service:
#   ./run_multi_account_scan.sh --profiles "prod,dev" --service s3
#
# Quick scan (S3 only):
#   ./run_multi_account_scan.sh --profiles "prod" --quick
#
# =============================================================================

set -e

# Default values
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
OUTPUT_DIR="$PROJECT_ROOT/output"
SERVICE=""
QUICK_MODE=false
PROFILES=""
ACCOUNTS=""
ROLE_ARN=""
USE_ORG=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

print_banner() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "  MULTI-ACCOUNT AWS SECURITY SCANNER"
    echo "============================================================"
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Multi-account AWS security scanning using Prowler.

Options:
  --profiles PROFILES    Comma-separated list of AWS profile names
                         Example: --profiles "prod,staging,dev"

  --accounts ACCOUNTS    Comma-separated list of AWS account IDs
                         (use with --role-arn)
                         Example: --accounts "111111111111,222222222222"

  --role-arn ARN         IAM role ARN to assume in each account
                         Use ACCOUNT_ID as placeholder for the account ID
                         Example: --role-arn "arn:aws:iam::ACCOUNT_ID:role/AuditRole"

  --org                  Use AWS Organizations to discover accounts
                         (requires organizations:ListAccounts permission)

  --service SERVICE      Limit scan to specific service (e.g., s3, iam, ec2)

  --quick                Quick scan mode (S3 service only)

  --output-dir DIR       Custom output directory (default: $OUTPUT_DIR)

  -h, --help             Show this help message

Examples:
  # Scan using AWS profiles
  $(basename "$0") --profiles "production,development"

  # Scan specific accounts using assume role
  $(basename "$0") --accounts "111111111111,222222222222" \\
                   --role-arn "arn:aws:iam::ACCOUNT_ID:role/SecurityAuditRole"

  # Quick S3-only scan
  $(basename "$0") --profiles "prod" --quick

  # Scan specific service across profiles
  $(basename "$0") --profiles "prod,dev" --service iam

EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --profiles)
                PROFILES="$2"
                shift 2
                ;;
            --accounts)
                ACCOUNTS="$2"
                shift 2
                ;;
            --role-arn)
                ROLE_ARN="$2"
                shift 2
                ;;
            --org)
                USE_ORG=true
                shift
                ;;
            --service)
                SERVICE="$2"
                shift 2
                ;;
            --quick)
                QUICK_MODE=true
                SERVICE="s3"
                shift
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -h|--help)
                usage
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Get account ID from current credentials
get_account_id() {
    aws sts get-caller-identity --query "Account" --output text 2>/dev/null
}

# Get account alias (friendly name)
get_account_alias() {
    local alias
    alias=$(aws iam list-account-aliases --query "AccountAliases[0]" --output text 2>/dev/null)
    if [[ "$alias" == "None" ]] || [[ -z "$alias" ]]; then
        echo ""
    else
        echo "$alias"
    fi
}

# Run Prowler scan for a single account
run_prowler_scan() {
    local account_id="$1"
    local profile="$2"
    local role_arn="$3"

    local account_output_dir="$OUTPUT_DIR/$account_id"
    mkdir -p "$account_output_dir"

    print_info "Scanning account: $account_id"

    # Build Prowler command
    local prowler_cmd="prowler aws"

    # Add profile if specified
    if [[ -n "$profile" ]]; then
        prowler_cmd+=" --profile $profile"
        print_info "  Using profile: $profile"
    fi

    # Add assume role if specified
    if [[ -n "$role_arn" ]]; then
        # Replace ACCOUNT_ID placeholder with actual account ID
        local resolved_role_arn="${role_arn//ACCOUNT_ID/$account_id}"
        prowler_cmd+=" --role $resolved_role_arn"
        print_info "  Assuming role: $resolved_role_arn"
    fi

    # Add service filter if specified
    if [[ -n "$SERVICE" ]]; then
        prowler_cmd+=" --service $SERVICE"
        print_info "  Service filter: $SERVICE"
    fi

    # Add output directory
    prowler_cmd+=" --output-directory $account_output_dir"
    prowler_cmd+=" --output-formats json"

    print_info "  Output directory: $account_output_dir"
    echo ""

    # Run Prowler
    if eval "$prowler_cmd"; then
        print_success "Completed scan for account $account_id"
    else
        print_warning "Scan completed with warnings for account $account_id"
    fi
    echo ""
}

# Scan using AWS profiles
scan_with_profiles() {
    IFS=',' read -ra PROFILE_ARRAY <<< "$PROFILES"

    print_info "Scanning ${#PROFILE_ARRAY[@]} account(s) using AWS profiles"
    echo ""

    for profile in "${PROFILE_ARRAY[@]}"; do
        # Trim whitespace
        profile=$(echo "$profile" | xargs)

        # Get account ID for this profile
        export AWS_PROFILE="$profile"
        local account_id
        account_id=$(get_account_id)

        if [[ -z "$account_id" ]]; then
            print_error "Could not get account ID for profile: $profile"
            continue
        fi

        run_prowler_scan "$account_id" "$profile" ""
    done

    unset AWS_PROFILE
}

# Scan using assume role
scan_with_assume_role() {
    IFS=',' read -ra ACCOUNT_ARRAY <<< "$ACCOUNTS"

    print_info "Scanning ${#ACCOUNT_ARRAY[@]} account(s) using assume role"
    echo ""

    for account_id in "${ACCOUNT_ARRAY[@]}"; do
        # Trim whitespace
        account_id=$(echo "$account_id" | xargs)

        run_prowler_scan "$account_id" "" "$ROLE_ARN"
    done
}

# Scan using AWS Organizations
scan_with_organizations() {
    print_info "Discovering accounts from AWS Organizations..."

    # Get list of accounts from Organizations
    local accounts_json
    accounts_json=$(aws organizations list-accounts --query "Accounts[?Status=='ACTIVE'].Id" --output text 2>/dev/null)

    if [[ -z "$accounts_json" ]]; then
        print_error "Could not list accounts from AWS Organizations"
        print_error "Ensure you have organizations:ListAccounts permission"
        exit 1
    fi

    # Convert to array
    IFS=$'\t' read -ra ACCOUNT_ARRAY <<< "$accounts_json"

    print_info "Found ${#ACCOUNT_ARRAY[@]} active account(s)"
    echo ""

    for account_id in "${ACCOUNT_ARRAY[@]}"; do
        # Skip management account if no role specified
        if [[ -z "$ROLE_ARN" ]]; then
            local current_account
            current_account=$(get_account_id)
            if [[ "$account_id" == "$current_account" ]]; then
                run_prowler_scan "$account_id" "" ""
            else
                print_warning "Skipping account $account_id (no role specified for cross-account access)"
            fi
        else
            run_prowler_scan "$account_id" "" "$ROLE_ARN"
        fi
    done
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    print_banner
    parse_args "$@"

    # Validate inputs
    if [[ -z "$PROFILES" ]] && [[ -z "$ACCOUNTS" ]] && [[ "$USE_ORG" == false ]]; then
        print_error "You must specify one of: --profiles, --accounts (with --role-arn), or --org"
        echo ""
        usage
    fi

    if [[ -n "$ACCOUNTS" ]] && [[ -z "$ROLE_ARN" ]]; then
        print_error "--accounts requires --role-arn to be specified"
        exit 1
    fi

    # Check if Prowler is installed
    if ! command -v prowler &> /dev/null; then
        print_error "Prowler is not installed. Install with: pip install prowler"
        exit 1
    fi

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Record start time
    local start_time
    start_time=$(date +%s)

    # Run scans based on approach
    if [[ -n "$PROFILES" ]]; then
        scan_with_profiles
    elif [[ -n "$ACCOUNTS" ]]; then
        scan_with_assume_role
    elif [[ "$USE_ORG" == true ]]; then
        scan_with_organizations
    fi

    # Calculate duration
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  SCAN COMPLETE${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    print_info "Duration: ${minutes}m ${seconds}s"
    print_info "Output directory: $OUTPUT_DIR"
    echo ""
    print_info "Next steps:"
    echo "  1. Aggregate findings:"
    echo "     python $PROJECT_ROOT/scripts/scanning/aggregate_findings.py"
    echo ""
    echo "  2. Launch dashboard:"
    echo "     python $PROJECT_ROOT/dashboard/app.py"
    echo ""
}

main "$@"
