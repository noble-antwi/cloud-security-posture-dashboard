# =============================================================================
# AZURE SECURITY TEST INFRASTRUCTURE
# =============================================================================
# This Terraform configuration deploys INTENTIONALLY MISCONFIGURED Azure
# resources for security scanning practice. These resources have security
# vulnerabilities that security scanners like ScoutSuite will detect.
#
# WARNING: These resources are insecure by design. Only deploy in test
# environments and destroy after testing.
# =============================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  required_version = ">= 1.0.0"
}

# Configure the Azure Provider
# Credentials come from ARM_* environment variables
provider "azurerm" {
  features {}
}

# =============================================================================
# VARIABLES
# =============================================================================

variable "environment" {
  description = "Environment name for tagging"
  type        = string
  default     = "security-test"
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "East US"
}

# Random suffix for globally unique names
resource "random_id" "suffix" {
  byte_length = 4
}

# =============================================================================
# RESOURCE GROUP
# =============================================================================
# All test resources will be in this resource group for easy cleanup

resource "azurerm_resource_group" "security_test" {
  name     = "rg-security-test-${random_id.suffix.hex}"
  location = var.location

  tags = {
    Environment    = var.environment
    Purpose        = "Security Testing"
    SecurityStatus = "Intentionally Misconfigured"
  }
}

# =============================================================================
# MISCONFIGURED STORAGE ACCOUNT #1: No Encryption + HTTP Allowed
# =============================================================================
# Security Issues:
# - HTTPS not enforced (allows unencrypted HTTP traffic)
# - Blob public access enabled
# - No infrastructure encryption
# - Shared key access enabled (less secure than Azure AD)

resource "azurerm_storage_account" "insecure_storage" {
  name                     = "insecure${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.security_test.name
  location                 = azurerm_resource_group.security_test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # SECURITY ISSUE: Allow HTTP (unencrypted) traffic
  enable_https_traffic_only = false

  # SECURITY ISSUE: Allow public access to blobs
  allow_nested_items_to_be_public = true

  # SECURITY ISSUE: Shared key access enabled (prefer Azure AD)
  shared_access_key_enabled = true

  # SECURITY ISSUE: Minimum TLS version not set to latest
  min_tls_version = "TLS1_0"

  tags = {
    Environment    = var.environment
    SecurityStatus = "Misconfigured - No HTTPS enforcement"
  }
}

# Create a container with public access
resource "azurerm_storage_container" "public_container" {
  name                 = "public-data"
  storage_account_name = azurerm_storage_account.insecure_storage.name

  # SECURITY ISSUE: Container is publicly accessible
  container_access_type = "blob"
}

# =============================================================================
# MISCONFIGURED STORAGE ACCOUNT #2: No Soft Delete + No Versioning
# =============================================================================
# Security Issues:
# - No blob soft delete (can't recover deleted data)
# - No container soft delete
# - No versioning enabled

resource "azurerm_storage_account" "no_recovery_storage" {
  name                     = "norecovery${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.security_test.name
  location                 = azurerm_resource_group.security_test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # SECURITY ISSUE: No soft delete configured
  # blob_properties not configured = no soft delete or versioning

  tags = {
    Environment    = var.environment
    SecurityStatus = "Misconfigured - No data recovery options"
  }
}

# =============================================================================
# MISCONFIGURED NETWORK SECURITY GROUP: Overly Permissive Rules
# =============================================================================
# Security Issues:
# - SSH (22) open to the entire internet (0.0.0.0/0)
# - RDP (3389) open to the entire internet
# - All ports open from any source

resource "azurerm_network_security_group" "insecure_nsg" {
  name                = "nsg-insecure-${random_id.suffix.hex}"
  location            = azurerm_resource_group.security_test.location
  resource_group_name = azurerm_resource_group.security_test.name

  # SECURITY ISSUE: SSH open to the world
  security_rule {
    name                       = "Allow-SSH-From-Internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*" # DANGEROUS: Any IP can access
    destination_address_prefix = "*"
  }

  # SECURITY ISSUE: RDP open to the world
  security_rule {
    name                       = "Allow-RDP-From-Internet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*" # DANGEROUS: Any IP can access
    destination_address_prefix = "*"
  }

  # SECURITY ISSUE: All ports open
  security_rule {
    name                       = "Allow-All-Inbound"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*" # DANGEROUS: Everything allowed
    destination_address_prefix = "*"
  }

  tags = {
    Environment    = var.environment
    SecurityStatus = "Misconfigured - Overly permissive rules"
  }
}

# =============================================================================
# VIRTUAL NETWORK (Required for NSG association demo)
# =============================================================================

resource "azurerm_virtual_network" "test_vnet" {
  name                = "vnet-security-test-${random_id.suffix.hex}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.security_test.location
  resource_group_name = azurerm_resource_group.security_test.name

  tags = {
    Environment = var.environment
  }
}

resource "azurerm_subnet" "test_subnet" {
  name                 = "subnet-test"
  resource_group_name  = azurerm_resource_group.security_test.name
  virtual_network_name = azurerm_virtual_network.test_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Associate the insecure NSG with the subnet
resource "azurerm_subnet_network_security_group_association" "insecure_association" {
  subnet_id                 = azurerm_subnet.test_subnet.id
  network_security_group_id = azurerm_network_security_group.insecure_nsg.id
}

# =============================================================================
# MISCONFIGURED KEY VAULT: Overly Permissive Access
# =============================================================================
# Security Issues:
# - Public network access enabled
# - Soft delete disabled (if possible)
# - No purge protection

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "insecure_vault" {
  name                = "kv-insecure-${random_id.suffix.hex}"
  location            = azurerm_resource_group.security_test.location
  resource_group_name = azurerm_resource_group.security_test.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  # SECURITY ISSUE: Public network access (should be private endpoint only)
  public_network_access_enabled = true

  # SECURITY ISSUE: No purge protection
  purge_protection_enabled = false

  # SECURITY ISSUE: Soft delete with minimum retention
  soft_delete_retention_days = 7

  # Access policy for current user (needed to manage vault)
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Purge"
    ]

    key_permissions = [
      "Get", "List", "Create", "Delete", "Purge"
    ]
  }

  tags = {
    Environment    = var.environment
    SecurityStatus = "Misconfigured - Public access enabled"
  }
}

# =============================================================================
# OUTPUTS
# =============================================================================
# Display information about created resources

output "resource_group_name" {
  description = "Name of the resource group containing test resources"
  value       = azurerm_resource_group.security_test.name
}

output "insecure_storage_account" {
  description = "Storage account with HTTP allowed and public access"
  value       = azurerm_storage_account.insecure_storage.name
}

output "no_recovery_storage_account" {
  description = "Storage account without soft delete or versioning"
  value       = azurerm_storage_account.no_recovery_storage.name
}

output "insecure_nsg_name" {
  description = "NSG with SSH/RDP open to internet"
  value       = azurerm_network_security_group.insecure_nsg.name
}

output "insecure_key_vault" {
  description = "Key Vault with public access enabled"
  value       = azurerm_key_vault.insecure_vault.name
}

output "cleanup_command" {
  description = "Command to destroy all test resources"
  value       = "terraform destroy"
}
