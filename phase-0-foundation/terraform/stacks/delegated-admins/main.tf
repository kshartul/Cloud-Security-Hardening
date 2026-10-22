###############################################################################
# Stack: delegated-admins (run in MANAGEMENT account)
# Registers the Security Tooling account as delegated administrator for every
# security service. Must run before phase-1 security-baseline.
###############################################################################

terraform {
  required_version = ">= 1.10" # S3 native state locking (use_lockfile)
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-0/delegated-admins/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.home_region
}

variable "home_region" {
  type    = string
  default = "ap-south-1"
}
variable "security_tooling_account_id" { type = string }
variable "log_archive_account_id" { type = string }
variable "enabled_regions" {
  description = "GuardDuty/Inspector/Macie/Detective admin is regional — one apply per region (pipeline matrix)"
  type        = list(string)
  default     = ["ap-south-1"]
}

# Prerequisite: trusted access (aws_service_access_principals) is enabled for every service
# below — Control Tower enables most; verify with
#   aws organizations list-aws-service-access-for-organization
#
# Generic delegated admin only for services WITHOUT their own admin API.
# (Security Hub, GuardDuty, Inspector, Macie, Detective and FMS register themselves via
#  the service-specific resources further down; registering them twice fails.)
resource "aws_organizations_delegated_administrator" "this" {
  for_each = toset([
    "config.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "access-analyzer.amazonaws.com",
  ])
  account_id        = var.security_tooling_account_id
  service_principal = each.key
}

# Security Lake admin lives in Log Archive
resource "aws_organizations_delegated_administrator" "securitylake" {
  account_id        = var.log_archive_account_id
  service_principal = "securitylake.amazonaws.com"
}

# Service-specific admin registration
resource "aws_securityhub_organization_admin_account" "this" {
  admin_account_id = var.security_tooling_account_id
}

resource "aws_guardduty_organization_admin_account" "this" {
  admin_account_id = var.security_tooling_account_id
}

resource "aws_inspector2_delegated_admin_account" "this" {
  account_id = var.security_tooling_account_id
}

resource "aws_macie2_organization_admin_account" "this" {
  admin_account_id = var.security_tooling_account_id
}

resource "aws_detective_organization_admin_account" "this" {
  account_id = var.security_tooling_account_id
}

resource "aws_fms_admin_account" "this" {
  account_id = var.security_tooling_account_id
}
