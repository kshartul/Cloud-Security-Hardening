###############################################################################
# Stack: identity-center (run in MANAGEMENT account, or Identity Center delegated admin)
###############################################################################

terraform {
  required_version = ">= 1.10" # S3 native state locking (use_lockfile)
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-0/identity-center/terraform.tfstate"
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
variable "accounts" {
  description = "Account name => id"
  type        = map(string)
}

locals {
  all_accounts      = values(var.accounts)
  workload_nonprod  = [for k, v in var.accounts : v if can(regex("-(dev|stage)$", k))]
  workload_prod     = [for k, v in var.accounts : v if can(regex("-prod$", k))]
  security_accounts = [var.accounts["security-tooling"], var.accounts["log-archive"]]
}

module "sso" {
  source = "../../modules/identity-center"

  permission_sets = {
    ReadOnly = {
      description      = "Read-only across the account"
      session_duration = "PT8H"
      managed_policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    }
    Developer = {
      description      = "Deploy/debug apps; no IAM/org/security-service admin"
      session_duration = "PT8H"
      managed_policies = ["arn:aws:iam::aws:policy/PowerUserAccess"]
      inline_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Sid      = "DenySecurityServiceAdmin"
          Effect   = "Deny"
          Action   = ["guardduty:*", "securityhub:Disable*", "securityhub:Delete*", "config:Delete*", "config:Stop*", "cloudtrail:*", "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy"]
          Resource = "*"
        }]
      })
    }
    DataEngineer = {
      description      = "DMS / Redshift / Glue / S3 data operations"
      session_duration = "PT8H"
      managed_policies = [
        "arn:aws:iam::aws:policy/AmazonRedshiftFullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        "arn:aws:iam::aws:policy/service-role/AmazonDMSRedshiftS3Role"
      ]
    }
    PlatformAdmin = {
      description      = "Platform team admin (prod session 4h)"
      session_duration = "PT4H"
      managed_policies = ["arn:aws:iam::aws:policy/AdministratorAccess"]
    }
    SecurityReadOnly = {
      description      = "SecOps investigations"
      session_duration = "PT8H"
      managed_policies = ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/ReadOnlyAccess"]
    }
    SecurityOperator = {
      description      = "Triage findings, run playbooks (Security Tooling only)"
      session_duration = "PT8H"
      managed_policies = [
        "arn:aws:iam::aws:policy/AWSSecurityHubFullAccess",
        "arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess",
        "arn:aws:iam::aws:policy/AmazonInspector2FullAccess",
        "arn:aws:iam::aws:policy/AmazonDetectiveFullAccess",
        "arn:aws:iam::aws:policy/AWSStepFunctionsConsoleFullAccess"
      ]
    }
  }

  assignments = [
    { group = "aws-readonly", permission_set = "ReadOnly", account_ids = local.all_accounts },
    { group = "aws-developers", permission_set = "Developer", account_ids = local.workload_nonprod },
    { group = "aws-developers", permission_set = "ReadOnly", account_ids = local.workload_prod },
    { group = "aws-data-engineers", permission_set = "DataEngineer", account_ids = local.workload_nonprod },
    { group = "aws-platform-admins", permission_set = "PlatformAdmin", account_ids = local.all_accounts },
    { group = "aws-secops", permission_set = "SecurityReadOnly", account_ids = local.all_accounts },
    { group = "aws-secops", permission_set = "SecurityOperator", account_ids = local.security_accounts },
  ]
}
