###############################################################################
# Stack: security-tooling (run in SECURITY TOOLING account)
# Applies the security-baseline module in the home region and the regional
# services (GuardDuty) in each additional region.
###############################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-1/security-tooling/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

variable "security_tooling_account_id" { type = string }
variable "organization_id" { type = string }
variable "root_id" { type = string }
variable "policy_target_ous" { type = list(string) }
variable "log_archive_bucket" { type = string }
variable "log_archive_kms_arn" { type = string }
variable "tags" { type = map(string) }

provider "aws" {
  region = "ap-south-1"
  assume_role {
    role_arn = "arn:aws:iam::${var.security_tooling_account_id}:role/SecurityPipelineDeploy"
  }
  default_tags { tags = var.tags }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${var.security_tooling_account_id}:role/SecurityPipelineDeploy"
  }
  default_tags { tags = var.tags }
}

module "baseline" {
  source                      = "../../modules/security-baseline"
  home_region                 = "ap-south-1"
  linked_regions              = ["us-east-1"]
  organization_id             = var.organization_id
  root_id                     = var.root_id
  policy_target_ous           = var.policy_target_ous
  config_bucket_name          = var.log_archive_bucket
  guardduty_export_bucket_arn = "arn:aws:s3:::${var.log_archive_bucket}"
  guardduty_export_kms_arn    = var.log_archive_kms_arn
  tags                        = var.tags
}

# GuardDuty is regional — repeat detector + org config in us-east-1
module "guardduty_us_east_1" {
  source = "../../modules/guardduty-regional"
  providers = {
    aws = aws.us_east_1
  }
  export_bucket_arn = "arn:aws:s3:::${var.log_archive_bucket}"
  export_kms_arn    = var.log_archive_kms_arn
  tags              = var.tags
}

module "access_analyzer" {
  source = "../../../../phase-0-foundation/terraform/modules/access-analyzer"
  tags   = var.tags
}
