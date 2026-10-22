###############################################################################
# Stack: account-baseline — applied to EVERY account by the pipeline matrix.
#   terraform workspace select <account-name>   (one workspace per account)
#   TF_VAR_target_account_id=<id> terraform apply
###############################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key                  = "baseline.tfstate"
    workspace_key_prefix = "phase-0/account-baseline"
    encrypt              = true
    use_lockfile         = true
  }
}

variable "target_account_id" { type = string }
variable "home_region" {
  type    = string
  default = "ap-south-1"
}
variable "security_tooling_account_id" {
  type    = string
  default = "222222222222"
}
variable "is_workload_account" {
  type    = bool
  default = true
}
variable "tags" {
  type = map(string)
  default = {
    owner        = "cloud-platform"
    service      = "account-baseline"
    "managed-by" = "terraform"
  }
}

provider "aws" {
  region = var.home_region
  assume_role {
    role_arn     = "arn:aws:iam::${var.target_account_id}:role/SecurityPipelineDeploy"
    session_name = "account-baseline"
  }
  default_tags { tags = var.tags }
}

module "defaults" {
  source             = "../../modules/account-defaults"
  create_domain_keys = var.is_workload_account
  tags               = var.tags
}

# Remediation role assumed by SOAR playbooks in Security Tooling (Phase 6)
module "remediation_role" {
  source                      = "../../../../phase-6-integration/terraform/modules/remediation-role"
  security_tooling_account_id = var.security_tooling_account_id
  tags                        = var.tags
}

# Forward sign-in / break-glass / IAM-user events to Security Tooling (Phase 6).
# Console sign-in events are emitted in us-east-1, so forward from both regions.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  assume_role {
    role_arn     = "arn:aws:iam::${var.target_account_id}:role/SecurityPipelineDeploy"
    session_name = "account-baseline"
  }
  default_tags { tags = var.tags }
}

module "event_forwarder_home" {
  count                       = var.target_account_id == var.security_tooling_account_id ? 0 : 1 # avoid forwarding loop
  source                      = "../../../../phase-6-integration/terraform/modules/event-forwarder"
  security_tooling_account_id = var.security_tooling_account_id
}

module "event_forwarder_us_east_1" {
  count                       = var.target_account_id == var.security_tooling_account_id ? 0 : 1
  source                      = "../../../../phase-6-integration/terraform/modules/event-forwarder"
  providers                   = { aws = aws.us_east_1 }
  security_tooling_account_id = var.security_tooling_account_id
}
