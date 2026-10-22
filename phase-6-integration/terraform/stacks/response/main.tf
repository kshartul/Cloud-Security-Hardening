###############################################################################
# Stack: response (run in SECURITY TOOLING) — alert routing + SOAR
###############################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
  backend "s3" {
    key          = "phase-6/response/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = "ap-south-1"
  default_tags {
    tags = { owner = "security", service = "soar", environment = "security", "managed-by" = "terraform" }
  }
}

variable "kms_key_arn" { type = string }
variable "notify_topic_arn" { type = string } # from phase-4 stack
variable "pager_topic_arn" { type = string }  # from phase-4 stack
variable "pagerduty_routing_key" {
  type      = string
  sensitive = true
}
variable "organization_id" { type = string }
variable "prod_account_ids" { type = list(string) }
variable "forensics_account_id" { type = string }
variable "soar_dry_run" {
  type    = bool
  default = true
}

module "alerts" {
  source                = "../../modules/alert-routing"
  pagerduty_routing_key = var.pagerduty_routing_key
  organization_id       = var.organization_id
  kms_key_arn           = var.kms_key_arn
}

module "soar" {
  source               = "../../modules/soar"
  notify_topic_arn     = var.notify_topic_arn
  pager_topic_arn      = var.pager_topic_arn
  approval_topic_arn   = module.alerts.chat_topic_arns["sec-oncall"]
  prod_account_ids     = var.prod_account_ids
  forensics_account_id = var.forensics_account_id
  kms_key_arn          = var.kms_key_arn
  dry_run              = var.soar_dry_run
}
