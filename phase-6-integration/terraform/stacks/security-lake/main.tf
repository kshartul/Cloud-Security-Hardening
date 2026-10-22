###############################################################################
# Stack: security-lake (run in LOG ARCHIVE — Security Lake delegated admin)
###############################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-6/security-lake/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

variable "log_archive_account_id" { type = string }
variable "kms_key_arn" { type = string }
variable "siem_account_id" { type = string }
variable "siem_external_id" {
  type      = string
  sensitive = true
}
variable "siem_name" {
  type    = string
  default = "enterprise-siem"
}

provider "aws" {
  region = "ap-south-1"
  assume_role {
    role_arn = "arn:aws:iam::${var.log_archive_account_id}:role/SecurityPipelineDeploy"
  }
}

module "lake" {
  source      = "../../modules/security-lake"
  kms_key_arn = var.kms_key_arn
  subscriber_principal = {
    account_id  = var.siem_account_id
    external_id = var.siem_external_id
    name        = var.siem_name
  }
  subscriber_access_type = "S3"
}

output "subscriber_role_arn" { value = module.lake.subscriber_role_arn }
