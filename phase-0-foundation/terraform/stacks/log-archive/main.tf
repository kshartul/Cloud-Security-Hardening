###############################################################################
# Stack: log-archive (run in LOG ARCHIVE account)
###############################################################################

terraform {
  required_version = ">= 1.10" # S3 native state locking (use_lockfile)
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-0/log-archive/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.home_region
  default_tags { tags = var.tags }
}

variable "home_region" {
  type    = string
  default = "ap-south-1"
}
variable "organization_id" { type = string }
variable "management_account_id" { type = string }
variable "bucket_name" { type = string }
variable "tags" { type = map(string) }

module "log_bucket" {
  source                = "../../modules/log-archive-bucket"
  bucket_name           = var.bucket_name
  organization_id       = var.organization_id
  management_account_id = var.management_account_id
  retention_days        = 365
  glacier_after_days    = 90
  tags                  = var.tags
}

output "bucket_name" { value = module.log_bucket.bucket_name }
output "kms_key_arn" { value = module.log_bucket.kms_key_arn }
