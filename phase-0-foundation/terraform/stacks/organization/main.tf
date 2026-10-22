###############################################################################
# Stack: organization (run in MANAGEMENT account)
# - OU tree, SCP library + staged attachments
###############################################################################

terraform {
  required_version = ">= 1.10" # S3 native state locking (use_lockfile)
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-0/organization/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
    # bucket / region supplied by -backend-config=backend.hcl (repo root)
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
variable "allowed_regions" { type = list(string) }
variable "scp_attach_ous" {
  description = "Short OU names that currently receive the guardrail SCPs (promotion list)"
  type        = list(string)
}
variable "tags" { type = map(string) }

data "aws_organizations_organization" "this" {}

locals {
  root_id = data.aws_organizations_organization.this.roots[0].id
}

# ---------------- OU tree ----------------
resource "aws_organizations_organizational_unit" "top" {
  for_each  = toset(["Security", "Infrastructure", "Workloads", "Sandbox", "Suspended"])
  name      = each.key
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "workloads" {
  for_each  = toset(["Dev", "Stage", "Prod"])
  name      = each.key
  parent_id = aws_organizations_organizational_unit.top["Workloads"].id
}

locals {
  ou_ids = {
    security       = aws_organizations_organizational_unit.top["Security"].id
    infrastructure = aws_organizations_organizational_unit.top["Infrastructure"].id
    workloads      = aws_organizations_organizational_unit.top["Workloads"].id
    sandbox        = aws_organizations_organizational_unit.top["Sandbox"].id
    suspended      = aws_organizations_organizational_unit.top["Suspended"].id
    dev            = aws_organizations_organizational_unit.workloads["Dev"].id
    stage          = aws_organizations_organizational_unit.workloads["Stage"].id
    prod           = aws_organizations_organizational_unit.workloads["Prod"].id
  }
}

# ---------------- SCPs ----------------
module "scp" {
  source          = "../../modules/scp"
  policy_dir      = "${path.module}/../../../policies/scp"
  allowed_regions = var.allowed_regions
  ou_ids          = local.ou_ids
  attachments = {
    "protect-security-services"   = var.scp_attach_ous
    "data-and-compute-guardrails" = [for ou in var.scp_attach_ous : ou if ou != "security"]
    "region-deny"                 = var.scp_attach_ous
    "suspended-deny-all"          = ["suspended"]
  }
}

output "ou_ids" { value = local.ou_ids }
output "scp_ids" { value = module.scp.policy_ids }
