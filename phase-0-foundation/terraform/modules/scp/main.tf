###############################################################################
# SCP library — creates every policy once, attaches to the OUs listed per policy.
# Promotion is done by editing var.attachments (see docs/DEPLOYMENT_ORDER.md).
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "policy_dir" {
  description = "Directory holding SCP JSON / JSON template files"
  type        = string
}

variable "allowed_regions" {
  description = "Regions workloads may use (global services are exempt)"
  type        = list(string)
  default     = ["ap-south-1", "us-east-1"]
}

variable "ou_ids" {
  description = "Map of short OU name => OU id (ou-xxxx-yyyyyyyy)"
  type        = map(string)
}

variable "attachments" {
  description = "Map of policy name => list of short OU names to attach to"
  type        = map(list(string))
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  policies = {
    "protect-security-services" = {
      description = "Deny disabling/tampering with security services, leaving the org, and root usage"
      content     = file("${var.policy_dir}/protect-security-services.json")
    }
    "data-and-compute-guardrails" = {
      description = "IMDSv2, encryption, no IAM users/keys, no unauthenticated Lambda URLs, no public Redshift"
      content     = file("${var.policy_dir}/data-and-compute-guardrails.json")
    }
    "region-deny" = {
      description = "Deny non-approved regions except global services"
      content     = templatefile("${var.policy_dir}/region-deny.json.tftpl", { allowed_regions = var.allowed_regions })
    }
    "suspended-deny-all" = {
      description = "Deny everything in the Suspended OU"
      content = jsonencode({
        Version   = "2012-10-17"
        Statement = [{ Sid = "DenyAll", Effect = "Deny", Action = "*", Resource = "*" }]
      })
    }
  }

  # flatten policy x OU into attachment pairs
  attachment_pairs = merge([
    for policy, ous in var.attachments : {
      for ou in ous : "${policy}:${ou}" => { policy = policy, ou_id = var.ou_ids[ou] }
    }
  ]...)
}

resource "aws_organizations_policy" "this" {
  for_each    = local.policies
  name        = each.key
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = jsonencode(jsondecode(each.value.content)) # minify — SCP limit is 5,120 chars
  tags        = var.tags
}

resource "aws_organizations_policy_attachment" "this" {
  for_each  = local.attachment_pairs
  policy_id = aws_organizations_policy.this[each.value.policy].id
  target_id = each.value.ou_id
}

output "policy_ids" {
  value = { for k, p in aws_organizations_policy.this : k => p.id }
}
