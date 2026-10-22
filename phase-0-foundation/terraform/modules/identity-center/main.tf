###############################################################################
# IAM Identity Center permission sets + group assignments
# Groups are provisioned from Entra ID / Okta via SCIM; this module only references them.
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "permission_sets" {
  description = "Permission set definitions"
  type = map(object({
    description      = string
    session_duration = string # ISO-8601, e.g. PT8H
    managed_policies = list(string)
    inline_policy    = optional(string) # JSON
    boundary_policy  = optional(string) # customer managed policy name used as permissions boundary
  }))
}

variable "assignments" {
  description = "List of {group, permission_set, account_ids}"
  type = list(object({
    group          = string
    permission_set = string
    account_ids    = list(string)
  }))
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_ssoadmin_instances" "this" {}

locals {
  instance_arn      = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]

  managed_attachments = merge([
    for ps, def in var.permission_sets : {
      for p in def.managed_policies : "${ps}|${p}" => { ps = ps, policy = p }
    }
  ]...)

  assignment_pairs = merge([
    for a in var.assignments : {
      for acct in a.account_ids : "${a.group}|${a.permission_set}|${acct}" => merge(a, { account_id = acct })
    }
  ]...)

  groups = toset([for a in var.assignments : a.group])
}

resource "aws_ssoadmin_permission_set" "this" {
  for_each         = var.permission_sets
  name             = each.key
  description      = each.value.description
  instance_arn     = local.instance_arn
  session_duration = each.value.session_duration
  tags             = var.tags
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each           = local.managed_attachments
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.ps].arn
  managed_policy_arn = each.value.policy
}

resource "aws_ssoadmin_permission_set_inline_policy" "this" {
  for_each           = { for k, v in var.permission_sets : k => v if v.inline_policy != null }
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = each.value.inline_policy
}

resource "aws_ssoadmin_permissions_boundary_attachment" "this" {
  for_each           = { for k, v in var.permission_sets : k => v if v.boundary_policy != null }
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  permissions_boundary {
    customer_managed_policy_reference {
      name = each.value.boundary_policy
      path = "/"
    }
  }
}

data "aws_identitystore_group" "this" {
  for_each          = local.groups
  identity_store_id = local.identity_store_id
  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = each.key
    }
  }
}

resource "aws_ssoadmin_account_assignment" "this" {
  for_each           = local.assignment_pairs
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn
  principal_id       = data.aws_identitystore_group.this[each.value.group].group_id
  principal_type     = "GROUP"
  target_id          = each.value.account_id
  target_type        = "AWS_ACCOUNT"
}

output "permission_set_arns" {
  value = { for k, v in aws_ssoadmin_permission_set.this : k => v.arn }
}
