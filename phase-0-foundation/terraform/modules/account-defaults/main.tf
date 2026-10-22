###############################################################################
# Per-account secure defaults — apply in EVERY account (pipeline matrix)
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

# NOTE: EBS default encryption, IMDS defaults and snapshot/AMI public-access blocks are
# regional — the caller applies this module once per region in use (provider per region).

variable "create_domain_keys" {
  description = "Create the per-domain KMS CMKs in this account"
  type        = bool
  default     = true
}

variable "kms_domains" {
  type    = list(string)
  default = ["dw", "api", "secrets"]
}

variable "tags" {
  type    = map(string)
  default = {}
}

# --- S3 account-level Block Public Access (global per account)
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --- EBS default encryption (regional)
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# --- IMDSv2 by default for new instances (regional)
resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 2
  http_endpoint               = "enabled"
  instance_metadata_tags      = "disabled"
}

# --- Block public sharing of EBS snapshots and AMIs (regional)
resource "aws_ebs_snapshot_block_public_access" "this" {
  state = "block-all-sharing"
}

resource "aws_ec2_image_block_public_access" "this" {
  state = "block-new-sharing"
}

# --- Password policy (only relevant to break-glass IAM users)
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 16
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# --- Per data-domain CMKs
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "domain" {
  for_each                = var.create_domain_keys ? toset(var.kms_domains) : toset([])
  description             = "CMK for data domain ${each.key}"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "DenyKeyDeletionOutsidePipeline"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy"]
        Resource  = "*"
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = ["arn:aws:iam::*:role/SecurityPipelineDeploy", "arn:aws:iam::*:role/SecurityBreakGlass"] }
        }
      }
    ]
  })
  tags = merge(var.tags, { "data-domain" = each.key })
}

resource "aws_kms_alias" "domain" {
  for_each      = aws_kms_key.domain
  name          = "alias/omni-${each.key}"
  target_key_id = each.value.key_id
}

output "domain_key_arns" {
  value = { for k, v in aws_kms_key.domain : k => v.arn }
}
