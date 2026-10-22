###############################################################################
# Stack: bootstrap-state (run ONCE in SECURITY TOOLING as SecurityPipelineDeploy — the key
# policy denies data-key use to any other principal — with local state, then
# `terraform init -migrate-state -backend-config=../../../../backend.hcl`)
###############################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

provider "aws" {
  region = "ap-south-1"
}

data "aws_caller_identity" "me" {}

resource "aws_kms_key" "state" {
  description         = "Terraform state for security program"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AccountAdmin", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:root" }, Action = "kms:*", Resource = "*" },
      {
        Sid       = "DenyUseOutsidePipeline"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = ["arn:aws:iam::*:role/SecurityPipelineDeploy", "arn:aws:iam::*:role/SecurityBreakGlass"] } }
      }
    ]
  })
}

resource "aws_s3_bucket" "state" {
  bucket = "kf-security-tfstate-${data.aws_caller_identity.me.account_id}-ap-south-1"
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "OnlyPipelineAndBreakGlass"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutObject", "s3:DeleteObject"]
        Resource  = "${aws_s3_bucket.state.arn}/*"
        Condition = {
          ArnNotLike = { "aws:PrincipalArn" = ["arn:aws:iam::*:role/SecurityPipelineDeploy", "arn:aws:iam::*:role/SecurityBreakGlass"] }
        }
      }
    ]
  })
}

output "state_bucket" { value = aws_s3_bucket.state.id }
