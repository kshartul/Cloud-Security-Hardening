###############################################################################
# Stack: org-trail (run in MANAGEMENT account)
###############################################################################

terraform {
  required_version = ">= 1.10" # S3 native state locking (use_lockfile)
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-0/org-trail/terraform.tfstate"
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
variable "log_bucket_name" { type = string }
variable "log_kms_key_arn" { type = string }
variable "security_alerts_email" { type = string }
variable "tags" { type = map(string) }

resource "aws_kms_key" "mgmt_logs" {
  description         = "CloudWatch Logs key for org trail log group"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Admin", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:root" }, Action = "kms:*", Resource = "*" },
      {
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.home_region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
      }
    ]
  })
}

data "aws_caller_identity" "me" {}

resource "aws_sns_topic" "alarms" {
  name              = "security-cloudtrail-alarms"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.security_alerts_email
}

module "trail" {
  source                 = "../../modules/org-cloudtrail"
  s3_bucket_name         = var.log_bucket_name
  kms_key_arn            = var.log_kms_key_arn
  cloudwatch_kms_key_arn = aws_kms_key.mgmt_logs.arn
  alarm_sns_topic_arn    = aws_sns_topic.alarms.arn
  tags                   = var.tags
}

output "trail_arn" { value = module.trail.trail_arn }
