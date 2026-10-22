###############################################################################
# Stack: findings-routing (run in SECURITY TOOLING)
###############################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
  backend "s3" {
    key          = "phase-4/findings-routing/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = "ap-south-1"
  default_tags {
    tags = {
      owner        = "security"
      service      = "vuln-management"
      environment  = "security"
      "managed-by" = "terraform"
    }
  }
}

variable "jira_base_url" { type = string }
variable "jira_secret_arn" { type = string }
variable "pagerduty_email_endpoint" {
  description = "PagerDuty email integration (or replace with HTTPS endpoint / Phase 6 API destination)"
  type        = string
}
variable "security_team_email" { type = string }
variable "dry_run" {
  type    = bool
  default = true
}

resource "aws_kms_key" "secvuln" {
  description         = "Vulnerability management (Lambda env, logs, SQS, SNS)"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Admin", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:root" }, Action = "kms:*", Resource = "*" },
      { Sid       = "Services", Effect = "Allow",
        Principal = { Service = ["logs.ap-south-1.amazonaws.com", "events.amazonaws.com", "sns.amazonaws.com", "sqs.amazonaws.com"] },
      Action = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"], Resource = "*" }
    ]
  })
}

data "aws_caller_identity" "me" {}

resource "aws_sns_topic" "pager" {
  name              = "security-pager-p1"
  kms_master_key_id = aws_kms_key.secvuln.arn
}

resource "aws_sns_topic_subscription" "pager" {
  topic_arn = aws_sns_topic.pager.arn
  protocol  = "email"
  endpoint  = var.pagerduty_email_endpoint
}

resource "aws_sns_topic" "notify" {
  name              = "security-notify"
  kms_master_key_id = aws_kms_key.secvuln.arn
}

resource "aws_sns_topic_subscription" "notify" {
  topic_arn = aws_sns_topic.notify.arn
  protocol  = "email"
  endpoint  = var.security_team_email
}

module "router" {
  source           = "../../modules/findings-router"
  jira_base_url    = var.jira_base_url
  jira_secret_arn  = var.jira_secret_arn
  pager_topic_arn  = aws_sns_topic.pager.arn
  notify_topic_arn = aws_sns_topic.notify.arn
  kms_key_arn      = aws_kms_key.secvuln.arn
  dry_run          = var.dry_run
}
