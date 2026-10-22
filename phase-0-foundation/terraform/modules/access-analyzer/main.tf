###############################################################################
# IAM Access Analyzer — org external access + org unused access (90 days)
# Apply in the delegated admin (Security Tooling) account.
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "unused_access_age_days" {
  type    = number
  default = 90
}

variable "archive_rules" {
  description = "Known-good external access (e.g. vendor roles). name => map of filter criteria"
  type = map(list(object({
    criteria = string
    eq       = list(string)
  })))
  default = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_accessanalyzer_analyzer" "external" {
  analyzer_name = "org-external-access"
  type          = "ORGANIZATION"
  tags          = var.tags
}

resource "aws_accessanalyzer_analyzer" "unused" {
  analyzer_name = "org-unused-access"
  type          = "ORGANIZATION_UNUSED_ACCESS"
  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days
    }
  }
  tags = var.tags
}

resource "aws_accessanalyzer_archive_rule" "this" {
  for_each      = var.archive_rules
  analyzer_name = aws_accessanalyzer_analyzer.external.analyzer_name
  rule_name     = each.key
  dynamic "filter" {
    for_each = each.value
    content {
      criteria = filter.value.criteria
      eq       = filter.value.eq
    }
  }
}
