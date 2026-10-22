###############################################################################
# WAFv2 web ACL for API Gateway (REGIONAL)
# Managed rule groups start in COUNT (override) and are promoted per group by
# moving names from var.count_rule_groups to blocking after FP review.
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "name" {
  type    = string
  default = "api-baseline"
}

variable "rate_limit_per_5min" {
  description = "Requests per 5 minutes per source IP"
  type        = number
  default     = 2000
}

variable "count_rule_groups" {
  description = "Managed rule groups still in COUNT mode (promotion list)"
  type        = list(string)
  default = [
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
  ]
}

variable "max_body_size_bytes" {
  type    = number
  default = 1048576 # 1 MiB; API GW REST max is 10 MiB
}

variable "pentest_allow_cidrs" {
  description = "Pen-test source IPs (Phase 5) — allowed past rate/reputation rules, still logged"
  type        = list(string)
  default     = []
}

variable "log_destination_arn" {
  description = "Firehose (aws-waf-logs-*) or S3 bucket (aws-waf-logs-*) ARN in Log Archive"
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  managed_groups = [
    { name = "AWSManagedRulesAmazonIpReputationList", priority = 10 },
    { name = "AWSManagedRulesAnonymousIpList", priority = 20 },
    { name = "AWSManagedRulesKnownBadInputsRuleSet", priority = 30 },
    { name = "AWSManagedRulesCommonRuleSet", priority = 40 },
    { name = "AWSManagedRulesSQLiRuleSet", priority = 50 },
  ]
}

resource "aws_wafv2_ip_set" "pentest" {
  count              = length(var.pentest_allow_cidrs) > 0 ? 1 : 0
  name               = "${var.name}-pentest-allow"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = var.pentest_allow_cidrs
  tags               = var.tags
}

resource "aws_wafv2_web_acl" "this" {
  name        = var.name
  description = "Baseline ACL for API Gateway stages (FMS-managed in prod)"
  scope       = "REGIONAL"
  tags        = var.tags

  default_action {
    allow {}
  }

  # 0 — pen-test allow list (labelled so it is visible in logs)
  dynamic "rule" {
    for_each = length(var.pentest_allow_cidrs) > 0 ? [1] : []
    content {
      name     = "pentest-allow"
      priority = 0
      action {
        count {}
      }
      rule_label {
        name = "kf:pentest"
      }
      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.pentest[0].arn
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "pentest-allow"
        sampled_requests_enabled   = true
      }
    }
  }

  # 5 — oversize body (CommonRuleSet SizeRestrictions_BODY only inspects 8 KB)
  rule {
    name     = "body-size-limit"
    priority = 5
    action {
      block {}
    }
    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = var.max_body_size_bytes
        field_to_match {
          body {
            oversize_handling = "MATCH"
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "body-size-limit"
      sampled_requests_enabled   = true
    }
  }

  # 10–50 — AWS managed rule groups
  dynamic "rule" {
    for_each = local.managed_groups
    content {
      name     = rule.value.name
      priority = rule.value.priority
      override_action {
        dynamic "count" {
          for_each = contains(var.count_rule_groups, rule.value.name) ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = contains(var.count_rule_groups, rule.value.name) ? [] : [1]
          content {}
        }
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value.name
          # Exclude the pen-test label from IP-reputation style groups
          dynamic "scope_down_statement" {
            for_each = length(var.pentest_allow_cidrs) > 0 && contains(["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList"], rule.value.name) ? [1] : []
            content {
              not_statement {
                statement {
                  label_match_statement {
                    scope = "LABEL"
                    key   = "kf:pentest"
                  }
                }
              }
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # 60 — rate limit per IP
  rule {
    name     = "rate-limit-per-ip"
    priority = 60
    action {
      block {
        custom_response {
          response_code = 429
        }
      }
    }
    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5min
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit-per-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [var.log_destination_arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

}

output "web_acl_arn" { value = aws_wafv2_web_acl.this.arn }
