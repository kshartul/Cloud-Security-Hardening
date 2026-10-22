###############################################################################
# Alert routing (Security Tooling): severity-based fan-out
#   CRITICAL / root login / break-glass  -> PagerDuty (EventBridge API destination) + #sec-critical
#   HIGH                                 -> #sec-high (AWS Chatbot via SNS)
#   SOAR approvals                       -> #sec-oncall (AWS Chatbot via SNS)
# AWS Chatbot channel configs for Microsoft Teams/Slack require a one-time tenant/workspace
# authorisation in the console; afterwards they are managed here (see variables).
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "pagerduty_routing_key" {
  description = <<-EOT
    PagerDuty Events v2 integration (routing) key, passed as TF_VAR from the pipeline's Key Vault-backed
    secret. PD v2 requires it in the request body, so it is stored in the EventBridge target input; it only
    allows *creating* incidents on one service. Rotate in PagerDuty if exposed.
  EOT
  type        = string
  sensitive   = true
}
variable "organization_id" { type = string }
variable "kms_key_arn" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}

# ------------------------------------------------------------------ SNS topics for Chatbot
resource "aws_sns_topic" "chat" {
  for_each          = toset(["sec-critical", "sec-high", "sec-oncall"])
  name              = each.key
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "chat_topic" {
  for_each = aws_sns_topic.chat
  statement {
    actions   = ["sns:Publish"]
    resources = [each.value.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "chat" {
  for_each = aws_sns_topic.chat
  arn      = each.value.arn
  policy   = data.aws_iam_policy_document.chat_topic[each.key].json
}

# ------------------------------------------------------------------ org event forwarding
# Member accounts forward console sign-in / break-glass CloudTrail events to this account's
# default bus (see modules/event-forwarder, deployed via account-baseline in us-east-1 and home region).
resource "aws_cloudwatch_event_bus_policy" "org_put" {
  event_bus_name = "default"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowOrgPutEvents"
      Effect    = "Allow"
      Principal = "*"
      Action    = "events:PutEvents"
      Resource  = "arn:aws:events:*:*:event-bus/default"
      Condition = { StringEquals = { "aws:PrincipalOrgID" = var.organization_id } }
    }]
  })
}

# ------------------------------------------------------------------ PagerDuty API destination
resource "aws_cloudwatch_event_connection" "pagerduty" {
  name               = "pagerduty-events-v2"
  authorization_type = "API_KEY"
  auth_parameters {
    api_key {
      key   = "x-routing-key" # header unused by PD v2 (routing key goes in body); kept for connection validity
      value = var.pagerduty_routing_key
    }
  }
}

resource "aws_cloudwatch_event_api_destination" "pagerduty" {
  name                             = "pagerduty-enqueue"
  invocation_endpoint              = "https://events.pagerduty.com/v2/enqueue"
  http_method                      = "POST"
  invocation_rate_limit_per_second = 10
  connection_arn                   = aws_cloudwatch_event_connection.pagerduty.arn
}

resource "aws_iam_role" "events_api" {
  name = "security-events-api-destination"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "events_api" {
  role = aws_iam_role.events_api.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "events:InvokeApiDestination", Resource = aws_cloudwatch_event_api_destination.pagerduty.arn }]
  })
}

# ------------------------------------------------------------------ rules
locals {
  rules = {
    sechub-critical = {
      pattern = {
        source        = ["aws.securityhub"]
        "detail-type" = ["Security Hub Findings - Imported"]
        detail        = { findings = { Severity = { Label = ["CRITICAL"] }, Workflow = { Status = ["NEW"] }, RecordState = ["ACTIVE"] } }
      }
      chat  = "sec-critical"
      pager = true
    }
    sechub-high = {
      pattern = {
        source        = ["aws.securityhub"]
        "detail-type" = ["Security Hub Findings - Imported"]
        detail        = { findings = { Severity = { Label = ["HIGH"] }, Workflow = { Status = ["NEW"] }, RecordState = ["ACTIVE"] } }
      }
      chat  = "sec-high"
      pager = false
    }
    guardduty-high = {
      pattern = {
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail        = { severity = [{ numeric = [">=", 7] }] }
      }
      chat  = "sec-critical"
      pager = true
    }
    root-login = {
      pattern = {
        "detail-type" = ["AWS Console Sign In via CloudTrail"]
        detail        = { userIdentity = { type = ["Root"] } }
      }
      chat  = "sec-critical"
      pager = true
    }
    break-glass-use = {
      pattern = {
        "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
        detail        = { userIdentity = { arn = [{ wildcard = "*SecurityBreakGlass*" }] } }
      }
      chat  = "sec-critical"
      pager = true
    }
  }
}

resource "aws_cloudwatch_event_rule" "this" {
  for_each      = local.rules
  name          = "alert-${each.key}"
  event_pattern = jsonencode(each.value.pattern)
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "chat" {
  for_each = local.rules
  rule     = aws_cloudwatch_event_rule.this[each.key].name
  arn      = aws_sns_topic.chat[each.value.chat].arn
}

resource "aws_cloudwatch_event_target" "pager" {
  for_each = { for k, v in local.rules : k => v if v.pager }
  rule     = aws_cloudwatch_event_rule.this[each.key].name
  arn      = aws_cloudwatch_event_api_destination.pagerduty.arn
  role_arn = aws_iam_role.events_api.arn
  input_transformer {
    input_paths = {
      account = "$.account"
      region  = "$.region"
      dtype   = "$.detail-type"
      id      = "$.id"
    }
    input_template = <<-EOT
      {
        "routing_key": "${var.pagerduty_routing_key}",
        "event_action": "trigger",
        "dedup_key": "<id>",
        "payload": {
          "summary": "AWS security alert: <dtype> in <account>/<region> (${each.key})",
          "source": "<account>",
          "severity": "critical",
          "component": "${each.key}"
        }
      }
    EOT
  }
}

output "chat_topic_arns" { value = { for k, t in aws_sns_topic.chat : k => t.arn } }
