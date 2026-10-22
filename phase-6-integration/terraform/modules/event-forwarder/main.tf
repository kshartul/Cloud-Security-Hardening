###############################################################################
# Member-account event forwarder (apply in every account, in us-east-1 for console
# sign-in events and in the home region). Forwards security-relevant CloudTrail
# events to the Security Tooling default event bus.
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "security_tooling_account_id" { type = string }
variable "target_region" {
  type    = string
  default = "ap-south-1"
}

data "aws_region" "this" {}

resource "aws_iam_role" "forward" {
  name = "security-event-forwarder-${data.aws_region.this.name}"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

locals {
  target_bus = "arn:aws:events:${var.target_region}:${var.security_tooling_account_id}:event-bus/default"
}

resource "aws_iam_role_policy" "forward" {
  role = aws_iam_role.forward.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "events:PutEvents", Resource = local.target_bus }]
  })
}

resource "aws_cloudwatch_event_rule" "security" {
  name = "forward-security-events"
  event_pattern = jsonencode({
    "$or" = [
      { "detail-type" = ["AWS Console Sign In via CloudTrail"], detail = { userIdentity = { type = ["Root"] } } },
      { "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"],
      detail = { userIdentity = { arn = [{ wildcard = "*SecurityBreakGlass*" }] } } },
      { "detail-type" = ["AWS API Call via CloudTrail"],
      detail = { eventSource = ["iam.amazonaws.com"], eventName = ["CreateUser", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy"] } }
    ]
  })
}

resource "aws_cloudwatch_event_target" "security" {
  rule     = aws_cloudwatch_event_rule.security.name
  arn      = local.target_bus
  role_arn = aws_iam_role.forward.arn
}
