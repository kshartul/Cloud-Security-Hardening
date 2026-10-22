###############################################################################
# Organization CloudTrail (management account)
# multi-region, log validation, KMS, mgmt + S3/Lambda data events, CloudWatch Logs for alarms
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "trail_name" {
  type    = string
  default = "org-trail"
}
variable "s3_bucket_name" { type = string }
variable "kms_key_arn" { type = string }
variable "cloudwatch_retention_days" {
  type    = number
  default = 365
}
variable "alarm_sns_topic_arn" {
  description = "SNS topic for CIS 4.x metric alarms (root use, console no MFA, CT changes, ...)"
  type        = string
  default     = ""
}
variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = var.cloudwatch_kms_key_arn # key in the management account (CW Logs cannot use a cross-account key easily)
  tags              = var.tags
}

variable "cloudwatch_kms_key_arn" {
  description = "KMS key in the management account for the CloudWatch log group (null = AWS-owned key)"
  type        = string
  default     = null
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_cw" {
  name               = "${var.trail_name}-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "trail_cw" {
  role = aws_iam_role.trail_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "org" {
  name                          = var.trail_name
  s3_bucket_name                = var.s3_bucket_name
  s3_key_prefix                 = "cloudtrail"
  kms_key_id                    = var.kms_key_arn
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_cw.arn

  advanced_event_selector {
    name = "Management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }
  advanced_event_selector {
    name = "S3 data events (exclude log buckets to avoid loops)"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field           = "resources.ARN"
      not_starts_with = ["arn:aws:s3:::${var.s3_bucket_name}/"]
    }
  }
  advanced_event_selector {
    name = "Lambda invoke data events"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::Lambda::Function"]
    }
  }

  tags = var.tags
}

# ---- CIS 4.x style metric filters + alarms ----
locals {
  metric_filters = {
    RootAccountUsage      = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    ConsoleLoginNoMFA     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
    UnauthorizedAPICalls  = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    CloudTrailChanges     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    IAMPolicyChanges      = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = AttachUserPolicy) }"
    KMSKeyDisableOrDelete = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    SCPChanges            = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = UpdatePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DeletePolicy)) }"
    BreakGlassUse         = "{ $.userIdentity.arn = \"*SecurityBreakGlass*\" }"
  }
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each       = local.metric_filters
  name           = each.key
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value
  metric_transformation {
    name      = each.key
    namespace = "Security/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each            = var.alarm_sns_topic_arn == "" ? {} : local.metric_filters
  alarm_name          = "security-${each.key}"
  namespace           = "Security/CloudTrail"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.key == "UnauthorizedAPICalls" ? 20 : 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alarm_sns_topic_arn]
  tags                = var.tags
}

output "trail_arn" { value = aws_cloudtrail.org.arn }
output "log_group_name" { value = aws_cloudwatch_log_group.trail.name }
