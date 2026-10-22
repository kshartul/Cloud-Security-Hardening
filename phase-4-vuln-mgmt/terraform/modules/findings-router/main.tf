###############################################################################
# Findings routing (Security Tooling account, home region)
#   EventBridge rules -> findings-router Lambda (new + resolved)
#   Schedules        -> exception-expiry, kpi-snapshot
#   DLQ + alarms, least-privilege roles, Jira secret reference
###############################################################################

terraform {
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

variable "name_prefix" {
  type    = string
  default = "secvuln"
}
variable "jira_base_url" { type = string }
variable "jira_project" {
  type    = string
  default = "SECVULN"
}
variable "jira_secret_arn" {
  description = "Secrets Manager secret {email, api_token}"
  type        = string
}
variable "jira_custom_fields" {
  description = "Env overrides for Jira custom field ids"
  type        = map(string)
  default     = {}
}
variable "pager_topic_arn" { type = string }
variable "notify_topic_arn" { type = string }
variable "tag_lookup_role" {
  type    = string
  default = "SecurityReadOnlyAutomation"
}
variable "dry_run" {
  type    = bool
  default = true # flip to false after a week of reviewing logs
}
variable "kms_key_arn" {
  description = "CMK for Lambda env, logs and DLQ"
  type        = string
}
variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_caller_identity" "me" {}
data "aws_region" "this" {}

locals {
  lambda_root = "${path.module}/../../../lambda"
}

# ------------------------------------------------------------------ packaging
data "archive_file" "router" {
  type        = "zip"
  source_dir  = "${local.lambda_root}/findings_router"
  output_path = "${path.module}/.build/findings_router.zip"
}
data "archive_file" "expiry" {
  type        = "zip"
  source_dir  = "${local.lambda_root}/exception_expiry"
  output_path = "${path.module}/.build/exception_expiry.zip"
}
data "archive_file" "kpi" {
  type        = "zip"
  source_dir  = "${local.lambda_root}/kpi_snapshot"
  output_path = "${path.module}/.build/kpi_snapshot.zip"
}

# ------------------------------------------------------------------ DLQ
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-router-dlq"
  message_retention_seconds = 1209600
  kms_master_key_id         = var.kms_key_arn
  tags                      = var.tags
}

# ------------------------------------------------------------------ IAM
data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "router" {
  name               = "${var.name_prefix}-findings-router"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
  tags               = var.tags
}

data "aws_iam_policy_document" "router" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.router.arn}:*"]
  }
  statement {
    sid       = "SecurityHubUpdate"
    actions   = ["securityhub:BatchUpdateFindings", "securityhub:GetFindings"]
    resources = ["*"]
  }
  statement {
    sid       = "JiraSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.jira_secret_arn]
  }
  statement {
    sid       = "Kms"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
  statement {
    sid       = "Pager"
    actions   = ["sns:Publish"]
    resources = [var.pager_topic_arn]
  }
  statement {
    sid       = "TagLookup"
    actions   = ["sts:AssumeRole"]
    resources = ["arn:aws:iam::*:role/${var.tag_lookup_role}"]
  }
  statement {
    sid       = "Dlq"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
}

resource "aws_iam_role_policy" "router" {
  role   = aws_iam_role.router.id
  policy = data.aws_iam_policy_document.router.json
}

resource "aws_iam_role" "jobs" {
  name               = "${var.name_prefix}-scheduled-jobs"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "jobs" {
  role = aws_iam_role.jobs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource = ["${aws_cloudwatch_log_group.expiry.arn}:*", "${aws_cloudwatch_log_group.kpi.arn}:*"] },
      { Sid = "SH", Effect = "Allow", Action = ["securityhub:GetFindings", "securityhub:BatchUpdateFindings"], Resource = "*" },
      { Sid = "CW", Effect = "Allow", Action = "cloudwatch:PutMetricData", Resource = "*",
      Condition = { StringEquals = { "cloudwatch:namespace" = "Security" } } },
      { Sid = "Notify", Effect = "Allow", Action = "sns:Publish", Resource = var.notify_topic_arn },
      { Sid = "Kms", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },
    ]
  })
}

# ------------------------------------------------------------------ Lambdas
resource "aws_cloudwatch_log_group" "router" {
  name              = "/aws/lambda/${var.name_prefix}-findings-router"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}
resource "aws_cloudwatch_log_group" "expiry" {
  name              = "/aws/lambda/${var.name_prefix}-exception-expiry"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}
resource "aws_cloudwatch_log_group" "kpi" {
  name              = "/aws/lambda/${var.name_prefix}-kpi-snapshot"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_lambda_function" "router" {
  function_name                  = "${var.name_prefix}-findings-router"
  role                           = aws_iam_role.router.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  timeout                        = 60
  memory_size                    = 256
  reserved_concurrent_executions = 10 # protects Jira API rate limits
  filename                       = data.archive_file.router.output_path
  source_code_hash               = data.archive_file.router.output_base64sha256
  kms_key_arn                    = var.kms_key_arn
  tracing_config { mode = "Active" }
  dead_letter_config { target_arn = aws_sqs_queue.dlq.arn }
  environment {
    variables = merge({
      JIRA_BASE_URL   = var.jira_base_url
      JIRA_PROJECT    = var.jira_project
      JIRA_SECRET_ARN = var.jira_secret_arn
      PAGER_TOPIC_ARN = var.pager_topic_arn
      TAG_LOOKUP_ROLE = var.tag_lookup_role
      DRY_RUN         = tostring(var.dry_run)
    }, var.jira_custom_fields)
  }
  depends_on = [aws_cloudwatch_log_group.router]
  tags       = var.tags
}

resource "aws_lambda_function" "expiry" {
  function_name                  = "${var.name_prefix}-exception-expiry"
  role                           = aws_iam_role.jobs.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  timeout                        = 300
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.expiry.output_path
  source_code_hash               = data.archive_file.expiry.output_base64sha256
  kms_key_arn                    = var.kms_key_arn
  tracing_config { mode = "Active" }
  environment {
    variables = { NOTIFY_TOPIC_ARN = var.notify_topic_arn, MAX_EXCEPTION_DAYS = "90", REMIND_DAYS = "14" }
  }
  depends_on = [aws_cloudwatch_log_group.expiry]
  tags       = var.tags
}

resource "aws_lambda_function" "kpi" {
  function_name                  = "${var.name_prefix}-kpi-snapshot"
  role                           = aws_iam_role.jobs.arn
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  timeout                        = 600
  memory_size                    = 512
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.kpi.output_path
  source_code_hash               = data.archive_file.kpi.output_base64sha256
  kms_key_arn                    = var.kms_key_arn
  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.kpi]
  tags       = var.tags
}

# ------------------------------------------------------------------ EventBridge
resource "aws_cloudwatch_event_rule" "new_crit_high" {
  name        = "${var.name_prefix}-sechub-new-critical-high"
  description = "New, active CRITICAL/HIGH Security Hub findings"
  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["CRITICAL", "HIGH"] }
        Workflow    = { Status = ["NEW"] }
        RecordState = ["ACTIVE"]
      }
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "resolved" {
  name        = "${var.name_prefix}-sechub-resolved"
  description = "Ticketed findings that the scanner no longer reports"
  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        UserDefinedFields = { jira = [{ exists = true }] }
        "$or" = [
          { RecordState = ["ARCHIVED"] },
          { Compliance = { Status = ["PASSED"] } },
          { Workflow = { Status = ["RESOLVED"] } }
        ]
      }
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "router" {
  for_each = {
    new      = aws_cloudwatch_event_rule.new_crit_high.name
    resolved = aws_cloudwatch_event_rule.resolved.name
  }
  rule = each.value
  arn  = aws_lambda_function.router.arn
  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }
  dead_letter_config { arn = aws_sqs_queue.dlq.arn }
}

resource "aws_lambda_permission" "router" {
  for_each      = { new = aws_cloudwatch_event_rule.new_crit_high.arn, resolved = aws_cloudwatch_event_rule.resolved.arn }
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.router.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = { ArnEquals = { "aws:SourceArn" = [aws_cloudwatch_event_rule.new_crit_high.arn, aws_cloudwatch_event_rule.resolved.arn] } }
    }]
  })
}

# ------------------------------------------------------------------ Schedules
resource "aws_cloudwatch_event_rule" "daily" {
  name                = "${var.name_prefix}-daily-jobs"
  schedule_expression = "cron(30 0 * * ? *)" # 06:00 IST
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "daily" {
  for_each = { expiry = aws_lambda_function.expiry.arn, kpi = aws_lambda_function.kpi.arn }
  rule     = aws_cloudwatch_event_rule.daily.name
  arn      = each.value
}

resource "aws_lambda_permission" "daily" {
  for_each      = { expiry = aws_lambda_function.expiry.function_name, kpi = aws_lambda_function.kpi.function_name }
  statement_id  = "AllowDaily"
  action        = "lambda:InvokeFunction"
  function_name = each.value
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily.arn
}

# ------------------------------------------------------------------ Alarms
resource "aws_cloudwatch_metric_alarm" "dlq" {
  alarm_name          = "${var.name_prefix}-router-dlq-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [var.notify_topic_arn]
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "router_errors" {
  alarm_name          = "${var.name_prefix}-router-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.router.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [var.notify_topic_arn]
  tags                = var.tags
}

output "router_function_arn" { value = aws_lambda_function.router.arn }
output "dlq_url" { value = aws_sqs_queue.dlq.id }
