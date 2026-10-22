###############################################################################
# SOAR — auto-remediation playbooks (Security Tooling account)
#   * direct (no approval): S3 public, IAM key exposed
#   * via Step Functions approval workflow: SG open admin ports, Lambda URL (prod),
#     EC2 isolation (always)
#   * approval = Security Hub custom actions SOAR-Approve / SOAR-Reject
###############################################################################

terraform {
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

variable "notify_topic_arn" { type = string }
variable "pager_topic_arn" { type = string }
variable "approval_topic_arn" {
  description = "SNS topic subscribed by AWS Chatbot (Teams/Slack on-call channel)"
  type        = string
}
variable "prod_account_ids" { type = list(string) }
variable "forensics_account_id" { type = string }
variable "kms_key_arn" { type = string }
variable "dry_run" {
  type    = bool
  default = true
}
variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  src = "${path.module}/../../../lambda"

  playbooks = {
    s3_block_public    = { handler = "s3_block_public.handler", timeout = 60 }
    iam_key_deactivate = { handler = "iam_key_deactivate.handler", timeout = 60 }
    sg_open_ingress    = { handler = "sg_open_ingress.handler", timeout = 60 }
    ec2_isolate        = { handler = "ec2_isolate.handler", timeout = 300 }
    lambda_url_auth    = { handler = "lambda_url_auth.handler", timeout = 60 }
  }

  common_env = {
    REMEDIATION_ROLE     = "SecurityAutoRemediation"
    NOTIFY_TOPIC_ARN     = var.notify_topic_arn
    PROD_ACCOUNT_IDS     = join(",", var.prod_account_ids)
    FORENSICS_ACCOUNT_ID = var.forensics_account_id
    DRY_RUN              = tostring(var.dry_run)
  }
}

data "archive_file" "remediation" {
  type        = "zip"
  source_dir  = "${local.src}/remediation"
  output_path = "${path.module}/.build/remediation.zip"
}

data "archive_file" "approval" {
  type        = "zip"
  source_dir  = "${local.src}/approval"
  output_path = "${path.module}/.build/approval.zip"
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ------------------------------------------------------------------ playbook role
resource "aws_iam_role" "playbooks" {
  name               = "soar-playbooks"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "playbooks" {
  role = aws_iam_role.playbooks.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AssumeRemediation", Effect = "Allow", Action = "sts:AssumeRole", Resource = "arn:aws:iam::*:role/SecurityAutoRemediation" },
      { Sid = "Annotate", Effect = "Allow", Action = "securityhub:BatchUpdateFindings", Resource = "*" },
      { Sid = "Notify", Effect = "Allow", Action = "sns:Publish", Resource = [var.notify_topic_arn] },
      { Sid = "Kms", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },
      { Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/soar-*" },
    ]
  })
}

resource "aws_lambda_function" "playbook" {
  for_each                       = local.playbooks
  function_name                  = "soar-${replace(each.key, "_", "-")}"
  role                           = aws_iam_role.playbooks.arn
  handler                        = each.value.handler
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  timeout                        = each.value.timeout
  reserved_concurrent_executions = 5
  filename                       = data.archive_file.remediation.output_path
  source_code_hash               = data.archive_file.remediation.output_base64sha256
  kms_key_arn                    = var.kms_key_arn
  environment { variables = local.common_env }
  tracing_config { mode = "Active" }
  tags = var.tags
}

# ------------------------------------------------------------------ approvals
resource "aws_dynamodb_table" "approvals" {
  name         = "soar-approvals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_key"
  attribute {
    name = "finding_key"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
  point_in_time_recovery { enabled = true }
  tags = var.tags
}

resource "aws_iam_role" "approval" {
  name               = "soar-approval"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "approval" {
  role = aws_iam_role.approval.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem"], Resource = aws_dynamodb_table.approvals.arn },
      { Effect = "Allow", Action = ["states:SendTaskSuccess", "states:SendTaskFailure"], Resource = aws_sfn_state_machine.remediation.arn },
      { Effect = "Allow", Action = "sns:Publish", Resource = var.approval_topic_arn },
      { Effect = "Allow", Action = "securityhub:BatchUpdateFindings", Resource = "*" },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/soar-*" },
    ]
  })
}

resource "aws_lambda_function" "request_approval" {
  function_name                  = "soar-request-approval"
  role                           = aws_iam_role.approval.arn
  handler                        = "request_approval.handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  timeout                        = 30
  filename                       = data.archive_file.approval.output_path
  source_code_hash               = data.archive_file.approval.output_base64sha256
  kms_key_arn                    = var.kms_key_arn
  reserved_concurrent_executions = 5
  tracing_config { mode = "Active" }
  environment {
    variables = { APPROVAL_TABLE = aws_dynamodb_table.approvals.name, APPROVAL_TOPIC_ARN = var.approval_topic_arn }
  }
  tags = var.tags
}

resource "aws_lambda_function" "approval_handler" {
  function_name                  = "soar-approval-handler"
  role                           = aws_iam_role.approval.arn
  handler                        = "approval_handler.handler"
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  timeout                        = 30
  filename                       = data.archive_file.approval.output_path
  source_code_hash               = data.archive_file.approval.output_base64sha256
  kms_key_arn                    = var.kms_key_arn
  reserved_concurrent_executions = 5
  tracing_config { mode = "Active" }
  environment {
    variables = { APPROVAL_TABLE = aws_dynamodb_table.approvals.name }
  }
  tags = var.tags
}

resource "aws_securityhub_action_target" "approve" {
  name        = "SOAR-Approve"
  identifier  = "SOARApprove"
  description = "Approve the pending SOAR remediation for this finding"
}

resource "aws_securityhub_action_target" "reject" {
  name        = "SOAR-Reject"
  identifier  = "SOARReject"
  description = "Reject the pending SOAR remediation for this finding"
}

# ------------------------------------------------------------------ state machine
resource "aws_iam_role" "sfn" {
  name = "soar-stepfunctions"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "states.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "sfn" {
  role = aws_iam_role.sfn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "lambda:InvokeFunction",
      Resource = concat([for f in aws_lambda_function.playbook : f.arn], [aws_lambda_function.request_approval.arn]) },
      { Effect = "Allow", Action = "sns:Publish", Resource = var.pager_topic_arn },
      { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },
      { Effect = "Allow", Action = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"], Resource = "*" },
    ]
  })
}

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/soar-remediation"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sfn_state_machine" "remediation" {
  name     = "soar-remediation"
  role_arn = aws_iam_role.sfn.arn
  definition = templatefile("${path.module}/../../../stepfunctions/remediation-with-approval.asl.json", {
    request_approval_arn = aws_lambda_function.request_approval.arn
    pager_topic_arn      = var.pager_topic_arn
  })
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }
  tracing_configuration { enabled = true }
  tags = var.tags
}

# ------------------------------------------------------------------ triggers
locals {
  sh_imported = { source = ["aws.securityhub"], "detail-type" = ["Security Hub Findings - Imported"] }

  direct_triggers = {
    s3_block_public = merge(local.sh_imported, { detail = { findings = {
      Compliance  = { SecurityControlId = ["S3.2", "S3.3", "S3.8", "S3.19"], Status = ["FAILED"] }
      Workflow    = { Status = ["NEW", "NOTIFIED"] }
      RecordState = ["ACTIVE"]
    } } })
    iam_key_deactivate = {
      source        = ["aws.guardduty"]
      "detail-type" = ["GuardDuty Finding"]
      detail = { type = [
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" },
        { prefix = "CredentialAccess:IAMUser/AnomalousBehavior" },
        { prefix = "UnauthorizedAccess:IAMUser/MaliciousIPCaller" }
      ] }
    }
  }

  # playbook => {pattern, alwaysApproval}
  sfn_triggers = {
    sg_open_ingress = {
      always = false
      pattern = merge(local.sh_imported, { detail = { findings = {
        Compliance  = { SecurityControlId = ["EC2.13", "EC2.14", "EC2.53", "EC2.54"], Status = ["FAILED"] }
        RecordState = ["ACTIVE"]
      } } })
    }
    lambda_url_auth = {
      always = false
      pattern = merge(local.sh_imported, { detail = { findings = {
        Compliance  = { SecurityControlId = ["Lambda.1"], Status = ["FAILED"] }
        RecordState = ["ACTIVE"]
      } } })
    }
    ec2_isolate = {
      always = true
      pattern = {
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail = {
          type     = [{ prefix = "CryptoCurrency:EC2/" }, { prefix = "Backdoor:EC2/C&CActivity" }, { prefix = "Trojan:EC2/" }]
          severity = [{ numeric = [">=", 7] }]
        }
      }
    }
  }
}

resource "aws_cloudwatch_event_rule" "direct" {
  for_each      = local.direct_triggers
  name          = "soar-${replace(each.key, "_", "-")}"
  event_pattern = jsonencode(each.value)
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "direct" {
  for_each = local.direct_triggers
  rule     = aws_cloudwatch_event_rule.direct[each.key].name
  arn      = aws_lambda_function.playbook[each.key].arn
}

resource "aws_lambda_permission" "direct" {
  for_each      = local.direct_triggers
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.playbook[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.direct[each.key].arn
}

resource "aws_cloudwatch_event_rule" "sfn" {
  for_each      = local.sfn_triggers
  name          = "soar-${replace(each.key, "_", "-")}"
  event_pattern = jsonencode(each.value.pattern)
  tags          = var.tags
}

resource "aws_iam_role" "events_to_sfn" {
  name = "soar-events-to-sfn"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "events_to_sfn" {
  role = aws_iam_role.events_to_sfn.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "states:StartExecution", Resource = aws_sfn_state_machine.remediation.arn }]
  })
}

resource "aws_cloudwatch_event_target" "sfn" {
  for_each = local.sfn_triggers
  rule     = aws_cloudwatch_event_rule.sfn[each.key].name
  arn      = aws_sfn_state_machine.remediation.arn
  role_arn = aws_iam_role.events_to_sfn.arn
  input_transformer {
    input_paths    = { detail = "$.detail" }
    input_template = <<-EOT
      {"playbook": "${aws_lambda_function.playbook[each.key].arn}", "alwaysApproval": ${each.value.always}, "event": {"detail": <detail>}}
    EOT
  }
}

resource "aws_cloudwatch_event_rule" "approval_actions" {
  name = "soar-approval-custom-actions"
  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Custom Action"]
    resources     = [aws_securityhub_action_target.approve.arn, aws_securityhub_action_target.reject.arn]
  })
}

resource "aws_cloudwatch_event_target" "approval_actions" {
  rule = aws_cloudwatch_event_rule.approval_actions.name
  arn  = aws_lambda_function.approval_handler.arn
}

resource "aws_lambda_permission" "approval_actions" {
  statement_id  = "AllowCustomActions"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_handler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.approval_actions.arn
}

output "state_machine_arn" { value = aws_sfn_state_machine.remediation.arn }
