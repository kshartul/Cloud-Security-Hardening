###############################################################################
# Roles created in EVERY account (via phase-0 account-baseline stack):
#   SecurityAutoRemediation    — assumed by SOAR Lambdas in Security Tooling; narrow write actions
#   SecurityReadOnlyAutomation — assumed by findings-router / inventory scripts (tags, describe)
#   ProwlerAudit               — scheduled CSPM self-assessment
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "security_tooling_account_id" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_iam_policy_document" "trust_tooling" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_tooling_account_id}:root"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values = [
        "arn:aws:iam::${var.security_tooling_account_id}:role/secvuln-*",
        "arn:aws:iam::${var.security_tooling_account_id}:role/soar-*",
        "arn:aws:iam::${var.security_tooling_account_id}:role/SecurityPipelineDeploy",
      ]
    }
  }
}

# ---------------------------------------------------------------- remediation
resource "aws_iam_role" "remediation" {
  name                 = "SecurityAutoRemediation"
  assume_role_policy   = data.aws_iam_policy_document.trust_tooling.json
  max_session_duration = 3600
  tags                 = var.tags
}

resource "aws_iam_role_policy" "remediation" {
  role = aws_iam_role.remediation.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "S3BlockPublic"
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicyStatus", "s3:PutBucketTagging", "s3:GetBucketTagging"]
        Resource = "*"
      },
      {
        Sid      = "IamKeyDeactivate"
        Effect   = "Allow"
        Action   = ["iam:UpdateAccessKey", "iam:ListAccessKeys", "iam:TagUser", "iam:GetUser"]
        Resource = "*"
      },
      {
        Sid      = "SecurityGroups"
        Effect   = "Allow"
        Action   = ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules", "ec2:RevokeSecurityGroupIngress", "ec2:CreateTags"]
        Resource = "*"
      },
      {
        Sid    = "Ec2Isolate"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances", "ec2:CreateSecurityGroup", "ec2:ModifyInstanceAttribute",
          "ec2:CreateSnapshot", "ec2:CreateSnapshots", "ec2:DescribeSnapshots", "ec2:ModifySnapshotAttribute",
          "ec2:DescribeVolumes", "ec2:RevokeSecurityGroupEgress", "ec2:AuthorizeSecurityGroupEgress",
          "ec2:DisassociateIamInstanceProfile", "ec2:DescribeIamInstanceProfileAssociations",
          "autoscaling:DetachInstances", "autoscaling:DescribeAutoScalingInstances"
        ]
        Resource = "*"
      },
      {
        Sid      = "LambdaUrlAuth"
        Effect   = "Allow"
        Action   = ["lambda:GetFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig", "lambda:TagResource"]
        Resource = "*"
      },
      {
        Sid       = "SnapshotKms"
        Effect    = "Allow"
        Action    = ["kms:CreateGrant", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
      }
    ]
  })
}

# ---------------------------------------------------------------- read-only automation
resource "aws_iam_role" "readonly" {
  name               = "SecurityReadOnlyAutomation"
  assume_role_policy = data.aws_iam_policy_document.trust_tooling.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "readonly" {
  for_each   = toset(["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/ResourceGroupsandTagEditorReadOnlyAccess"])
  role       = aws_iam_role.readonly.name
  policy_arn = each.value
}

resource "aws_iam_role_policy" "readonly_extra" {
  role = aws_iam_role.readonly.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["apigateway:GET", "lambda:ListFunctions", "lambda:ListFunctionUrlConfigs", "wafv2:GetWebACLForResource"]
      Resource = "*"
    }]
  })
}

# ---------------------------------------------------------------- Prowler
resource "aws_iam_role" "prowler" {
  name               = "ProwlerAudit"
  assume_role_policy = data.aws_iam_policy_document.trust_tooling.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "prowler" {
  for_each   = toset(["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"])
  role       = aws_iam_role.prowler.name
  policy_arn = each.value
}

output "remediation_role_arn" { value = aws_iam_role.remediation.arn }
