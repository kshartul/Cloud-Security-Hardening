###############################################################################
# Amazon Security Lake (run in LOG ARCHIVE = Security Lake delegated admin)
# Org-wide native sources, 365 d retention with tiering, SIEM subscriber.
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "regions" {
  type    = list(string)
  default = ["ap-south-1", "us-east-1"]
}
variable "rollup_region" {
  type    = string
  default = "ap-south-1"
}
variable "kms_key_arn" { type = string }
variable "subscriber_principal" {
  description = "SIEM account/principal (e.g. Splunk / Sentinel AWS account id) and external id"
  type = object({
    account_id  = string
    external_id = string
    name        = string
  })
}
variable "subscriber_access_type" {
  description = "S3 (notification-based, e.g. Splunk/Sentinel SQS) or LAKEFORMATION (query, e.g. Athena/OpenSearch)"
  type        = string
  default     = "S3"
}
variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_iam_role" "meta_store_manager" {
  name = "AmazonSecurityLakeMetaStoreManager"
  path = "/service-role/"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "meta_store_manager" {
  role       = aws_iam_role.meta_store_manager.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSecurityLakeMetastoreManager"
}

resource "aws_securitylake_data_lake" "this" {
  meta_store_manager_role_arn = aws_iam_role.meta_store_manager.arn

  dynamic "configuration" {
    for_each = var.regions
    content {
      region = configuration.value
      encryption_configuration {
        kms_key_id = var.kms_key_arn
      }
      lifecycle_configuration {
        transition {
          days          = 90
          storage_class = "STANDARD_IA"
        }
        transition {
          days          = 180
          storage_class = "GLACIER"
        }
        expiration {
          days = 365
        }
      }
      dynamic "replication_configuration" {
        for_each = configuration.value == var.rollup_region ? [] : [1]
        content {
          regions  = [var.rollup_region]
          role_arn = aws_iam_role.replication.arn
        }
      }
    }
  }
  tags = var.tags
}

resource "aws_iam_role" "replication" {
  name = "SecurityLakeReplication"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "s3.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "replication" {
  role       = aws_iam_role.replication.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSecurityLakeS3ReplicationRolePolicy"
}

locals {
  sources = {
    CLOUD_TRAIL_MGMT = "2.0"
    S3_DATA          = "2.0"
    LAMBDA_EXECUTION = "1.0"
    VPC_FLOW         = "2.0"
    ROUTE53          = "2.0"
    SH_FINDINGS      = "2.0"
    WAF              = "2.0"
  }
}

resource "aws_securitylake_aws_log_source" "this" {
  for_each = local.sources
  source {
    source_name    = each.key
    source_version = each.value
    regions        = var.regions
    # accounts omitted = all organization accounts
  }
  depends_on = [aws_securitylake_data_lake.this]
}

resource "aws_securitylake_subscriber" "siem" {
  subscriber_name        = var.subscriber_principal.name
  subscriber_description = "Enterprise SIEM"
  access_type            = var.subscriber_access_type

  dynamic "source" {
    for_each = local.sources
    content {
      aws_log_source_resource {
        source_name    = source.key
        source_version = source.value
      }
    }
  }

  subscriber_identity {
    principal   = var.subscriber_principal.account_id
    external_id = var.subscriber_principal.external_id
  }

  depends_on = [aws_securitylake_aws_log_source.this]
  tags       = var.tags
}

resource "aws_securitylake_subscriber_notification" "siem" {
  count         = var.subscriber_access_type == "S3" ? 1 : 0
  subscriber_id = aws_securitylake_subscriber.siem.id
  configuration {
    sqs_notification_configuration {}
  }
}

output "subscriber_role_arn" { value = aws_securitylake_subscriber.siem.role_arn }
output "subscriber_endpoint" { value = aws_securitylake_subscriber.siem.subscriber_endpoint }
