###############################################################################
# GuardDuty delegated-admin config for a non-home region
###############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

variable "export_bucket_arn" { type = string }
variable "export_kms_arn" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}

resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

resource "aws_guardduty_organization_configuration" "this" {
  detector_id                      = aws_guardduty_detector.this.id
  auto_enable_organization_members = "ALL"
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each    = toset(["S3_DATA_EVENTS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS"])
  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  auto_enable = "ALL"
}

resource "aws_guardduty_publishing_destination" "s3" {
  detector_id     = aws_guardduty_detector.this.id
  destination_arn = var.export_bucket_arn
  kms_key_arn     = var.export_kms_arn
}
