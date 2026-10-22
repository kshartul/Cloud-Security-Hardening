###############################################################################
# Amazon GuardDuty — org auto-enable ALL with protection plans
# Regional: apply per enabled region (stack uses provider per region)
###############################################################################

resource "aws_guardduty_detector" "admin" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

resource "aws_guardduty_organization_configuration" "this" {
  detector_id                      = aws_guardduty_detector.admin.id
  auto_enable_organization_members = "ALL"
}

locals {
  gd_features = merge(
    {
      S3_DATA_EVENTS         = []
      EBS_MALWARE_PROTECTION = []
      RDS_LOGIN_EVENTS       = []
      LAMBDA_NETWORK_LOGS    = []
      EKS_AUDIT_LOGS         = []
    },
    var.enable_runtime_monitoring ? {
      RUNTIME_MONITORING = ["EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT"]
    } : {}
  )
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each    = local.gd_features
  detector_id = aws_guardduty_detector.admin.id
  name        = each.key
  auto_enable = "ALL"

  dynamic "additional_configuration" {
    for_each = each.value
    content {
      name        = additional_configuration.value
      auto_enable = "ALL"
    }
  }
}

# Malware Protection for S3 is per-bucket (protection plan); enable on upload/landing buckets
# via phase-1 stack variable `malware_scan_buckets` (see stacks/security-tooling).

resource "aws_guardduty_publishing_destination" "s3" {
  detector_id     = aws_guardduty_detector.admin.id
  destination_arn = var.guardduty_export_bucket_arn
  kms_key_arn     = var.guardduty_export_kms_arn
}

# Threat intel: org-maintained deny list of known-bad IPs (optional)
# resource "aws_guardduty_threatintelset" "org" { ... }
