security_tooling_account_id = "222222222222"
organization_id             = "o-xxxxxxxxxx"
root_id                     = "r-xxxx"
log_archive_bucket          = "kf-org-security-logs-333333333333"
log_archive_kms_arn         = "arn:aws:kms:ap-south-1:333333333333:key/00000000-0000-0000-0000-000000000000"

# Promotion: sandbox -> dev -> stage -> prod -> security/infrastructure
policy_target_ous = [
  "ou-xxxx-sandbox0",
]

tags = {
  owner              = "cloud-platform"
  team               = "platform"
  service            = "security-tooling"
  environment        = "security"
  "managed-by"       = "terraform"
  "security-program" = "aws-hardening-2026"
}
