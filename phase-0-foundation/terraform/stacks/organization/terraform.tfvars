home_region     = "ap-south-1"
allowed_regions = ["ap-south-1", "us-east-1"] # us-east-1 kept for CloudFront/ACM/WAF global, IAM

# Promotion list — see docs/DEPLOYMENT_ORDER.md
scp_attach_ous = ["sandbox"]

tags = {
  owner              = "cloud-platform"
  team               = "platform"
  service            = "security-foundation"
  environment        = "org"
  "managed-by"       = "terraform"
  "security-program" = "aws-hardening-2026"
}
