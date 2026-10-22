###############################################################################
# Amazon Inspector, Macie, Detective — delegated admin configuration
###############################################################################

data "aws_caller_identity" "me" {}

# ---------------- Inspector ----------------
resource "aws_inspector2_enabler" "admin" {
  account_ids    = [data.aws_caller_identity.me.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]
}

resource "aws_inspector2_organization_configuration" "this" {
  auto_enable {
    ec2         = true
    ecr         = true
    lambda      = true
    lambda_code = true # code vulns + hard-coded secrets in functions
  }
  depends_on = [aws_inspector2_enabler.admin]
}
# Existing members: enable once with
#   aws inspector2 enable --account-ids $(aws organizations list-accounts ...) \
#       --resource-types EC2 ECR LAMBDA LAMBDA_CODE
# ECR re-scan duration (30 days) is set with:
#   aws inspector2 update-configuration --ecr-configuration rescanDuration=DAYS_30
# EC2 agentless + SSM hybrid scan mode:
#   aws inspector2 update-configuration --ec2-configuration scanMode=EC2_HYBRID

# ---------------- Macie ----------------
resource "aws_macie2_account" "admin" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}

resource "aws_macie2_organization_configuration" "this" {
  auto_enable = true
  depends_on  = [aws_macie2_account.admin]
}
# Automated sensitive data discovery (org-wide sampling) is switched on with
#   aws macie2 update-automated-discovery-configuration --status ENABLED --auto-enable-organization-members ALL
# (scripts/macie_setup.py does this + custom identifiers + priority job).

resource "aws_macie2_custom_data_identifier" "candidate_id" {
  name                   = "kf-candidate-id"
  description            = "Internal candidate identifier"
  regex                  = "\\bCND-[0-9]{8}\\b"
  keywords               = ["candidate", "candidate_id", "cand_id"]
  maximum_match_distance = 50
  depends_on             = [aws_macie2_account.admin]
}

resource "aws_macie2_custom_data_identifier" "employee_id" {
  name                   = "kf-employee-id"
  description            = "Internal employee identifier"
  regex                  = "\\bE[0-9]{6,7}\\b"
  keywords               = ["employee", "emp_id", "employee_id"]
  maximum_match_distance = 30
  depends_on             = [aws_macie2_account.admin]
}

# ---------------- Detective ----------------
resource "aws_detective_graph" "this" {
  tags = var.tags
}

resource "aws_detective_organization_configuration" "this" {
  auto_enable = true
  graph_arn   = aws_detective_graph.this.graph_arn
}
