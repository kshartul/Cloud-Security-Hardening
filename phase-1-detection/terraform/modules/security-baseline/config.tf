###############################################################################
# AWS Config — org aggregator + organization conformance packs
# Recorders in member accounts are managed by Control Tower; this module adds
# the aggregator and packs from the delegated admin account.
###############################################################################

resource "aws_iam_role" "config_aggregator" {
  name = "config-org-aggregator"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "config_aggregator" {
  role       = aws_iam_role.config_aggregator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

resource "aws_config_configuration_aggregator" "org" {
  name = "org-aggregator"
  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator.arn
  }
  tags = var.tags
}

locals {
  conformance_packs = {
    "cis-v3"      = "Operational-Best-Practices-for-CIS-AWS-v3.0.yaml"
    "serverless"  = "Operational-Best-Practices-for-Serverless.yaml"
    "redshift"    = "Operational-Best-Practices-for-Amazon-Redshift.yaml"
    "s3"          = "Operational-Best-Practices-for-Amazon-S3.yaml"
    "kms"         = "Operational-Best-Practices-for-KMS.yaml"
    "api-gateway" = "Operational-Best-Practices-for-API-Gateway.yaml"
  }
}

# Templates are vendored from github.com/awslabs/aws-config-rules (conformance-pack-templates)
# into ../../../conformance-packs/ by scripts/fetch_conformance_packs.sh — pinned by commit.
resource "aws_config_organization_conformance_pack" "this" {
  for_each          = local.conformance_packs
  name              = "org-${each.key}"
  template_body     = file("${path.module}/../../../conformance-packs/${each.value}")
  excluded_accounts = []
  depends_on        = [aws_config_configuration_aggregator.org]
}

# Custom org rule: every API Gateway stage must have a WAF ACL (supports API9 inventory)
resource "aws_config_organization_managed_rule" "apigw_waf" {
  name                 = "org-api-gw-associated-with-waf"
  rule_identifier      = "API_GW_ASSOCIATED_WITH_WAF"
  resource_types_scope = ["AWS::ApiGateway::Stage"]
}

resource "aws_config_organization_managed_rule" "lambda_url_auth" {
  name            = "org-lambda-function-url-auth"
  rule_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
}

resource "aws_config_organization_managed_rule" "required_tags" {
  name            = "org-required-tags"
  rule_identifier = "REQUIRED_TAGS"
  input_parameters = jsonencode({
    tag1Key = "owner"
    tag2Key = "team"
    tag3Key = "environment"
    tag4Key = "data-classification"
    tag5Key = "exposure"
    tag6Key = "criticality"
  })
  resource_types_scope = [
    "AWS::Lambda::Function", "AWS::ApiGateway::Stage", "AWS::S3::Bucket",
    "AWS::Redshift::Cluster", "AWS::DMS::ReplicationInstance", "AWS::EC2::Instance"
  ]
}
