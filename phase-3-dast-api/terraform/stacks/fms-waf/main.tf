###############################################################################
# Stack: fms-waf (run in SECURITY TOOLING = Firewall Manager admin)
# Firewall Manager pushes a WAFv2 ACL to every API Gateway stage and ALB/CloudFront
# in scope, org-wide, including accounts created later.
###############################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  backend "s3" {
    key          = "phase-3/fms-waf/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = "ap-south-1"
}

variable "include_ou_ids" {
  description = "Promotion list: Dev -> Stage -> Prod OU ids"
  type        = list(string)
}

variable "remediation_enabled" {
  description = "false = audit only (FMS reports non-compliant stages); true = auto-associate"
  type        = bool
  default     = false
}

variable "count_rule_groups" {
  description = "Managed groups still in COUNT across the org"
  type        = list(string)
  default = [
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
  ]
}

variable "waf_log_bucket_arn" {
  description = "Central S3 bucket aws-waf-logs-* in Log Archive"
  type        = string
}

locals {
  groups = [
    { name = "AWSManagedRulesAmazonIpReputationList", priority = 10 },
    { name = "AWSManagedRulesAnonymousIpList", priority = 20 },
    { name = "AWSManagedRulesKnownBadInputsRuleSet", priority = 30 },
    { name = "AWSManagedRulesCommonRuleSet", priority = 40 },
    { name = "AWSManagedRulesSQLiRuleSet", priority = 50 },
  ]

  managed_service_data = jsonencode({
    type = "WAFV2"
    preProcessRuleGroups = [
      for g in local.groups : {
        managedRuleGroupIdentifier = {
          vendorName           = "AWS"
          managedRuleGroupName = g.name
          version              = null
        }
        overrideAction         = { type = contains(var.count_rule_groups, g.name) ? "COUNT" : "NONE" }
        ruleGroupArn           = null
        excludeRules           = []
        ruleGroupType          = "ManagedRuleGroup"
        sampledRequestsEnabled = true
      }
    ]
    postProcessRuleGroups             = []
    defaultAction                     = { type = "ALLOW" }
    overrideCustomerWebACLAssociation = false
    loggingConfiguration = {
      logDestinationConfigs = [var.waf_log_bucket_arn]
      redactedFields        = [{ redactedFieldType = "SingleHeader", redactedFieldValue = "authorization" }]
    }
    sampledRequestsEnabledForDefaultActions = true
  })
}

resource "aws_fms_policy" "api_waf" {
  name                        = "org-api-waf-baseline"
  description                 = "Baseline WAF for API Gateway stages and ALBs"
  exclude_resource_tags       = true # resources tagged waf-exempt=true are excluded (reviewed exceptions)
  remediation_enabled         = var.remediation_enabled
  delete_all_policy_resources = false
  resource_type_list          = ["AWS::ApiGateway::Stage", "AWS::ElasticLoadBalancingV2::LoadBalancer"]

  include_map {
    orgunit = var.include_ou_ids
  }

  security_service_policy_data {
    type                 = "WAFV2"
    managed_service_data = local.managed_service_data
  }

  # Allow teams to keep a stricter app-specific ACL by tagging the stage waf-exempt=true (reviewed)
  resource_tags = {
    "waf-exempt" = "true"
  }
}

# Separate CloudFront policy (global scope, must be in us-east-1)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

resource "aws_fms_policy" "cloudfront_waf" {
  provider                    = aws.us_east_1
  name                        = "org-cloudfront-waf-baseline"
  exclude_resource_tags       = true
  remediation_enabled         = var.remediation_enabled
  delete_all_policy_resources = false
  resource_type               = "AWS::CloudFront::Distribution"

  include_map {
    orgunit = var.include_ou_ids
  }

  security_service_policy_data {
    type                 = "WAFV2"
    managed_service_data = local.managed_service_data
  }

  resource_tags = {
    "waf-exempt" = "true"
  }
}
