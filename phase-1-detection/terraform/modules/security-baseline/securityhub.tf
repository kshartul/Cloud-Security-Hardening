###############################################################################
# AWS Security Hub — central configuration (run in Security Tooling, home region)
###############################################################################

resource "aws_securityhub_account" "admin" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL" # consolidated control findings
  auto_enable_controls      = true
}

# Cross-region aggregation must exist before central configuration
resource "aws_securityhub_finding_aggregator" "this" {
  linking_mode      = "SPECIFIED_REGIONS"
  specified_regions = var.linked_regions
  depends_on        = [aws_securityhub_account.admin]
}

resource "aws_securityhub_organization_configuration" "this" {
  auto_enable           = false
  auto_enable_standards = "NONE"
  organization_configuration {
    configuration_type = "CENTRAL"
  }
  depends_on = [aws_securityhub_finding_aggregator.this]
}

locals {
  fsbp_arn = "arn:aws:securityhub:${var.home_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  cis_arn  = "arn:aws:securityhub:${var.home_region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
}

resource "aws_securityhub_configuration_policy" "baseline" {
  name        = "org-baseline"
  description = "FSBP + CIS v3.0; controls disabled only with documented reason"

  configuration_policy {
    service_enabled       = true
    enabled_standard_arns = [local.fsbp_arn, local.cis_arn]

    security_controls_configuration {
      disabled_control_identifiers = keys(var.disabled_control_ids)

      # Tighten parameterised controls
      security_control_custom_parameter {
        security_control_id = "IAM.7"
        parameter {
          name       = "MinimumPasswordLength"
          value_type = "CUSTOM"
          int {
            value = 16
          }
        }
      }
    }
  }

  depends_on = [aws_securityhub_organization_configuration.this]
}

# Policy that leaves Security Hub enabled but turns off standards — used for Suspended OU
resource "aws_securityhub_configuration_policy" "minimal" {
  name        = "minimal"
  description = "Service enabled, no standards (Suspended OU)"
  configuration_policy {
    service_enabled       = true
    enabled_standard_arns = []
    security_controls_configuration {
      disabled_control_identifiers = []
    }
  }
  depends_on = [aws_securityhub_organization_configuration.this]
}

resource "aws_securityhub_configuration_policy_association" "baseline" {
  for_each  = toset(var.policy_target_ous)
  target_id = each.value
  policy_id = aws_securityhub_configuration_policy.baseline.id
}

# --------- Automation rules (run before findings reach EventBridge) ---------
resource "aws_securityhub_automation_rule" "raise_internet_facing" {
  rule_name   = "raise-severity-internet-facing"
  description = "Resources tagged exposure=internet: MEDIUM → HIGH"
  rule_order  = 10
  rule_status = "ENABLED"

  criteria {
    resource_tags {
      comparison = "EQUALS"
      key        = "exposure"
      value      = "internet"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "MEDIUM"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  actions {
    type = "FINDING_FIELDS_UPDATE"
    finding_fields_update {
      severity {
        label = "HIGH"
      }
      note {
        text       = "Severity raised: internet-facing resource (automation rule 10)"
        updated_by = "sechub-automation"
      }
    }
  }
}

resource "aws_securityhub_automation_rule" "suppress_sandbox_low" {
  rule_name   = "suppress-sandbox-low"
  description = "Sandbox OU accounts: suppress LOW/INFORMATIONAL"
  rule_order  = 20
  rule_status = "ENABLED"

  criteria {
    resource_tags {
      comparison = "EQUALS"
      key        = "environment"
      value      = "sandbox"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "LOW"
    }
  }

  actions {
    type = "FINDING_FIELDS_UPDATE"
    finding_fields_update {
      workflow {
        status = "SUPPRESSED"
      }
      note {
        text       = "Auto-suppressed: sandbox LOW (automation rule 20)"
        updated_by = "sechub-automation"
      }
    }
  }
}

resource "aws_securityhub_automation_rule" "critical_kev_tag" {
  rule_name   = "prod-critical-to-top"
  description = "Prod CRITICAL findings flagged for immediate routing"
  rule_order  = 5
  rule_status = "ENABLED"

  criteria {
    resource_tags {
      comparison = "EQUALS"
      key        = "environment"
      value      = "prod"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
  }

  actions {
    type = "FINDING_FIELDS_UPDATE"
    finding_fields_update {
      user_defined_fields = { "route" = "pager" }
    }
  }
}

# --------- Custom insights per team ---------
resource "aws_securityhub_insight" "by_team" {
  name               = "Open critical/high by team tag"
  group_by_attribute = "ResourceTags"
  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
    workflow_status {
      comparison = "NOT_EQUALS"
      value      = "SUPPRESSED"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }
  depends_on = [aws_securityhub_account.admin]
}
