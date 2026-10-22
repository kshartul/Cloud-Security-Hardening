variable "home_region" {
  description = "Aggregation region"
  type        = string
  default     = "ap-south-1"
}

variable "linked_regions" {
  description = "Other regions whose Security Hub findings are aggregated into home_region"
  type        = list(string)
  default     = ["us-east-1"]
}

variable "organization_id" {
  type = string
}

variable "root_id" {
  description = "Organization root id (r-xxxx)"
  type        = string
}

variable "policy_target_ous" {
  description = "OU ids that receive the baseline Security Hub configuration policy (promotion list)"
  type        = list(string)
}

variable "disabled_control_ids" {
  description = "Security Hub controls disabled org-wide with documented reason (see suppression register)"
  type        = map(string) # control id => reason
  default = {
    "EKS.1" = "No EKS clusters in estate"
    "EKS.2" = "No EKS clusters in estate"
  }
}

variable "config_bucket_name" {
  description = "Log Archive bucket for Config delivery"
  type        = string
}

variable "guardduty_export_bucket_arn" {
  type = string
}

variable "guardduty_export_kms_arn" {
  type = string
}

variable "enable_runtime_monitoring" {
  description = "GuardDuty Runtime Monitoring (only if EC2/ECS/EKS workloads exist)"
  type        = bool
  default     = false
}

variable "macie_priority_bucket_tags" {
  description = "Tag key/value that marks data lake / DW staging buckets for priority classification jobs"
  type        = map(string)
  default     = { "data-classification" = "confidential" }
}

variable "tags" {
  type    = map(string)
  default = {}
}
