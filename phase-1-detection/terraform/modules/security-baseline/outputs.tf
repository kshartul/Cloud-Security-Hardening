output "securityhub_baseline_policy_id" {
  value = aws_securityhub_configuration_policy.baseline.id
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.admin.id
}

output "detective_graph_arn" {
  value = aws_detective_graph.this.graph_arn
}

output "config_aggregator_name" {
  value = aws_config_configuration_aggregator.org.name
}
