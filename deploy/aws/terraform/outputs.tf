output "foundation_resources_enabled" {
  description = "Whether this plan creates AWS foundation resources."
  value       = var.create_foundation_resources
}

output "log_group_names" {
  description = "CloudWatch log groups for future Identrail services."
  value       = { for name, log_group in aws_cloudwatch_log_group.service : name => log_group.name }
}

output "runtime_secret_name" {
  description = "Secrets Manager secret metadata name for future runtime configuration."
  value       = try(aws_secretsmanager_secret.runtime[0].name, local.runtime_secret_name)
}
