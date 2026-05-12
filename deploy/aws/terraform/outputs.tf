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

output "api_hosting_enabled" {
  description = "Whether this plan creates the AWS API hosting layer."
  value       = var.create_api_hosting_resources
}

output "api_load_balancer_dns_name" {
  description = "DNS name for the API application load balancer when API hosting is enabled."
  value       = try(aws_lb.api[0].dns_name, null)
}

output "api_ecs_cluster_name" {
  description = "ECS cluster name for the API service when API hosting is enabled."
  value       = try(aws_ecs_cluster.api[0].name, null)
}

output "api_service_name" {
  description = "ECS service name for the API service when API hosting is enabled."
  value       = try(aws_ecs_service.api[0].name, local.api_service_name)
}
