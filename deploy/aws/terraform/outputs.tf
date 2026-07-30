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

output "user_data_export_bucket_name" {
  description = "S3 bucket used for self-serve account data export bundles when enabled."
  value       = try(aws_s3_bucket.user_data_exports[0].bucket, null)
}

output "worker_hosting_enabled" {
  description = "Whether this plan creates the AWS worker hosting layer."
  value       = var.create_worker_hosting_resources
}

output "worker_service_name" {
  description = "ECS service name for the worker service when worker hosting is enabled."
  value       = try(aws_ecs_service.worker[0].name, local.worker_service_name)
}

output "aws_connector_registration_topic_arn" {
  description = "Regional SNS custom-resource provider ARN configured in the Identrail API."
  value       = try(aws_sns_topic.aws_connector_registration[0].arn, null)
}

output "aws_connector_registration_queue_url" {
  description = "Private SQS queue consumed by the Identrail worker for AWS connector registration."
  value       = try(aws_sqs_queue.aws_connector_registration[0].url, null)
  sensitive   = true
}
