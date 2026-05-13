locals {
  service_names = toset(["api", "worker"])
  enabled_service_names = setunion(
    var.create_foundation_resources ? local.service_names : toset([]),
    var.create_api_hosting_resources ? toset(["api"]) : toset([])
  )
  runtime_secret_name = length(trimspace(var.runtime_secret_name)) > 0 ? trimspace(var.runtime_secret_name) : (
    "${var.name_prefix}/${var.environment}/runtime"
  )
  common_tags = merge(
    {
      Application = "identrail"
      Environment = var.environment
      ManagedBy   = "terraform"
    },
    var.tags
  )
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

resource "aws_cloudwatch_log_group" "service" {
  for_each = local.enabled_service_names

  name              = "/${var.name_prefix}/${var.environment}/${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_id
}

resource "aws_secretsmanager_secret" "runtime" {
  count = var.create_foundation_resources && var.create_runtime_secret ? 1 : 0

  name                    = local.runtime_secret_name
  description             = "Identrail ${var.environment} runtime configuration placeholder"
  recovery_window_in_days = 7
}
