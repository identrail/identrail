variable "aws_region" {
  description = "AWS region where Identrail foundation resources will live."
  type        = string
  default     = "us-east-1"
  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be an AWS region such as us-east-1."
  }
}

variable "environment" {
  description = "Short environment name used in resource names and tags."
  type        = string
  default     = "dev"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.environment))
    error_message = "environment must be 3-32 lowercase letters, numbers, or dashes, starting with a letter and ending with a letter or number."
  }
}

variable "name_prefix" {
  description = "Resource name prefix for Identrail AWS resources."
  type        = string
  default     = "identrail"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-32 lowercase letters, numbers, or dashes, starting with a letter and ending with a letter or number."
  }
}

variable "create_foundation_resources" {
  description = "Create foundation AWS resources. Keep false for validation-only PR and CI plans."
  type        = bool
  default     = false
}

variable "create_runtime_secret" {
  description = "Create the Secrets Manager metadata record for future Identrail runtime configuration."
  type        = bool
  default     = true
}

variable "runtime_secret_name" {
  description = "Secrets Manager secret name for future runtime configuration. Defaults to <name_prefix>/<environment>/runtime."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention for future Identrail service logs."
  type        = number
  default     = 30
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
    ], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch Logs supported retention value."
  }
}

variable "log_kms_key_id" {
  description = "Optional KMS key ARN or ID for CloudWatch log group encryption."
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional tags to apply to AWS resources."
  type        = map(string)
  default     = {}
}
