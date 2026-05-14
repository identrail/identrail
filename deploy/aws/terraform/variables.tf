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

variable "create_api_hosting_resources" {
  description = "Create the AWS ECS/Fargate API hosting layer. Keep false until operator inputs, secrets, database, and DNS are ready."
  type        = bool
  default     = false
}

variable "api_vpc_id" {
  description = "VPC ID for the API load balancer and ECS service. Required when create_api_hosting_resources=true."
  type        = string
  default     = ""
  validation {
    condition     = length(trimspace(var.api_vpc_id)) == 0 || can(regex("^vpc-[0-9a-f]+$", var.api_vpc_id))
    error_message = "api_vpc_id must be blank or a valid VPC ID."
  }
}

variable "api_public_subnet_ids" {
  description = "Public subnet IDs for the API application load balancer. Provide at least two distinct subnets in different Availability Zones with Internet Gateway default routes when API hosting is enabled."
  type        = list(string)
  default     = []
  validation {
    condition = length(var.api_public_subnet_ids) == length(distinct(var.api_public_subnet_ids)) && alltrue([
      for subnet_id in var.api_public_subnet_ids : can(regex("^subnet-[0-9a-f]+$", subnet_id))
    ])
    error_message = "api_public_subnet_ids must contain distinct valid subnet IDs."
  }
}

variable "api_private_subnet_ids" {
  description = "Private subnet IDs for the API ECS tasks. Provide at least two distinct subnets when API hosting is enabled."
  type        = list(string)
  default     = []
  validation {
    condition = length(var.api_private_subnet_ids) == length(distinct(var.api_private_subnet_ids)) && alltrue([
      for subnet_id in var.api_private_subnet_ids : can(regex("^subnet-[0-9a-f]+$", subnet_id))
    ])
    error_message = "api_private_subnet_ids must contain distinct valid subnet IDs."
  }
}

variable "api_task_subnet_ids" {
  description = "Optional ECS task subnet IDs. Leave empty to use api_private_subnet_ids. For a low-cost first cutover, operators may set this to public subnets and enable api_task_assign_public_ip to avoid NAT Gateway or VPC endpoint costs."
  type        = list(string)
  default     = []
  validation {
    condition = length(var.api_task_subnet_ids) == length(distinct(var.api_task_subnet_ids)) && alltrue([
      for subnet_id in var.api_task_subnet_ids : can(regex("^subnet-[0-9a-f]+$", subnet_id))
    ])
    error_message = "api_task_subnet_ids must contain distinct valid subnet IDs."
  }
}

variable "api_task_assign_public_ip" {
  description = "Assign public IPs to API ECS tasks. Keep false for private-subnet production; set true only for the low-cost first cutover path where task subnets are public and service ingress remains restricted to the ALB security group."
  type        = bool
  default     = false
}

variable "api_private_subnet_egress_ready" {
  description = "Set true only after private API task subnets have NAT egress or VPC endpoints for ECR, Secrets Manager, and CloudWatch Logs. Required when API hosting uses private tasks with api_task_assign_public_ip=false."
  type        = bool
  default     = false
}

variable "api_allowed_cidr_blocks" {
  description = "IPv4 CIDR blocks allowed to reach the public API load balancer."
  type        = list(string)
  default     = ["0.0.0.0/0"]
  validation {
    condition = alltrue([
      for cidr_block in var.api_allowed_cidr_blocks : can(cidrhost(cidr_block, 0)) && can(cidrnetmask(cidr_block))
    ])
    error_message = "api_allowed_cidr_blocks must contain valid IPv4 CIDR blocks."
  }
}

variable "api_cors_allowed_origins" {
  description = "HTTPS web origins allowed to call the hosted API from browsers. Defaults to Identrail Cloud web origins."
  type        = list(string)
  default = [
    "https://app.identrail.com",
    "https://identrail.com",
    "https://www.identrail.com",
  ]
  validation {
    condition = alltrue([
      for origin in var.api_cors_allowed_origins : can(regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$", origin))
    ])
    error_message = "api_cors_allowed_origins must contain bare HTTPS origins without paths, queries, fragments, or trailing slashes, such as https://app.identrail.com."
  }
}

variable "api_trusted_proxy_cidr_blocks" {
  description = "CIDR blocks for ALB/VPC proxy IPs trusted by the hosted API when reading X-Forwarded-For."
  type        = list(string)
  default = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
  ]
  validation {
    condition = alltrue([
      for cidr_block in var.api_trusted_proxy_cidr_blocks : can(cidrhost(cidr_block, 0)) && can(cidrnetmask(cidr_block))
    ])
    error_message = "api_trusted_proxy_cidr_blocks must contain valid IPv4 CIDR blocks."
  }
}

variable "api_certificate_arn" {
  description = "ACM certificate ARN for the API HTTPS listener. Required when create_api_hosting_resources=true."
  type        = string
  default     = ""
  validation {
    condition = length(trimspace(var.api_certificate_arn)) == 0 || can(regex(
      "^arn:(aws|aws-us-gov|aws-cn):acm:[a-z]{2}(-gov)?-[a-z]+-[0-9]+:[0-9]{12}:certificate/.+$",
      var.api_certificate_arn
    ))
    error_message = "api_certificate_arn must be blank or an ACM certificate ARN."
  }
}

variable "api_tls_policy" {
  description = "TLS policy for the API HTTPS listener."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "api_enable_http_redirect" {
  description = "Create an HTTP listener that redirects port 80 to HTTPS."
  type        = bool
  default     = true
}

variable "api_load_balancer_deletion_protection" {
  description = "Enable deletion protection on the API load balancer."
  type        = bool
  default     = false
}

variable "api_container_image" {
  description = "Immutable Identrail API container image reference. Required when create_api_hosting_resources=true."
  type        = string
  default     = ""
  validation {
    condition     = length(var.api_container_image) == length(trimspace(var.api_container_image))
    error_message = "api_container_image must not have leading or trailing whitespace."
  }
}

variable "api_container_port" {
  description = "Port exposed by the Identrail API container."
  type        = number
  default     = 8080
  validation {
    condition     = var.api_container_port > 0 && var.api_container_port < 65536
    error_message = "api_container_port must be a valid TCP port."
  }
}

variable "api_health_check_path" {
  description = "HTTP path the load balancer uses to check API health."
  type        = string
  default     = "/healthz"
  validation {
    condition     = startswith(var.api_health_check_path, "/")
    error_message = "api_health_check_path must start with /."
  }
}

variable "api_health_check_grace_period_seconds" {
  description = "Seconds ECS should wait before enforcing load balancer health checks after task start."
  type        = number
  default     = 60
  validation {
    condition     = var.api_health_check_grace_period_seconds >= 0 && var.api_health_check_grace_period_seconds <= 7200
    error_message = "api_health_check_grace_period_seconds must be between 0 and 7200."
  }
}

variable "api_task_cpu" {
  description = "Fargate CPU units for the API task."
  type        = number
  default     = 512
}

variable "api_task_memory" {
  description = "Fargate memory in MiB for the API task."
  type        = number
  default     = 1024
}

variable "api_desired_count" {
  description = "Desired number of API tasks."
  type        = number
  default     = 1
  validation {
    condition     = var.api_desired_count >= 1 && var.api_desired_count <= 100
    error_message = "api_desired_count must be between 1 and 100."
  }
}

variable "api_environment_variables" {
  description = "Non-secret environment variables for the API task definition."
  type        = map(string)
  default     = {}
  validation {
    condition = alltrue([
      for name in keys(var.api_environment_variables) : !contains([
        "IDENTRAIL_ALERT_HMAC_SECRET",
        "IDENTRAIL_API_KEYS",
        "IDENTRAIL_API_KEY_SCOPE_BINDINGS",
        "IDENTRAIL_API_KEY_SCOPES",
        "IDENTRAIL_AUDIT_FINGERPRINT_SECRET",
        "IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET",
        "IDENTRAIL_CONNECTOR_SECRET_KEYS",
        "IDENTRAIL_DATABASE_URL",
        "IDENTRAIL_EMAIL_API_KEY",
        "IDENTRAIL_GITHUB_APP_PRIVATE_KEY",
        "IDENTRAIL_GITHUB_APP_WEBHOOK_SECRET",
        "IDENTRAIL_METRICS_API_KEY",
        "IDENTRAIL_SESSION_KEY",
        "IDENTRAIL_SESSION_KEY_PREVIOUS",
        "IDENTRAIL_WORKOS_API_KEY",
        "IDENTRAIL_WORKOS_WEBHOOK_SECRET",
        "IDENTRAIL_WRITE_API_KEYS",
      ], name)
    ])
    error_message = "api_environment_variables is for non-secret settings only. Put database URLs, API keys, session keys, OAuth/webhook secrets, and HMAC secrets in api_secrets."
  }
}

variable "api_secrets" {
  description = "Map of API environment variable names to Secrets Manager secret ARNs or ECS valueFrom selectors. Values are references only, not secret material."
  type        = map(string)
  default     = {}
  validation {
    condition = alltrue([
      for name, value_from in var.api_secrets :
      can(regex("^[A-Z][A-Z0-9_]*$", name)) &&
      can(regex("^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z]{2}(-gov)?-[a-z]+-[0-9]+:[0-9]{12}:secret:.+$", value_from))
    ])
    error_message = "api_secrets must map uppercase environment variable names to Secrets Manager secret ARNs."
  }
}

variable "api_secret_kms_key_arns" {
  description = "Customer-managed KMS key ARNs needed to decrypt API Secrets Manager references during ECS secret injection. Leave empty when referenced secrets use AWS-managed keys."
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for key_arn in var.api_secret_kms_key_arns :
      can(regex("^arn:(aws|aws-us-gov|aws-cn):kms:[a-z]{2}(-gov)?-[a-z]+-[0-9]+:[0-9]{12}:key/.+$", key_arn))
    ])
    error_message = "api_secret_kms_key_arns must contain KMS key ARNs."
  }
}

variable "api_connector_role_arns" {
  description = "AWS connector role ARNs the hosted API task may assume for connector validation and recurring scans. Leave empty until connector roles are ready."
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for role_arn in var.api_connector_role_arns :
      can(regex("^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/.+$", role_arn))
    ])
    error_message = "api_connector_role_arns must contain IAM role ARNs."
  }
}

variable "api_container_insights_enabled" {
  description = "Enable ECS Container Insights for the API cluster."
  type        = bool
  default     = true
}

variable "api_enable_execute_command" {
  description = "Enable ECS Exec for break-glass debugging. Leave false unless operator access controls and audit expectations are ready."
  type        = bool
  default     = false
}

variable "api_autoscaling_enabled" {
  description = "Enable target-tracking autoscaling for the API ECS service."
  type        = bool
  default     = true
}

variable "api_autoscaling_min_capacity" {
  description = "Minimum API task count when autoscaling is enabled."
  type        = number
  default     = 1
  validation {
    condition     = var.api_autoscaling_min_capacity >= 1
    error_message = "api_autoscaling_min_capacity must be at least 1."
  }
}

variable "api_autoscaling_max_capacity" {
  description = "Maximum API task count when autoscaling is enabled."
  type        = number
  default     = 4
  validation {
    condition     = var.api_autoscaling_max_capacity >= 1
    error_message = "api_autoscaling_max_capacity must be at least 1."
  }
}

variable "api_autoscaling_target_cpu_percent" {
  description = "Average CPU utilization target for API autoscaling."
  type        = number
  default     = 60
  validation {
    condition     = var.api_autoscaling_target_cpu_percent >= 10 && var.api_autoscaling_target_cpu_percent <= 90
    error_message = "api_autoscaling_target_cpu_percent must be between 10 and 90."
  }
}
