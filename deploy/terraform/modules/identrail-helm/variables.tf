variable "namespace" {
  description = "Kubernetes namespace for Identrail."
  type        = string
}

variable "release_name" {
  description = "Helm release name."
  type        = string
}

variable "chart_path" {
  description = "Filesystem path to the Identrail Helm chart."
  type        = string
}

variable "create_namespace" {
  description = "Create namespace if not present."
  type        = bool
  default     = true
}

variable "create_kubernetes_secret" {
  description = "Create runtime secret from secret_data."
  type        = bool
  default     = false
}

variable "secret_name" {
  description = "Existing secret name to use when not creating one."
  type        = string
  default     = ""
  validation {
    condition     = var.create_kubernetes_secret || length(trimspace(var.secret_name)) > 0
    error_message = "secret_name must be set when create_kubernetes_secret=false."
  }
}

variable "secret_data" {
  description = "Sensitive runtime values for Kubernetes secret string_data."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "chart_values" {
  description = "Additional Helm values."
  # Helm chart values are best modeled as an object because different top-level
  # keys (api/worker/web/secret/config/...) often have different shapes.
  type     = any
  nullable = false
  default  = {}
  validation {
    condition     = can(keys(var.chart_values))
    error_message = "chart_values must be a map/object of Helm values."
  }
}

variable "wait" {
  description = "Wait for Helm resources to become ready."
  type        = bool
  default     = true
}

variable "timeout" {
  description = "Helm release timeout in seconds."
  type        = number
  default     = 600
}
