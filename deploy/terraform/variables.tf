variable "namespace" {
  description = "Kubernetes namespace for Identrail."
  type        = string
  default     = "identrail"
}

variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "identrail"
}

variable "chart_path" {
  description = "Path to the Identrail Helm chart."
  type        = string
  default     = "../helm/identrail"
}

variable "create_namespace" {
  description = "Create the namespace if it does not already exist."
  type        = bool
  default     = true
}

variable "create_kubernetes_secret" {
  description = "Create a Kubernetes secret from secret_data. Keep false in production to avoid persisting secrets in Terraform state."
  type        = bool
  default     = false
}

variable "secret_name" {
  description = "Existing secret name to use when create_kubernetes_secret=false."
  type        = string
  default     = ""
}

variable "secret_data" {
  description = "Sensitive runtime values injected as Kubernetes secret string_data."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "chart_values" {
  description = "Additional Helm values merged into release settings."
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
