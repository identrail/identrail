# Terraform Deployment Baseline

This Terraform baseline deploys Identrail on Kubernetes through the Helm chart.

## What It Creates

- Kubernetes namespace (optional)
- Kubernetes secret for runtime credentials (optional)
- Helm release for API/worker (and web if enabled in chart values)

## Quick Start

1. Copy example variables:
   - `cp deploy/terraform/terraform.tfvars.example deploy/terraform/terraform.tfvars`
2. Set `secret_name` to an existing Kubernetes secret and edit image tags in `terraform.tfvars`.
   - The defaults keep `create_kubernetes_secret=false` to avoid writing runtime secrets to Terraform state.
   - For production hardening values, start from `terraform.prod.tfvars.example` and adapt image tags, CORS origins, resources, and secret management.
3. Deploy:
   - `cd deploy/terraform`
   - `terraform init`
   - `terraform plan`
   - `terraform apply`

## Required Provider Auth

- Kubernetes provider auth from kubeconfig or in-cluster identity.
- Helm provider uses the same Kubernetes context.

## Notes

- This module assumes a Kubernetes cluster already exists.
- `create_kubernetes_secret=true` is an explicit opt-in and will place `secret_data` in Terraform state.
