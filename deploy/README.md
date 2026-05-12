# Deploy

Deployment profiles:

- `aws/`: AWS deployment foundation and future AWS hosting stack
- `docker/`: single-host container deployment
- `kubernetes/`: cluster deployment manifests
- `helm/`: Kubernetes Helm chart
- `systemd/`: VM/bare-metal service units
- `terraform/`: infrastructure modules
- `policies/`: least-privilege read-only templates for AWS and Kubernetes

Published container image examples use `ghcr.io/identrail/identrail` for the main server image, with `ghcr.io/identrail/identrail-worker`, `ghcr.io/identrail/identrail-web`, and the compatibility alias `ghcr.io/identrail/identrail-api` for multi-service deployments. Pin production deployments to immutable release tags. Helm and Terraform deployment values should use tagged images (`repository` + `tag`), while digest pinning is only for deployment paths that explicitly support digest references.

AWS deployment starts with a validation-only foundation. See `aws/README.md`
before enabling resource creation.
