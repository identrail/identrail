# Deploy

Deployment profiles:

- `docker/`: single-host container deployment
- `kubernetes/`: cluster deployment manifests
- `helm/`: Kubernetes Helm chart
- `systemd/`: VM/bare-metal service units
- `terraform/`: infrastructure modules
- `policies/`: least-privilege read-only templates for AWS and Kubernetes

Published container image examples use `ghcr.io/identrail/identrail-api`, `ghcr.io/identrail/identrail-worker`, and `ghcr.io/identrail/identrail-web`. Pin production deployments to immutable release tags. Helm and Terraform deployment values should use tagged images (`repository` + `tag`), while digest pinning is only for deployment paths that explicitly support digest references.
