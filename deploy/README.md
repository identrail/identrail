# Deploy

Deployment profiles:

- `docker/`: single-host container deployment
- `kubernetes/`: cluster deployment manifests
- `helm/`: Kubernetes Helm chart
- `systemd/`: VM/bare-metal service units
- `terraform/`: infrastructure modules
- `policies/`: least-privilege read-only templates for AWS and Kubernetes

Published container image examples use `ghcr.io/identrail/identrail-api`, `ghcr.io/identrail/identrail-worker`, and `ghcr.io/identrail/identrail-web`. The `dev` tag is published from the default branch for evaluation, while production deployments should pin immutable release or SHA tags. Helm and Terraform deployment values should use tagged images (`repository` + `tag`), while digest pinning is only for deployment paths that explicitly support digest references.
