# Deploy

Deployment profiles:

- `aws/`: AWS deployment foundation and future AWS hosting stack
- `docker/`: single-host container deployment
- `kubernetes/`: cluster deployment manifests
- `helm/`: Kubernetes Helm chart
- `systemd/`: VM/bare-metal service units
- `terraform/`: infrastructure modules
- `policies/`: least-privilege read-only templates for AWS and Kubernetes

Published public evaluation images are available from Docker Hub under `docker.io/identrail/*`, with GHCR mirrors under `ghcr.io/identrail/*`. Deployment examples still use `ghcr.io/identrail/identrail` for the main server image, with `ghcr.io/identrail/identrail-worker`, `ghcr.io/identrail/identrail-web`, and the compatibility alias `ghcr.io/identrail/identrail-api` for multi-service deployments. Pin production deployments to immutable release tags. Helm and Terraform deployment values should use tagged images (`repository` + `tag`), while digest pinning is only for deployment paths that explicitly support digest references.

AWS deployment starts with a validation-only foundation and a plan-first API
hosting layer. See `aws/README.md` and `../docs/aws-api-hosting.md` before
enabling resource creation.
