# Systemd Deployment

Use this for VM or bare-metal Linux hosts.

## Steps

1. Copy env template:
   - `cp deploy/systemd/identrail.env.example /etc/identrail/identrail.env`
   - set `IDENTRAIL_K8S_SOURCE=kubectl` for live Kubernetes collection mode
2. Build binaries:
   - `go build -o /usr/local/bin/identrail-server ./cmd/server`
   - `go build -o /usr/local/bin/identrail-worker ./cmd/worker`
3. Copy runtime assets:
   - `migrations/` to `/opt/identrail/migrations`
   - `testdata/` to `/opt/identrail/testdata`
4. Install units:
   - `cp deploy/systemd/identrail-api.service /etc/systemd/system/`
   - `cp deploy/systemd/identrail-worker.service /etc/systemd/system/`
5. Start services:
   - `systemctl daemon-reload`
   - `systemctl enable --now identrail-api identrail-worker`

The example binds the API to `127.0.0.1:8080` so a reverse proxy or load balancer owns
public TLS and ingress controls. If you bind directly to a public interface, configure
host firewall rules, TLS termination, and trusted proxy settings before exposing the unit.
