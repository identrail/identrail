# Systemd Deployment

Use this for VM or bare-metal Linux hosts.

## Steps

1. Copy env template:
   - `cp deploy/systemd/identrail.env.example /etc/identrail/identrail.env`
   - confirm the live AWS SDK and kubectl source settings match the host credentials
2. Build binaries:
   - `go build -o /usr/local/bin/identrail-server ./cmd/server`
   - `go build -o /usr/local/bin/identrail-worker ./cmd/worker`
3. Copy runtime assets:
   - `migrations/` to `/opt/identrail/migrations`
   - `testdata/` to `/opt/identrail/testdata` only for demo fixture-mode evaluations
4. Install units:
   - `cp deploy/systemd/identrail-api.service /etc/systemd/system/`
   - `cp deploy/systemd/identrail-worker.service /etc/systemd/system/`
5. Start services:
   - `systemctl daemon-reload`
   - `systemctl enable --now identrail-api identrail-worker`
