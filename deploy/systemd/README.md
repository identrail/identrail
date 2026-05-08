# Systemd Deployment

Use this for VM or bare-metal Linux hosts.

## Steps

1. Copy env template:
   - `cp deploy/systemd/identrail.env.example /etc/identrail/identrail.env`
   - `chown root:identrail /etc/identrail/identrail.env`
   - `chmod 0640 /etc/identrail/identrail.env`
   - set `IDENTRAIL_K8S_SOURCE=kubectl` for live Kubernetes collection mode

Keep API keys, database URLs, and webhook secrets out of shell history and logs when editing
`/etc/identrail/identrail.env`.
2. Build binaries:
   - `go build -o /usr/local/bin/identrail-server ./cmd/server`
   - `go build -o /usr/local/bin/identrail-worker ./cmd/worker`
3. Copy runtime assets:
   - `migrations/` to `/opt/identrail/migrations`
   - `testdata/` to `/opt/identrail/testdata`
4. Install units:
   - `cp deploy/systemd/identrail-migrations.service /etc/systemd/system/`
   - `cp deploy/systemd/identrail-api.service /etc/systemd/system/`
   - `cp deploy/systemd/identrail-worker.service /etc/systemd/system/`
5. Start services:
   - `systemctl daemon-reload`
   - `systemctl start identrail-migrations`
   - `systemctl enable --now identrail-api identrail-worker`

Run `identrail-migrations` once before starting or upgrading the API and worker units. Keep
`IDENTRAIL_RUN_MIGRATIONS=false` in the shared environment file so long-running services do
not race each other on schema changes.

The migration unit is intentionally manual-only; avoid enabling it at boot to prevent migrations from running automatically during every startup. Run it explicitly once before enabling long-running services.
