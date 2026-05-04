CREATE TABLE IF NOT EXISTS tenancy_connector_secret_envelopes (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    secret_name TEXT NOT NULL,
    envelope_version INTEGER NOT NULL DEFAULT 1,
    algorithm TEXT NOT NULL,
    key_version TEXT NOT NULL,
    nonce BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    secret_ref_id TEXT,
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotation_due_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, project_id, connector_id, secret_name),
    FOREIGN KEY (tenant_id, workspace_id, project_id, connector_id)
        REFERENCES tenancy_connectors(tenant_id, workspace_id, project_id, connector_id)
        ON DELETE CASCADE,
    CHECK (LENGTH(TRIM(secret_name)) > 0),
    CHECK (envelope_version > 0),
    CHECK (algorithm = 'AES-256-GCM'),
    CHECK (LENGTH(TRIM(key_version)) > 0),
    CHECK (LENGTH(nonce) = 12),
    CHECK (LENGTH(ciphertext) > 0),
    CHECK (secret_ref_id IS NULL OR LENGTH(TRIM(secret_ref_id)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_tenancy_connector_secret_envelopes_rotation
    ON tenancy_connector_secret_envelopes (tenant_id, workspace_id, rotation_due_at ASC NULLS LAST);
