-- user_data_exports tracks self-serve "Download my data" jobs (#1421).
--
-- Each row is one export request by one user. Lifecycle:
--   queued -> running -> ready -> expired (after retention window)
--                     \-> failed
--
-- The bundle itself lives in object storage / local disk (referenced by
-- bundle_path). The signed-download URL is HMAC-signed by the API using the
-- server's session key, so no token material is persisted on the row — it can
-- be re-issued statelessly on every poll while remaining tamper-resistant.
CREATE TABLE IF NOT EXISTS user_data_exports (
    id                  UUID        PRIMARY KEY,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status              TEXT        NOT NULL CHECK (status IN ('queued','running','ready','failed','expired')),
    bundle_path         TEXT        NOT NULL DEFAULT '',
    bundle_size_bytes   BIGINT      NOT NULL DEFAULT 0,
    bundle_sha256       TEXT        NOT NULL DEFAULT '',
    error_message       TEXT        NOT NULL DEFAULT '',
    requested_at        TIMESTAMPTZ NOT NULL,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    download_expires_at TIMESTAMPTZ,
    purge_after         TIMESTAMPTZ,
    purged_at           TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_user_data_exports_user ON user_data_exports(user_id, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_data_exports_queued ON user_data_exports(requested_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_user_data_exports_purge ON user_data_exports(purge_after) WHERE purged_at IS NULL AND purge_after IS NOT NULL;
