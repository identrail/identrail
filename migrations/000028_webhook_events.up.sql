-- 000028_webhook_events.up.sql
--
-- webhook_events is the durable idempotency ledger for provider-issued
-- webhook deliveries (issue #1204). The WorkOS webhook handler validates the
-- HMAC signature but previously applied user lifecycle changes (deactivate,
-- email change) without recording the provider event id, so a retry,
-- duplicate at-least-once delivery, or a replay inside the provider's
-- signature tolerance window would re-apply the side effects.
--
-- After signature validation the handler records (provider, event_id) here
-- before applying side effects. The composite primary key makes the first
-- delivery insert and any duplicate a no-op, durable across API restarts and
-- shared by every API instance pointed at the same database. received_at is
-- retained for provider retry/replay windows and operational troubleshooting.

CREATE TABLE IF NOT EXISTS webhook_events (
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL DEFAULT '',
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, event_id),
    CHECK (LENGTH(provider) > 0 AND LENGTH(provider) <= 64),
    CHECK (LENGTH(event_id) > 0 AND LENGTH(event_id) <= 256)
);

-- Supports age-based retention/cleanup and troubleshooting queries.
CREATE INDEX IF NOT EXISTS idx_webhook_events_received_at
    ON webhook_events (received_at);
