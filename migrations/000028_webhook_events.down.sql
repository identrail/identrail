-- 000028_webhook_events.down.sql

DROP INDEX IF EXISTS idx_webhook_events_received_at;
DROP TABLE IF EXISTS webhook_events;
