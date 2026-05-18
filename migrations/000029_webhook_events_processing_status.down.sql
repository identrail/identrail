-- 000029_webhook_events_processing_status.down.sql

ALTER TABLE webhook_events
    DROP COLUMN IF EXISTS claim_token;

ALTER TABLE webhook_events
    DROP COLUMN IF EXISTS status;
