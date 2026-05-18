-- 000029_webhook_events_processing_status.up.sql
--
-- Extend webhook idempotency rows to track processing state so concurrent
-- in-flight duplicates can be retried instead of being acknowledged.

ALTER TABLE webhook_events
    ADD COLUMN IF NOT EXISTS status TEXT;

UPDATE webhook_events
   SET status = 'processing'
 WHERE status IS NULL;

ALTER TABLE webhook_events
    ALTER COLUMN status SET DEFAULT 'processing';

ALTER TABLE webhook_events
    ALTER COLUMN status SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'webhook_events_status_check'
          AND conrelid = 'webhook_events'::regclass
    ) THEN
        ALTER TABLE webhook_events
            ADD CONSTRAINT webhook_events_status_check
            CHECK (status IN ('processing', 'processed'));
    END IF;
END $$;
