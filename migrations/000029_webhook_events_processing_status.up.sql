-- 000029_webhook_events_processing_status.up.sql
--
-- Extend webhook idempotency rows to track processing state so concurrent
-- in-flight duplicates can be retried instead of being acknowledged, and add
-- a per-claim token so a handler whose claim was reclaimed cannot complete
-- or erase the successor's claim.

ALTER TABLE webhook_events
    ADD COLUMN IF NOT EXISTS status TEXT;

ALTER TABLE webhook_events
    ADD COLUMN IF NOT EXISTS claim_token TEXT NOT NULL DEFAULT '';

-- Rows written before this migration were only ever recorded by the old
-- handler *after* it finished applying side effects, i.e. they represent
-- already-seen, terminal events. Backfill them as 'processed' so a duplicate
-- of a legacy event is a no-op success, not treated as in-flight (which
-- would 503 until the stale window and then reapply the side effect).
UPDATE webhook_events
   SET status = 'processed'
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
