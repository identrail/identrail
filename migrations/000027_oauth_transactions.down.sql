-- 000027_oauth_transactions.down.sql

DROP INDEX IF EXISTS idx_oauth_transactions_expires_at;
DROP TABLE IF EXISTS oauth_transactions;
