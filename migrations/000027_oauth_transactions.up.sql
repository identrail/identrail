-- 000027_oauth_transactions.up.sql
--
-- oauth_transactions persists the small server-side context for one in-flight
-- WorkOS OAuth login (issue #1200). Before this table the only replay
-- protection for the signed `state` token was a process-local `used` nonce
-- map. That map is invisible to other API instances, so a captured state
-- could be replayed against any instance that had not itself seen the nonce,
-- and a valid signed state was accepted without proving the same browser
-- initiated that specific login.
--
-- The callback now requires the signed state nonce AND a browser-bound
-- cookie token to match an unconsumed, unexpired row. The row is one-shot
-- consumed (UPDATE ... WHERE consumed_at IS NULL RETURNING) so replays fail
-- across every API instance that shares this database. Rows expire after a
-- short TTL and are swept on consume.

CREATE TABLE IF NOT EXISTS oauth_transactions (
    nonce TEXT PRIMARY KEY,
    cookie_token TEXT NOT NULL,
    intent TEXT NOT NULL DEFAULT 'login',
    return_to TEXT NOT NULL DEFAULT '',
    expected_user_id TEXT NOT NULL DEFAULT '',
    expected_session_id TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (LENGTH(nonce) > 0 AND LENGTH(nonce) <= 128),
    CHECK (LENGTH(cookie_token) > 0 AND LENGTH(cookie_token) <= 128)
);

-- Prune by expiry; also lets the post-consume sweep reclaim consumed rows.
CREATE INDEX IF NOT EXISTS idx_oauth_transactions_expires_at
    ON oauth_transactions (expires_at);
