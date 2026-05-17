-- 000025_saml_relay_states_and_session_saml.up.sql
--
-- Two changes that unblock the native SAML ACS flow added in PR #1153:
--
-- 1. saml_relay_states persists the small SP-side state (connection id,
--    AuthnRequest id, return_to) that has to survive between the
--    /auth/saml/login redirect and the matching ACS POST. The in-process
--    map this replaces breaks any deployment with more than one API
--    instance — the AuthnRequest issued by instance A is invisible to
--    instance B when the IdP POSTs back to a different node.
--
-- 2. The sessions.auth_method CHECK constraint is widened to accept
--    'saml' as a value. Without this, the very first session insert from
--    the SAML ACS handler fails with a 23514 constraint violation.

------------------------------------------------------------------------------
-- saml_relay_states: short-lived per-AuthnRequest state
------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS saml_relay_states (
    handle TEXT PRIMARY KEY,
    connection_id UUID NOT NULL REFERENCES identity_connections(id) ON DELETE CASCADE,
    saml_request_id TEXT NOT NULL,
    return_to TEXT NOT NULL DEFAULT '',
    intent TEXT NOT NULL DEFAULT 'login',
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (LENGTH(handle) > 0 AND LENGTH(handle) <= 128),
    CHECK (LENGTH(saml_request_id) > 0)
);

-- Prune by expiry; also lets a single sweeping query reclaim consumed rows.
CREATE INDEX IF NOT EXISTS idx_saml_relay_states_expires_at
    ON saml_relay_states (expires_at);

CREATE INDEX IF NOT EXISTS idx_saml_relay_states_connection_id
    ON saml_relay_states (connection_id, created_at DESC);

------------------------------------------------------------------------------
-- sessions.auth_method: accept 'saml'
------------------------------------------------------------------------------

-- 000018 created the original CHECK inline (anonymous), so Postgres assigned
-- it an auto-generated name like sessions_check. Find any CHECK on the
-- sessions table whose definition mentions auth_method and drop it before
-- adding the widened replacement. CHECK constraints are AND'd, so a new
-- broader constraint alone would still be rejected by the old narrower one.
DO $$
DECLARE
    target_name TEXT;
BEGIN
    SELECT conname INTO target_name
    FROM pg_constraint
    WHERE conrelid = 'sessions'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%auth_method%'
    LIMIT 1;
    IF target_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE sessions DROP CONSTRAINT %I', target_name);
    END IF;
END;
$$;

ALTER TABLE sessions
    ADD CONSTRAINT sessions_auth_method_check
        CHECK (auth_method IN ('workos', 'oidc', 'manual', 'saml'));
