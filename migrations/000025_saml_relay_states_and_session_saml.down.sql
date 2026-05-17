-- 000025_saml_relay_states_and_session_saml.down.sql

-- Revert sessions.auth_method to the pre-PR-1153 enum.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'sessions_auth_method_check'
    ) THEN
        ALTER TABLE sessions DROP CONSTRAINT sessions_auth_method_check;
    END IF;
END;
$$;

-- SAML sessions cannot satisfy the pre-SAML CHECK constraint. Rolling back
-- this migration disables native SAML session support, so expire those
-- sessions before re-adding the narrower enum.
DELETE FROM sessions
WHERE auth_method = 'saml';

ALTER TABLE sessions
    ADD CONSTRAINT sessions_auth_method_check
        CHECK (auth_method IN ('workos', 'oidc', 'manual'));

DROP INDEX IF EXISTS idx_saml_relay_states_connection_id;
DROP INDEX IF EXISTS idx_saml_relay_states_expires_at;
DROP TABLE IF EXISTS saml_relay_states;
