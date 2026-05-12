DROP POLICY IF EXISTS identity_connections_scope_isolation ON identity_connections;
ALTER TABLE identity_connections NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_connections DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS verified_domains_scope_isolation ON verified_domains;
ALTER TABLE verified_domains NO FORCE ROW LEVEL SECURITY;
ALTER TABLE verified_domains DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS invitations_scope_isolation ON invitations;
ALTER TABLE invitations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE invitations DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS idx_identity_connections_org_status;
DROP TABLE IF EXISTS identity_connections;

DROP INDEX IF EXISTS idx_verified_domains_org_verified;
DROP TABLE IF EXISTS verified_domains;

DROP INDEX IF EXISTS idx_invitations_org_expires;
DROP INDEX IF EXISTS idx_invitations_org_created;
DROP INDEX IF EXISTS idx_invitations_org_email_pending;
DROP TABLE IF EXISTS invitations;
