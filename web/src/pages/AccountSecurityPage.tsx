import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { apiClient, type SessionListItem } from '../api/client';
import { SessionsList } from '../components/auth/SessionsList';
import { ErrorState } from '../components/common/ErrorState';
import { useMe } from '../hooks/useMe';

export function AccountSecurityPage() {
  const navigate = useNavigate();
  const { me, loading, error, unauthenticated, refresh } = useMe();
  const [sessions, setSessions] = useState<SessionListItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(true);
  const [sessionsError, setSessionsError] = useState('');
  const [busySessionID, setBusySessionID] = useState('');
  const [revokingOthers, setRevokingOthers] = useState(false);

  const loadSessions = async () => {
    setSessionsLoading(true);
    setSessionsError('');
    try {
      const response = await apiClient.listCurrentUserSessions();
      setSessions(response.items);
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : 'Unable to load active sessions.';
      setSessionsError(message);
    } finally {
      setSessionsLoading(false);
    }
  };

  useEffect(() => {
    if (!unauthenticated) {
      void loadSessions();
    }
  }, [unauthenticated]);

  const handleRevoke = async (sessionID: string, isCurrent: boolean) => {
    setBusySessionID(sessionID);
    setSessionsError('');
    try {
      await apiClient.revokeCurrentUserSession(sessionID);
      if (isCurrent) {
        navigate('/signin?signed_out=1', { replace: true });
        return;
      }
      await loadSessions();
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : 'Unable to revoke session.';
      setSessionsError(message);
    } finally {
      setBusySessionID('');
    }
  };

  const handleRevokeOthers = async () => {
    setRevokingOthers(true);
    setSessionsError('');
    try {
      await apiClient.revokeOtherCurrentUserSessions();
      await loadSessions();
    } catch (requestError) {
      const message = requestError instanceof Error ? requestError.message : 'Unable to revoke other sessions.';
      setSessionsError(message);
    } finally {
      setRevokingOthers(false);
    }
  };

  if (loading) {
    return (
      <section className="idt-app-shell-screen" aria-live="polite">
        <article className="idt-app-panel">
          <p className="idt-app-kicker">Loading</p>
          <h1>Loading account security</h1>
          <p>Checking your server session.</p>
        </article>
      </section>
    );
  }

  if (unauthenticated) {
    return (
      <section className="idt-app-shell-screen">
        <ErrorState title="Sign in required" message="Your account session is not active." />
        <div className="idt-inline-actions">
          <Link className="idt-btn idt-btn-primary" to="/signin">
            Sign In
          </Link>
        </div>
      </section>
    );
  }

  return (
    <section className="idt-app-shell idt-account-security-page">
      <header className="idt-app-shell-header">
        <div>
          <p className="idt-app-kicker">Account security</p>
          <h1>{me?.user.display_name || me?.user.primary_email || 'Your account'}</h1>
          <p>
            {me?.user.primary_email}
            {me?.workspace_id ? (
              <>
                {' '}
                · Workspace <strong>{me.workspace_id}</strong>
              </>
            ) : null}
          </p>
        </div>
        <div className="idt-app-shell-actions">
          <button
            className="idt-btn idt-btn-ghost"
            type="button"
            onClick={() => {
              void refresh();
              void loadSessions();
            }}
          >
            Refresh
          </button>
          <Link className="idt-btn idt-btn-dark" to={me?.org_id && me.workspace_id ? `/app/${me.org_id}/${me.workspace_id}` : '/app'}>
            Back to app
          </Link>
        </div>
      </header>

      {error ? <ErrorState title="Unable to load account" message={error} actionLabel="Retry" onAction={() => void refresh()} /> : null}

      <section className="idt-app-panel idt-security-overview">
        <article>
          <p className="idt-app-kicker">Identity</p>
          <h2>{me?.user.primary_email}</h2>
          <p>Status: {me?.user.status ?? 'unknown'}</p>
        </article>
        <article>
          <p className="idt-app-kicker">Access scope</p>
          <h2>{me?.role ?? 'member'}</h2>
          <p>{me?.org_id && me.workspace_id ? `${me.org_id} / ${me.workspace_id}` : 'No workspace selected yet'}</p>
        </article>
      </section>

      <section className="idt-app-panel">
        {sessionsLoading ? <p className="idt-app-alert">Loading active sessions...</p> : null}
        {sessionsError ? <ErrorState title="Session action failed" message={sessionsError} /> : null}
        {!sessionsLoading ? (
          <SessionsList
            sessions={sessions}
            busySessionID={busySessionID}
            revokingOthers={revokingOthers}
            onRevoke={handleRevoke}
            onRevokeOthers={handleRevokeOthers}
          />
        ) : null}
      </section>
    </section>
  );
}
