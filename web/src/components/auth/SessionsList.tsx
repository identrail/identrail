import { type SessionListItem } from '../../api/client';
import { EmptyState } from '../common/EmptyState';

type SessionsListProps = {
  sessions: SessionListItem[];
  busySessionID?: string;
  revokingOthers?: boolean;
  onRevoke: (sessionID: string, isCurrent: boolean) => void;
  onRevokeOthers: () => void;
};

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit'
  }).format(date);
}

function compactUserAgent(value?: string): string {
  if (!value) {
    return 'Unknown device';
  }
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (normalized.length <= 96) {
    return normalized;
  }
  return `${normalized.slice(0, 93)}...`;
}

export function SessionsList({
  sessions,
  busySessionID,
  revokingOthers = false,
  onRevoke,
  onRevokeOthers
}: SessionsListProps) {
  if (sessions.length === 0) {
    return (
      <EmptyState
        eyebrow="Sessions"
        title="No active browser sessions"
        body="When you sign in, active sessions for this account will appear here."
      />
    );
  }

  const hasOtherSessions = sessions.some((session) => !session.current);

  return (
    <section className="idt-sessions-list" aria-label="Active account sessions">
      <div className="idt-security-section-header">
        <div>
          <p className="idt-app-kicker">Sessions</p>
          <h2>Active browser sessions</h2>
        </div>
        <button
          className="idt-btn idt-btn-ghost"
          type="button"
          disabled={!hasOtherSessions || revokingOthers}
          onClick={onRevokeOthers}
        >
          {revokingOthers ? 'Revoking...' : 'Revoke others'}
        </button>
      </div>

      <div className="idt-session-stack">
        {sessions.map((session) => (
          <article className="idt-session-row" key={session.id}>
            <div>
              <div className="idt-session-title">
                <strong>{compactUserAgent(session.user_agent)}</strong>
                {session.current ? <span>Current</span> : null}
              </div>
              <p>
                {session.auth_method.toUpperCase()} · {session.ip || 'IP unavailable'} · Last seen{' '}
                {formatDate(session.last_seen_at)}
              </p>
              <p>Idle expiry {formatDate(session.idle_expires_at)}</p>
            </div>
            <button
              className="idt-btn idt-btn-ghost"
              type="button"
              disabled={busySessionID === session.id}
              onClick={() => onRevoke(session.id, session.current)}
            >
              {busySessionID === session.id ? 'Revoking...' : session.current ? 'Sign out here' : 'Revoke'}
            </button>
          </article>
        ))}
      </div>
    </section>
  );
}
