import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient, type CurrentUserContext } from '../api/client';

function appPathForSession(me: CurrentUserContext): string {
  if (me.org_id && me.workspace_id) {
    return `/app/${encodeURIComponent(me.org_id)}/${encodeURIComponent(me.workspace_id)}`;
  }
  return '/app';
}

export function AuthCallbackPage() {
  const navigate = useNavigate();

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      try {
        const response = await apiClient.getMe({ redirectOnUnauthorized: false });
        if (mounted) {
          navigate(appPathForSession(response.me), { replace: true });
        }
      } catch {
        if (mounted) {
          navigate('/signin?reason=callback_error', { replace: true });
        }
      }
    };
    void run();
    return () => {
      mounted = false;
    };
  }, [navigate]);

  return (
    <section className="idt-app-shell-screen" aria-live="polite">
      <article className="idt-app-panel">
        <p className="idt-app-kicker">Completing sign-in</p>
        <h1>Securing your workspace session</h1>
        <p>Checking the server session before opening Identrail.</p>
      </article>
    </section>
  );
}
