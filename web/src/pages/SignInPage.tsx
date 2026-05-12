import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { apiClient, buildAPIURL, type AuthConfigResponse } from '../api/client';

type AuthIntent = 'login' | 'signup';

type AuthChoicePageProps = {
  intent: AuthIntent;
};

function normalizeReturnTo(value: string | null): string {
  const candidate = value?.trim() ?? '';
  if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//')) {
    return '/app';
  }
  if (candidate.startsWith('/signin') || candidate.startsWith('/signup')) {
    return '/app';
  }
  return candidate;
}

function authReasonMessage(reason: string): string {
  switch (reason) {
    case 'session_expired':
      return 'Your session expired. Sign in again to continue.';
    case 'callback_error':
      return 'Sign-in did not complete. Please retry.';
    case 'state_mismatch':
      return 'Secure sign-in validation failed. Please retry.';
    default:
      return '';
  }
}

function workOSURL(intent: AuthIntent, returnTo: string): string {
  const query = new URLSearchParams();
  const webReturnTo = typeof window === 'undefined' ? returnTo : new URL(returnTo, window.location.origin).toString();
  query.set('return_to', webReturnTo);
  return buildAPIURL(`/auth/${intent === 'signup' ? 'signup' : 'login'}?${query.toString()}`);
}

export function AuthChoicePage({ intent }: AuthChoicePageProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const query = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const returnTo = normalizeReturnTo(query.get('return_to') ?? query.get('next'));
  const signedOut = query.get('signed_out') === '1';
  const reason = authReasonMessage(query.get('reason') ?? '');
  const [config, setConfig] = useState<AuthConfigResponse | null>(null);
  const [loadingConfig, setLoadingConfig] = useState(true);
  const [configError, setConfigError] = useState('');
  const [manualSubmitting, setManualSubmitting] = useState(false);
  const [manualError, setManualError] = useState('');
  const [manualDraft, setManualDraft] = useState({
    tenantID: 'default',
    workspaceID: 'default',
    projectID: '',
    email: '',
    displayName: ''
  });

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      setLoadingConfig(true);
      setConfigError('');
      try {
        const response = await apiClient.getAuthConfig();
        if (mounted) {
          setConfig(response);
        }
      } catch (error) {
        if (mounted) {
          const message = error instanceof Error ? error.message : 'Unable to load authentication options.';
          setConfigError(message);
        }
      } finally {
        if (mounted) {
          setLoadingConfig(false);
        }
      }
    };
    void run();
    return () => {
      mounted = false;
    };
  }, []);

  const handleManualSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setManualSubmitting(true);
    setManualError('');
    try {
      const response = await apiClient.manualLogin({
        tenant_id: manualDraft.tenantID.trim(),
        workspace_id: manualDraft.workspaceID.trim(),
        project_id: manualDraft.projectID.trim() || undefined,
        email: manualDraft.email.trim() || undefined,
        display_name: manualDraft.displayName.trim() || undefined
      });
      navigate(response.redirect_to || returnTo, { replace: true });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Manual sign-in failed.';
      setManualError(message);
    } finally {
      setManualSubmitting(false);
    }
  };

  const title = intent === 'signup' ? 'Create your Identrail account' : 'Sign in to Identrail';
  const subtitle =
    intent === 'signup'
      ? 'Start with hosted, passwordless access and keep self-host development behind a separate manual mode.'
      : 'Use your approved identity provider to enter the Identrail workspace boundary.';
  const switchLink = intent === 'signup' ? '/signin' : '/signup';
  const switchCopy = intent === 'signup' ? 'Already have an account?' : 'New to Identrail?';
  const switchAction = intent === 'signup' ? 'Sign in' : 'Create account';

  return (
    <section className="idt-auth-page">
      <div className="idt-auth-visual" aria-hidden="true">
        <div className="idt-auth-signal-card">
          <img src="/identrail-logo.png" alt="" />
          <span>Verified access</span>
        </div>
        <div className="idt-auth-path">
          <span>GitHub</span>
          <span>Google</span>
          <span>WorkOS</span>
          <span>Identrail</span>
        </div>
      </div>

      <article className="idt-auth-panel">
        <p className="idt-app-kicker">Account access</p>
        <h1>{title}</h1>
        <p>{subtitle}</p>

        {signedOut ? <p className="idt-app-alert idt-app-alert-success">Signed out successfully.</p> : null}
        {reason ? <p className="idt-app-alert">{reason}</p> : null}

        {loadingConfig ? <p className="idt-app-alert">Loading authentication options...</p> : null}
        {configError ? <p className="idt-app-alert idt-app-alert-error">{configError}</p> : null}

        {config?.auth.workos_login_enabled ? (
          <div className="idt-auth-provider-stack">
            <a className="idt-auth-provider idt-auth-provider-primary" href={workOSURL(intent, returnTo)}>
              <img src="/brand-logos/openid.svg" alt="" />
              <span>{intent === 'signup' ? 'Continue with hosted sign-up' : 'Continue with hosted sign-in'}</span>
            </a>
            <div className="idt-auth-provider-grid" aria-label="Supported identity providers">
              <a className="idt-auth-provider" href={workOSURL(intent, returnTo)}>
                <img src="/brand-logos/github.svg" alt="" />
                <span>GitHub</span>
              </a>
              <a className="idt-auth-provider" href={workOSURL(intent, returnTo)}>
                <span className="idt-auth-provider-letter">G</span>
                <span>Google</span>
              </a>
            </div>
          </div>
        ) : null}

        {config?.auth.manual_mode ? (
          <form className="idt-app-form idt-auth-manual-form" onSubmit={handleManualSubmit}>
            <p className="idt-dev-mode-banner">Dev Mode</p>
            <label>
              Tenant ID
              <input
                value={manualDraft.tenantID}
                onChange={(event) => setManualDraft((current) => ({ ...current, tenantID: event.target.value }))}
                required
              />
            </label>
            <label>
              Workspace ID
              <input
                value={manualDraft.workspaceID}
                onChange={(event) => setManualDraft((current) => ({ ...current, workspaceID: event.target.value }))}
                required
              />
            </label>
            <label>
              Project ID
              <input
                value={manualDraft.projectID}
                onChange={(event) => setManualDraft((current) => ({ ...current, projectID: event.target.value }))}
              />
            </label>
            <label>
              Email
              <input
                type="email"
                value={manualDraft.email}
                onChange={(event) => setManualDraft((current) => ({ ...current, email: event.target.value }))}
              />
            </label>
            <label>
              Display name
              <input
                value={manualDraft.displayName}
                onChange={(event) => setManualDraft((current) => ({ ...current, displayName: event.target.value }))}
              />
            </label>
            {manualError ? <p className="idt-app-alert idt-app-alert-error">{manualError}</p> : null}
            <button className="idt-btn idt-btn-ghost" type="submit" disabled={manualSubmitting}>
              {manualSubmitting ? 'Creating session...' : 'Continue in dev mode'}
            </button>
          </form>
        ) : null}

        {!loadingConfig && config && !config.auth.workos_login_enabled && !config.auth.manual_mode ? (
          <p className="idt-app-alert idt-app-alert-error">This deployment has not enabled an account provider yet.</p>
        ) : null}

        <div className="idt-auth-footer-line">
          <span>{switchCopy}</span>
          <Link to={switchLink}>{switchAction}</Link>
          <Link to="/why-no-passwords">Why no passwords?</Link>
        </div>
      </article>
    </section>
  );
}

export function SignInPage() {
  return <AuthChoicePage intent="login" />;
}
