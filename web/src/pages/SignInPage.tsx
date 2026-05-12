import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { apiClient, buildAPIURL, type AuthConfigResponse } from '../api/client';

type AuthIntent = 'login' | 'signup';

type AuthChoicePageProps = {
  intent: AuthIntent;
};

type HostedProvider = {
  id: string;
  label: string;
  icon: 'google' | 'github' | 'sso';
  signUpTone?: 'dark';
};

const HOSTED_PROVIDERS: HostedProvider[] = [
  { id: 'google_oauth', label: 'Continue with Google', icon: 'google' },
  { id: 'github_oauth', label: 'Continue with GitHub', icon: 'github', signUpTone: 'dark' },
  { id: 'authkit', label: 'Continue with SAML SSO', icon: 'sso' }
];

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

function providerIcon(provider: HostedProvider) {
  switch (provider.icon) {
    case 'google':
      return (
        <span className="idt-auth-provider-icon idt-auth-provider-icon-google" aria-hidden="true">
          G
        </span>
      );
    case 'github':
      return <img className="idt-auth-provider-icon" src="/brand-logos/github.svg" alt="" />;
    case 'sso':
      return (
        <span className="idt-auth-provider-icon idt-auth-provider-icon-sso" aria-hidden="true">
          <svg viewBox="0 0 16 16" focusable="false">
            <path
              fill="currentColor"
              d="M4.25 7.1V5.4a3.75 3.75 0 1 1 7.5 0v1.7h.45c.72 0 1.3.58 1.3 1.3v4.25c0 .72-.58 1.3-1.3 1.3H3.8c-.72 0-1.3-.58-1.3-1.3V8.4c0-.72.58-1.3 1.3-1.3h.45Zm1.35 0h4.8V5.4a2.4 2.4 0 0 0-4.8 0v1.7Zm3.1 2.75a.7.7 0 1 0-1.4 0v1.45a.7.7 0 1 0 1.4 0V9.85Z"
            />
          </svg>
        </span>
      );
  }
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

  const providerIDs = config?.auth.providers ?? [];
  const hostedProviders =
    config?.auth.workos_login_enabled === true
      ? HOSTED_PROVIDERS.filter((provider) => providerIDs.includes(provider.id))
      : [];
  const title = intent === 'signup' ? 'Your first trust graph is just a sign-up away.' : 'Log in to Identrail';
  const switchLink = intent === 'signup' ? '/signin' : '/signup';
  const switchAction = intent === 'signup' ? 'Log In' : 'Sign Up';

  return (
    <section className={`idt-auth-page idt-auth-page-${intent}`}>
      <div className="idt-auth-topbar">
        <Link to="/" className={`idt-auth-logo ${intent === 'login' ? 'is-mark-only' : ''}`} aria-label="Identrail homepage">
          <img src="/identrail-logo.png" alt="" />
          <span>Identrail</span>
        </Link>
        <Link className="idt-auth-switch" to={switchLink}>
          {switchAction}
        </Link>
      </div>

      <article className={`idt-auth-panel idt-auth-panel-${intent}`}>
        <h1>{title}</h1>

        {signedOut ? <p className="idt-app-alert idt-app-alert-success">Signed out successfully.</p> : null}
        {reason ? <p className="idt-app-alert">{reason}</p> : null}

        {loadingConfig ? <p className="idt-app-alert">Loading authentication options...</p> : null}
        {configError ? <p className="idt-app-alert idt-app-alert-error">{configError}</p> : null}

        {config?.auth.workos_login_enabled ? (
          <div className="idt-auth-provider-stack">
            {hostedProviders.map((provider) => (
              <a
                key={provider.id}
                className={`idt-auth-provider ${
                  intent === 'signup' && provider.signUpTone === 'dark' ? 'idt-auth-provider-dark' : ''
                }`}
                href={workOSURL(intent, returnTo)}
              >
                {providerIcon(provider)}
                <span>{provider.label}</span>
              </a>
            ))}
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
            <button className="idt-auth-provider idt-auth-provider-dark" type="submit" disabled={manualSubmitting}>
              {manualSubmitting ? 'Creating session...' : 'Continue in dev mode'}
            </button>
          </form>
        ) : null}

        {!loadingConfig && config && !config.auth.workos_login_enabled && !config.auth.manual_mode ? (
          <p className="idt-app-alert idt-app-alert-error">This deployment has not enabled an account provider yet.</p>
        ) : null}

        {intent === 'login' ? (
          <div className="idt-auth-footer-line">
            <span>Don't have an account?</span>
            <Link to={switchLink}>Sign Up</Link>
          </div>
        ) : (
          <p className="idt-auth-terms">
            By joining, you agree to our <Link to="/terms">Terms of Service</Link> and{' '}
            <Link to="/privacy">Privacy Policy</Link>
          </p>
        )}
      </article>

      {intent === 'login' ? (
        <div className="idt-auth-legal-footer">
          <Link to="/terms">Terms</Link>
          <Link to="/privacy">Privacy Policy</Link>
        </div>
      ) : null}
    </section>
  );
}

export function SignInPage() {
  return <AuthChoicePage intent="login" />;
}
