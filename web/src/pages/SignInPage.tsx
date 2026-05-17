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
};

const HOSTED_PROVIDERS: HostedProvider[] = [
  { id: 'google_oauth', label: 'Continue with Google', icon: 'google' },
  { id: 'github_oauth', label: 'Continue with GitHub', icon: 'github' },
  { id: 'authkit', label: 'Continue with SAML SSO', icon: 'sso' }
];

type AuthTheme = 'light' | 'system' | 'dark';

const AUTH_THEME_OPTIONS: Array<{ value: AuthTheme; label: string }> = [
  { value: 'light', label: 'Light' },
  { value: 'system', label: 'System' },
  { value: 'dark', label: 'Dark' }
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

function authConfigErrorMessage(error: unknown): string {
  if (error instanceof TypeError && /fetch/i.test(error.message)) {
    return 'Identrail API is not reachable yet. Please retry after the production API is online.';
  }
  return error instanceof Error ? error.message : 'Unable to load authentication options.';
}

function workOSURL(intent: AuthIntent, returnTo: string, provider: HostedProvider): string {
  const query = new URLSearchParams();
  const webReturnTo = typeof window === 'undefined' ? returnTo : new URL(returnTo, window.location.origin).toString();
  query.set('return_to', webReturnTo);
  query.set('provider', provider.id);
  return buildAPIURL(`/auth/${intent === 'signup' ? 'signup' : 'login'}?${query.toString()}`);
}

function providerIcon(provider: HostedProvider) {
  switch (provider.icon) {
    case 'google':
      return (
        <svg className="idt-auth-provider-icon idt-auth-provider-icon-google" viewBox="0 0 18 18" aria-hidden="true">
          <path
            fill="#4285F4"
            d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.91c1.7-1.57 2.69-3.88 2.69-6.62Z"
          />
          <path
            fill="#34A853"
            d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.91-2.26c-.81.54-1.84.86-3.05.86-2.35 0-4.34-1.58-5.05-3.72H.94v2.33A9 9 0 0 0 9 18Z"
          />
          <path
            fill="#FBBC05"
            d="M3.95 10.7A5.4 5.4 0 0 1 3.67 9c0-.59.1-1.16.28-1.7V4.97H.94A9 9 0 0 0 0 9c0 1.45.34 2.82.94 4.03l3.01-2.33Z"
          />
          <path
            fill="#EA4335"
            d="M9 3.58c1.32 0 2.5.45 3.43 1.34l2.59-2.58A8.66 8.66 0 0 0 9 0 9 9 0 0 0 .94 4.97L3.95 7.3C4.66 5.16 6.65 3.58 9 3.58Z"
          />
        </svg>
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
  const [authTheme, setAuthTheme] = useState<AuthTheme>('dark');
  const [prefersDark, setPrefersDark] = useState(true);
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
          setConfigError(authConfigErrorMessage(error));
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

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const updatePreference = () => setPrefersDark(media.matches);
    updatePreference();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', updatePreference);
      return () => media.removeEventListener('change', updatePreference);
    }
    media.addListener(updatePreference);
    return () => media.removeListener(updatePreference);
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
  const resolvedTheme = authTheme === 'system' ? (prefersDark ? 'dark' : 'light') : authTheme;

  return (
    <section className={`idt-auth-page idt-auth-page-${intent}`} data-auth-theme={resolvedTheme}>
      <div className="idt-auth-topbar">
        <Link to="/" className={`idt-auth-logo ${intent === 'login' ? 'is-mark-only' : ''}`} aria-label="Identrail homepage">
          <img src="/identrail-logo.png" alt="" />
          <span>Identrail</span>
        </Link>
        <Link className="idt-auth-topbar-action" to={switchLink}>
          {switchAction}
        </Link>
      </div>

      <div className="idt-auth-layout" data-auth-intent={intent}>
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
                  className={`idt-auth-provider idt-auth-provider-${provider.icon}`}
                  href={workOSURL(intent, returnTo, provider)}
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
              By joining, you agree to our <Link to="/terms">Terms of Use</Link> and{' '}
              <Link to="/privacy">Privacy Policy</Link>
            </p>
          )}
        </article>
      </div>

      <div className="idt-auth-legal-footer">
        <Link to="/terms">Terms</Link>
        <Link to="/privacy">Privacy Policy</Link>
      </div>

      <div className="idt-auth-theme-switcher" aria-label="Color theme">
        {AUTH_THEME_OPTIONS.map((option) => (
          <button
            key={option.value}
            type="button"
            className={authTheme === option.value ? 'is-active' : ''}
            aria-pressed={authTheme === option.value}
            onClick={() => setAuthTheme(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>
    </section>
  );
}

export function SignInPage() {
  return <AuthChoicePage intent="login" />;
}
