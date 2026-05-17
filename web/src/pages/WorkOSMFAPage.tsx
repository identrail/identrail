import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ApiError, apiClient, type WorkOSMFAPendingResponse } from '../api/client';

function sameOriginPath(value: string | null | undefined, fallback: string, pathPrefix?: string): string {
  const candidate = value?.trim();
  if (!candidate) {
    return fallback;
  }
  try {
    const parsed = new URL(candidate, `${window.location.origin}/`);
    if (parsed.origin !== window.location.origin) {
      return fallback;
    }
    if (pathPrefix && parsed.pathname !== pathPrefix && !parsed.pathname.startsWith(`${pathPrefix}/`)) {
      return fallback;
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}` || fallback;
  } catch {
    return fallback;
  }
}

export function normalizeReturnTo(value: string | null): string {
  return sameOriginPath(value, '/app', '/app');
}

export function normalizeCompletedSessionRedirect(value: string | null | undefined): string {
  return sameOriginPath(value, '/app');
}

function redirectToCompletedSession(target: string, navigate: ReturnType<typeof useNavigate>) {
  navigate(normalizeCompletedSessionRedirect(target), { replace: true });
}

export function mfaErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 401) {
    if (error.message && error.message !== `Request failed (${error.status})`) {
      if (error.message === 'mfa session expired') {
        return 'This verification session expired. Start sign-in again.';
      }
      return error.message;
    }
    return 'This verification session expired. Start sign-in again.';
  }
  return error instanceof Error ? error.message : 'Unable to continue verification.';
}

export function WorkOSMFAPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const query = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const returnTo = normalizeReturnTo(query.get('return_to'));
  const [pending, setPending] = useState<WorkOSMFAPendingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [code, setCode] = useState('');

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      setLoading(true);
      setError('');
      try {
        const response = await apiClient.getWorkOSMFAPending();
        if (mounted) {
          setPending(response);
        }
      } catch (loadError) {
        if (mounted) {
          setError(mfaErrorMessage(loadError));
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };
    void run();
    return () => {
      mounted = false;
    };
  }, []);

  const startEnrollment = async () => {
    setBusy(true);
    setError('');
    try {
      const response = await apiClient.enrollWorkOSMFA();
      setPending(response);
    } catch (enrollError) {
      setError(mfaErrorMessage(enrollError));
    } finally {
      setBusy(false);
    }
  };

  const startChallenge = async (factorID: string) => {
    setBusy(true);
    setError('');
    try {
      await apiClient.challengeWorkOSMFA(factorID);
      setPending((current) => (current ? { ...current, challenge_started: true } : current));
    } catch (challengeError) {
      setError(mfaErrorMessage(challengeError));
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const response = await apiClient.verifyWorkOSMFA(code);
      redirectToCompletedSession(response.redirect_to || returnTo, navigate);
    } catch (verifyError) {
      setError(mfaErrorMessage(verifyError));
    } finally {
      setBusy(false);
    }
  };

  const isEnrollment = pending?.mode === 'enrollment';
  const needsChallengeStart = pending?.mode === 'challenge' && !pending.challenge_started;
  const canEnterCode = Boolean(pending?.challenge_started || pending?.totp);

  return (
    <section className="idt-auth-page idt-auth-page-login">
      <div className="idt-auth-topbar">
        <Link to="/" className="idt-auth-logo is-mark-only" aria-label="Identrail homepage">
          <img src="/identrail-logo.png" alt="" />
          <span>Identrail</span>
        </Link>
        <Link className="idt-auth-topbar-action" to="/signin">
          Sign In
        </Link>
      </div>

      <article className="idt-auth-panel idt-auth-panel-login idt-auth-mfa-panel">
        <h1>{isEnrollment ? 'Set up two-factor authentication' : 'Verify your sign-in'}</h1>
        {pending?.user_email ? <p className="idt-auth-mfa-subtitle">{pending.user_email}</p> : null}
        {error ? <p className="idt-app-alert idt-app-alert-error">{error}</p> : null}
        {loading ? <p className="idt-auth-mfa-subtitle">Loading verification...</p> : null}

        {!loading && pending && isEnrollment && !pending.totp ? (
          <button className="idt-btn idt-btn-primary idt-auth-mfa-full" type="button" onClick={startEnrollment} disabled={busy}>
            {busy ? 'Starting setup...' : 'Set up authenticator app'}
          </button>
        ) : null}

        {!loading && pending?.totp ? (
          <div className="idt-auth-mfa-setup">
            <img className="idt-auth-mfa-qr" src={pending.totp.qr_code} alt="Authenticator QR code" />
            {pending.totp.secret ? <code className="idt-auth-mfa-secret">{pending.totp.secret}</code> : null}
          </div>
        ) : null}

        {!loading && pending && needsChallengeStart ? (
          <div className="idt-auth-provider-stack">
            {pending.factors
              .filter((factor) => factor.type === 'totp')
              .map((factor) => (
                <button
                  className="idt-auth-provider idt-auth-provider-plain"
                  key={factor.id}
                  type="button"
                  onClick={() => startChallenge(factor.id)}
                  disabled={busy}
                >
                  Use authenticator app
                </button>
              ))}
          </div>
        ) : null}

        {!loading && pending && canEnterCode ? (
          <form className="idt-auth-manual-form idt-auth-mfa-form" onSubmit={submitCode}>
            <label>
              Authentication code
              <input
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={10}
                onChange={(event) => setCode(event.target.value)}
                required
                value={code}
              />
            </label>
            <button className="idt-btn idt-btn-primary" type="submit" disabled={busy}>
              {busy ? 'Verifying...' : 'Verify and continue'}
            </button>
          </form>
        ) : null}

        <p className="idt-auth-footer-line">
          <Link to="/signin">Start sign-in again</Link>
        </p>
      </article>
    </section>
  );
}
