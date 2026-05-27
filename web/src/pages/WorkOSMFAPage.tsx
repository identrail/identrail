import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
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

function totpFactors(pending: WorkOSMFAPendingResponse | null) {
  return pending?.factors.filter((factor) => factor.type === 'totp') ?? [];
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
  const [autoChallengeFactorID, setAutoChallengeFactorID] = useState('');
  // Holds a deferred promise that resolves with the outcome of the silent
  // auto-challenge POST. Stored as a ref so we can populate it *during render*
  // — before the submittable form is committed to the DOM — and resolve it
  // later from the useEffect that actually fires the API call. This closes
  // the race where a programmatic submit (autofill helper hooked on
  // MutationObserver, `form.requestSubmit()`, or `Enter` on the autofocus
  // input) fired between commit and effect would otherwise see a null ref
  // and call /auth/mfa/verify before /auth/mfa/challenge had started.
  const challengeRequestRef = useRef<{
    promise: Promise<boolean>;
    resolve: (ok: boolean) => void;
  } | null>(null);

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

  const startChallenge = useCallback(async (factorID: string, options?: { silent?: boolean }) => {
    const silent = options?.silent === true;
    if (!silent) {
      setBusy(true);
    }
    setError('');
    // For silent (auto) challenges, the effect that mounted the form also
    // initializes the deferred promise in `challengeRequestRef`; resolve that
    // deferred when the API call
    // settles. For user-initiated (picker) challenges there is no deferred —
    // submitCode is gated on canEnterCode for that flow.
    const deferred = silent ? challengeRequestRef.current : null;
    try {
      await apiClient.challengeWorkOSMFA(factorID);
      setPending((current) => (current ? { ...current, challenge_started: true } : current));
      deferred?.resolve(true);
    } catch (challengeError) {
      setError(mfaErrorMessage(challengeError));
      deferred?.resolve(false);
    } finally {
      if (!silent) {
        setBusy(false);
      }
    }
  }, []);

  const submitCode = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) {
      return;
    }
    setBusy(true);
    setError('');
    try {
      // If the auto-challenge POST is still in flight, wait for the deferred
      // outcome before verifying. This keeps the submit path aligned with
      // challenge setup so a programmatic submit cannot race ahead of
      // `/auth/mfa/challenge`.
      const inFlightChallenge = challengeRequestRef.current;
      if (inFlightChallenge && !canEnterCode) {
        const challengeOk = await inFlightChallenge.promise;
        if (!challengeOk) {
          // startChallenge already surfaced the error to state; abort verify.
          return;
        }
      }
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
  const enrollmentChallengeStarted = Boolean(isEnrollment && pending?.challenge_started && !pending.totp);
  const canEnterCode = Boolean(pending?.challenge_started || pending?.totp);
  const availableTOTPFactors = totpFactors(pending);
  const autoChallengeFactorIDCandidate =
    !loading && needsChallengeStart && availableTOTPFactors.length === 1 ? availableTOTPFactors[0].id : '';
  const showChallengePicker = Boolean(
    !loading && pending && needsChallengeStart && (!autoChallengeFactorIDCandidate || error)
  );

  // Start the auto-challenge in the same effect cycle that also prepares the
  // deferred verifier. This keeps the challenge in flight before the manual
  // code form is ever mounted, avoiding programmatic submit races.
  useEffect(() => {
    if (!autoChallengeFactorIDCandidate || autoChallengeFactorID === autoChallengeFactorIDCandidate) {
      return;
    }

    if (challengeRequestRef.current === null) {
      let resolveDeferred: (ok: boolean) => void = () => {};
      const promise = new Promise<boolean>((resolve) => {
        resolveDeferred = resolve;
      });
      challengeRequestRef.current = { promise, resolve: resolveDeferred };
    }

    setAutoChallengeFactorID(autoChallengeFactorIDCandidate);
    void startChallenge(autoChallengeFactorIDCandidate, { silent: true });
  }, [autoChallengeFactorID, autoChallengeFactorIDCandidate, startChallenge]);

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

        {!loading && pending && isEnrollment && !pending.totp && !pending.challenge_started ? (
          <button className="idt-btn idt-btn-primary idt-auth-mfa-full" type="button" onClick={startEnrollment} disabled={busy}>
            {busy ? 'Starting setup...' : 'Set up authenticator app'}
          </button>
        ) : null}

        {!loading && pending && enrollmentChallengeStarted ? (
          <p className="idt-auth-mfa-subtitle">
            Enter the code from the authenticator app you just added. Start sign-in again if you need a fresh QR code.
          </p>
        ) : null}

        {!loading && pending?.totp ? (
          <div className="idt-auth-mfa-setup">
            <img className="idt-auth-mfa-qr" src={pending.totp.qr_code} alt="Authenticator QR code" />
            {pending.totp.secret ? <code className="idt-auth-mfa-secret">{pending.totp.secret}</code> : null}
          </div>
        ) : null}

        {showChallengePicker ? (
          <div className="idt-auth-provider-stack">
            {availableTOTPFactors.map((factor) => (
              <button
                className="idt-auth-provider idt-auth-provider-plain"
                key={factor.id}
                type="button"
                onClick={() => startChallenge(factor.id)}
                disabled={busy}
              >
                {busy ? 'Preparing challenge...' : 'Use authenticator app'}
              </button>
            ))}
          </div>
        ) : null}

        {!loading && pending && (canEnterCode || (autoChallengeFactorID && !error)) ? (
          <form className="idt-auth-manual-form idt-auth-mfa-form" onSubmit={submitCode}>
            <input
              aria-label="Authentication code"
              autoFocus
              autoComplete="one-time-code"
              inputMode="numeric"
              maxLength={6}
              onChange={(event) => setCode(event.target.value)}
              pattern="[0-9]*"
              placeholder="000000"
              required
              value={code}
            />
            <button className="idt-btn idt-btn-primary" type="submit" disabled={busy || !canEnterCode}>
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
