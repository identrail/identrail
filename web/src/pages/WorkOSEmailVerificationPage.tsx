import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router';
import { OTPInput, REGEXP_ONLY_DIGITS } from 'input-otp';
import { ApiError, apiClient, type WorkOSEmailVerificationPendingResponse } from '../api/client';
import { normalizeCompletedSessionRedirect, normalizeReturnTo } from './WorkOSMFAPage';

export function emailVerificationErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 401) {
    if (error.message && error.message !== `Request failed (${error.status})`) {
      if (error.message === 'email verification session expired') {
        return 'This verification session expired. Start sign-in again to receive a new code.';
      }
      return error.message;
    }
    return 'This verification session expired. Start sign-in again to receive a new code.';
  }
  return error instanceof Error ? error.message : 'Unable to continue verification.';
}

export function WorkOSEmailVerificationPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const query = useMemo(() => new URLSearchParams(location.search), [location.search]);
  const returnTo = normalizeReturnTo(query.get('return_to'));
  const [pending, setPending] = useState<WorkOSEmailVerificationPendingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [code, setCode] = useState('');
  const lastAutoSubmittedCodeRef = useRef('');

  useEffect(() => {
    let mounted = true;
    const run = async () => {
      setLoading(true);
      setError('');
      try {
        const response = await apiClient.getWorkOSEmailVerificationPending();
        if (mounted) {
          setPending(response);
        }
      } catch (loadError) {
        if (mounted) {
          setError(emailVerificationErrorMessage(loadError));
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

  const verifyCode = useCallback(async (nextCode: string) => {
    const verificationCode = nextCode.trim();
    if (busy || verificationCode.length < 6) {
      return;
    }
    lastAutoSubmittedCodeRef.current = verificationCode;
    setBusy(true);
    setError('');
    try {
      const response = await apiClient.verifyWorkOSEmailVerification(verificationCode);
      navigate(normalizeCompletedSessionRedirect(response.redirect_to || returnTo), { replace: true });
    } catch (verifyError) {
      lastAutoSubmittedCodeRef.current = '';
      setError(emailVerificationErrorMessage(verifyError));
    } finally {
      setBusy(false);
    }
  }, [busy, navigate, returnTo]);

  const submitCode = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    void verifyCode(code);
  };

  useEffect(() => {
    const verificationCode = code.trim();
    if (verificationCode.length < 6) {
      lastAutoSubmittedCodeRef.current = '';
      return;
    }
    if (loading || !pending || busy || error) {
      return;
    }
    if (lastAutoSubmittedCodeRef.current === verificationCode) {
      return;
    }
    lastAutoSubmittedCodeRef.current = verificationCode;
    void verifyCode(verificationCode);
  }, [busy, code, error, loading, pending, verifyCode]);

  const retryVerification = () => {
    lastAutoSubmittedCodeRef.current = '';
    void verifyCode(code);
  };

  const updateCode = (nextCode: string) => {
    setCode(nextCode);
    if (error && pending) {
      setError('');
    }
    if (nextCode.trim().length < 6) {
      lastAutoSubmittedCodeRef.current = '';
    }
  };

  const canRetryVerification = Boolean(error && pending && code.trim().length === 6 && !busy);

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
        <h1>Verify your email address</h1>
        {pending?.email ? <p className="idt-auth-mfa-subtitle">{pending.email}</p> : null}
        {error ? <p className="idt-app-alert idt-app-alert-error">{error}</p> : null}
        {loading ? <p className="idt-auth-mfa-subtitle">Loading verification...</p> : null}

        {!loading && pending ? (
          <p className="idt-auth-mfa-subtitle">
            Enter the code we emailed you to finish signing in.
          </p>
        ) : null}

        {!loading && pending ? (
          <form className="idt-auth-manual-form idt-auth-mfa-form" onSubmit={submitCode} aria-busy={busy}>
            <OTPInput
              aria-label="Email verification code"
              autoComplete="one-time-code"
              autoFocus
              containerClassName="idt-auth-otp"
              disabled={busy}
              inputMode="numeric"
              maxLength={6}
              onChange={updateCode}
              pattern={REGEXP_ONLY_DIGITS}
              pushPasswordManagerStrategy="none"
              value={code}
              render={({ slots }) => (
                <div className="idt-auth-otp-group">
                  {slots.map((slot, index) => (
                    <div
                      aria-hidden="true"
                      className={[
                        'idt-auth-otp-slot',
                        slot.isActive ? 'is-active' : '',
                        slot.char ? 'is-filled' : ''
                      ]
                        .filter(Boolean)
                        .join(' ')}
                      key={index}
                    >
                      {slot.char ?? ''}
                      {slot.hasFakeCaret ? <span className="idt-auth-otp-caret" /> : null}
                    </div>
                  ))}
                </div>
              )}
            />
            <p className="idt-visually-hidden" role="status" aria-live="polite">
              {busy ? 'Verifying code.' : ''}
            </p>
          </form>
        ) : null}

        {canRetryVerification ? (
          <button className="idt-btn idt-btn-secondary idt-auth-mfa-full" type="button" onClick={retryVerification}>
            Try again
          </button>
        ) : null}
      </article>
    </section>
  );
}
