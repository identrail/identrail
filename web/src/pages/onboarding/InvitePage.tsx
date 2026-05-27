import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { apiClient, type OnboardingState } from '../../api/client';
import { SkipForNow } from '../../components/onboarding/SkipForNow';
import {
  FEATURE_ONBOARDING_WIZARD,
  OnboardingFrame,
  loadOrStartOnboardingResponse,
  normalizeMemberToken,
  onboardingAuth,
  routeAfterOnboardingResponse,
  routeToOnboardingStep
} from './onboardingUtils';

function parseInviteEmails(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\s,;]+/)
        .map((item) => item.trim().toLowerCase())
        .filter((item) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item))
    )
  );
}

export function InvitePage() {
  const navigate = useNavigate();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [emails, setEmails] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [emailsError, setEmailsError] = useState('');
  const invitees = useMemo(() => parseInviteEmails(emails), [emails]);

  useEffect(() => {
    if (!FEATURE_ONBOARDING_WIZARD) {
      return;
    }
    let mounted = true;
    const run = async () => {
      setLoading(true);
      setError('');
      try {
        const response = await loadOrStartOnboardingResponse();
        const nextState = response.state;
        if (!mounted) {
          return;
        }
        setState(nextState);
        if (!nextState.org_id || !nextState.workspace_id) {
          navigate('/onboarding/workspace', { replace: true });
          return;
        }
        if (routeToOnboardingStep(navigate, response, '/onboarding/invite', '/onboarding/invite')) {
          return;
        }
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        setError(requestError instanceof Error ? requestError.message : 'Unable to load invite step.');
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
  }, [navigate]);

  if (!FEATURE_ONBOARDING_WIZARD) {
    return <Navigate to="/app" replace />;
  }

  const complete = async () => {
    setSaving(true);
    setError('');
    setEmailsError('');
    try {
      const response = await apiClient.completeOnboarding();
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/app');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to complete onboarding.');
    } finally {
      setSaving(false);
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setEmailsError('');
    if (!state?.workspace_id) {
      setError('Workspace context is required before inviting teammates.');
      return;
    }
    if (!invitees.length) {
      setEmailsError('Enter a valid email');
      return;
    }
    setSaving(true);
    try {
      const auth = onboardingAuth(state);
      for (const email of invitees) {
        const memberID = `member-${normalizeMemberToken(email) || Date.now()}`;
        await apiClient.upsertWorkspaceMember(
          state.workspace_id,
          {
            member_id: memberID,
            user_id: email,
            email,
            role: 'viewer',
            status: 'invited'
          },
          auth
        );
      }
      const response = await apiClient.completeOnboarding();
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/app');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to invite teammates.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <OnboardingFrame
      step="invite"
      eyebrow="Team"
      title="Invite reviewers"
      description="Add teammates who will own findings."
    >
      {loading ? <p className="idt-muted-strong">Preparing invite controls...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <form className="idt-onboarding-form" onSubmit={submit}>
        <div className="idt-onboarding-field">
          <label htmlFor="invite-emails">Email addresses</label>
          <div className={emailsError ? 'idt-onboarding-input-wrap has-error' : 'idt-onboarding-input-wrap'}>
            <textarea
              id="invite-emails"
              value={emails}
              onChange={(event) => {
                setEmails(event.target.value);
                if (emailsError) {
                  setEmailsError('');
                }
              }}
              rows={5}
              aria-invalid={emailsError ? 'true' : undefined}
              aria-describedby={emailsError ? 'invite-emails-error' : undefined}
            />
            {emailsError ? (
              <span id="invite-emails-error" className="idt-onboarding-input-error" role="alert">
                {emailsError}
              </span>
            ) : null}
          </div>
        </div>
        <div className="idt-onboarding-actions">
          <button type="submit" className="idt-btn idt-btn-primary" disabled={saving || loading}>
            {saving ? 'Finishing...' : 'Invite and finish'}
          </button>
          <SkipForNow disabled={saving || loading} onSkip={complete} label="Finish without invites" />
        </div>
      </form>
    </OnboardingFrame>
  );
}
