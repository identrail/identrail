import { FormEvent, useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { apiClient, type OnboardingState } from '../../api/client';
import { FEATURE_ONBOARDING_WIZARD, OnboardingFrame, routeAfterOnboardingResponse, routeToOnboardingStep } from './onboardingUtils';

export function OrgPage() {
  const navigate = useNavigate();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [orgName, setOrgName] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!FEATURE_ONBOARDING_WIZARD) {
      return;
    }
    let mounted = true;
    const run = async () => {
      setLoading(true);
      setError('');
      try {
        const [started, current] = await Promise.all([
          apiClient.startOnboarding(),
          apiClient.getMe({ redirectOnUnauthorized: false })
        ]);
        if (!mounted) {
          return;
        }
        if (routeToOnboardingStep(navigate, started, '/onboarding/org', '/onboarding/org')) {
          return;
        }
        setState(started.state);
        const displayName = current.me.user.display_name || current.me.user.primary_email?.split('@')[0] || '';
        setOrgName(displayName ? `${displayName} Security` : 'Production Security');
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        setError(requestError instanceof Error ? requestError.message : 'Unable to start onboarding.');
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

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const name = orgName.trim();
    if (!name) {
      setError('Organization name is required.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'org',
        org_name: name
      });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/workspace');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to save organization.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <OnboardingFrame
      step="org"
      eyebrow="Account setup"
      title="Create your organization boundary"
      description="This becomes the tenant root for every workspace, connector, scan, policy, and teammate you add later."
      aside={
        <div className="idt-onboarding-assurance">
          <strong>Server-owned setup</strong>
          <span>Progress is stored in Identrail, so refreshes and second devices resume safely.</span>
        </div>
      }
    >
      {loading ? <p className="idt-muted-strong">Preparing your account...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <form className="idt-onboarding-form" onSubmit={submit}>
        <label htmlFor="org-name">Organization name</label>
        <input
          id="org-name"
          value={orgName}
          onChange={(event) => setOrgName(event.target.value)}
          placeholder="Acme Security"
          autoComplete="organization"
        />
        <div className="idt-onboarding-actions">
          <button type="submit" className="idt-btn idt-btn-primary" disabled={saving || loading || !orgName.trim()}>
            {saving ? 'Saving...' : state?.org_id ? 'Continue' : 'Create organization'}
          </button>
        </div>
      </form>
    </OnboardingFrame>
  );
}
