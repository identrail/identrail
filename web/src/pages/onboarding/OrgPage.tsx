import { FormEvent, useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { apiClient } from '../../api/client';
import { FEATURE_ONBOARDING_WIZARD, OnboardingFrame, routeAfterOnboardingResponse, routeToOnboardingStep } from './onboardingUtils';

export function OrgPage() {
  const navigate = useNavigate();
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
      title="Name your organization"
      description="Identrail uses this as the secure home for your workspaces, sources, scans, and teammates."
      aside={
        <div className="idt-onboarding-assurance">
          <strong>Saved automatically</strong>
          <span>You can refresh or finish setup from another device without losing progress.</span>
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
            {saving ? 'Saving...' : 'Continue'}
          </button>
        </div>
      </form>
    </OnboardingFrame>
  );
}
