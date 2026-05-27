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
        const started = await apiClient.startOnboarding();
        if (!mounted) {
          return;
        }
        if (routeToOnboardingStep(navigate, started, '/onboarding/org', '/onboarding/org')) {
          return;
        }
        setState(started.state);
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
      setError('Please enter an organization name to continue.');
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
      eyebrow="Secure onboarding"
      title="Set up your organization"
      description="Create one boundary for workspaces, sources, scans, findings, and access."
    >
      {loading ? <p className="idt-muted-strong">Preparing your account...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <form className="idt-onboarding-form" onSubmit={submit}>
        <div className="idt-onboarding-field">
          <label htmlFor="org-name">Organization name</label>
          <p id="org-name-hint">Use a recognizable company or program name.</p>
          <input
            id="org-name"
            value={orgName}
            onChange={(event) => setOrgName(event.target.value)}
            autoComplete="organization"
            aria-describedby="org-name-hint"
          />
        </div>
        <div className="idt-onboarding-actions">
          <button type="submit" className="idt-btn idt-btn-primary" disabled={saving || loading}>
            {saving ? 'Saving...' : state?.org_id ? 'Continue' : 'Create organization'}
          </button>
        </div>
      </form>
    </OnboardingFrame>
  );
}
