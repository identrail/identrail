import { FormEvent, useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { apiClient, type OnboardingState } from '../../api/client';
import {
  FEATURE_ONBOARDING_WIZARD,
  OnboardingFrame,
  loadOrStartOnboardingResponse,
  routeAfterOnboardingResponse,
  routeToOnboardingStep
} from './onboardingUtils';

export function WorkspacePage() {
  const navigate = useNavigate();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [workspaceName, setWorkspaceName] = useState('Production');
  const [projectName, setProjectName] = useState('Production');
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
        const response = await loadOrStartOnboardingResponse();
        const nextState = response.state;
        if (!mounted) {
          return;
        }
        setState(nextState);
        if (!nextState.org_id) {
          navigate('/onboarding/org', { replace: true });
          return;
        }
        if (routeToOnboardingStep(navigate, response, '/onboarding/workspace', '/onboarding/workspace')) {
          return;
        }
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        setError(requestError instanceof Error ? requestError.message : 'Unable to load onboarding.');
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
    if (!workspaceName.trim()) {
      setError('Workspace name is required.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'workspace',
        workspace_name: workspaceName.trim(),
        project_name: projectName.trim() || workspaceName.trim()
      });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/connect');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to save workspace.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <OnboardingFrame
      step="workspace"
      eyebrow="Workspace"
      title="Name the environment you will secure first"
      description="A workspace keeps scans, connectors, projects, members, and findings inside one operating boundary."
      aside={
        <div className="idt-onboarding-assurance">
          <strong>Default project included</strong>
          <span>Identrail creates the first project automatically so connector setup has a safe scope immediately.</span>
        </div>
      }
    >
      {loading ? <p className="idt-muted-strong">Loading workspace setup...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <form className="idt-onboarding-form" onSubmit={submit}>
        <label htmlFor="workspace-name">Workspace name</label>
        <input
          id="workspace-name"
          value={workspaceName}
          onChange={(event) => setWorkspaceName(event.target.value)}
          placeholder="Production"
          autoComplete="off"
        />
        <label htmlFor="project-name">First project</label>
        <input
          id="project-name"
          value={projectName}
          onChange={(event) => setProjectName(event.target.value)}
          placeholder="Production"
          autoComplete="off"
        />
        <div className="idt-onboarding-actions">
          <button type="submit" className="idt-btn idt-btn-primary" disabled={saving || loading || !workspaceName.trim()}>
            {saving ? 'Creating...' : state?.workspace_id ? 'Continue' : 'Create workspace'}
          </button>
        </div>
      </form>
    </OnboardingFrame>
  );
}
