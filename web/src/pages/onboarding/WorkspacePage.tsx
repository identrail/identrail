import { FormEvent, useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { apiClient, type OnboardingState } from '../../api/client';
import { EnterSubmitHint } from '../../components/common/EnterSubmitHint';
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
  const [workspaceName, setWorkspaceName] = useState('');
  const [projectName, setProjectName] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [workspaceNameError, setWorkspaceNameError] = useState('');
  const [projectNameError, setProjectNameError] = useState('');

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
    setError('');
    setWorkspaceNameError('');
    setProjectNameError('');
    if (!workspaceName.trim()) {
      setWorkspaceNameError('Enter a workspace name');
      return;
    }
    if (!projectName.trim()) {
      setProjectNameError('Enter a project name');
      return;
    }
    setSaving(true);
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'workspace',
        workspace_name: workspaceName.trim(),
        project_name: projectName.trim()
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
      title="Name workspace"
    >
      {loading ? <p className="idt-muted-strong">Loading workspace setup...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <form className="idt-onboarding-form" onSubmit={submit}>
        <div className="idt-onboarding-field">
          <label htmlFor="workspace-name">Workspace name</label>
          <div className={workspaceNameError ? 'idt-onboarding-input-wrap has-error' : 'idt-onboarding-input-wrap'}>
            <input
              id="workspace-name"
              value={workspaceName}
              onChange={(event) => {
                setWorkspaceName(event.target.value);
                if (workspaceNameError) {
                  setWorkspaceNameError('');
                }
              }}
              autoComplete="off"
              aria-invalid={workspaceNameError ? 'true' : undefined}
              aria-describedby={workspaceNameError ? 'workspace-name-error' : undefined}
            />
            {workspaceNameError ? (
              <span id="workspace-name-error" className="idt-onboarding-input-error" role="alert">
                {workspaceNameError}
              </span>
            ) : null}
          </div>
        </div>
        <div className="idt-onboarding-field">
          <label htmlFor="project-name">Project name</label>
          <div className={projectNameError ? 'idt-onboarding-input-wrap has-error' : 'idt-onboarding-input-wrap'}>
            <input
              id="project-name"
              value={projectName}
              onChange={(event) => {
                setProjectName(event.target.value);
                if (projectNameError) {
                  setProjectNameError('');
                }
              }}
              autoComplete="off"
              aria-invalid={projectNameError ? 'true' : undefined}
              aria-describedby={projectNameError ? 'project-name-error' : undefined}
            />
            {projectNameError ? (
              <span id="project-name-error" className="idt-onboarding-input-error" role="alert">
                {projectNameError}
              </span>
            ) : null}
          </div>
        </div>
        <div className="idt-onboarding-actions">
          <button type="submit" className="idt-btn idt-btn-primary" disabled={saving || loading}>
            {saving ? (
              'Creating...'
            ) : (
              <>
                {state?.workspace_id ? 'Continue' : 'Create workspace'}
                <EnterSubmitHint />
              </>
            )}
          </button>
        </div>
      </form>
    </OnboardingFrame>
  );
}
