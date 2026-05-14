import { useEffect, useMemo, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { apiClient, type OnboardingState } from '../../api/client';
import { SkipForNow } from '../../components/onboarding/SkipForNow';
import {
  FEATURE_ONBOARDING_CONNECTOR_AWS,
  FEATURE_ONBOARDING_CONNECTOR_GITHUB,
  FEATURE_ONBOARDING_CONNECTOR_K8S,
  FEATURE_ONBOARDING_WIZARD,
  OnboardingFrame,
  loadOrStartOnboardingResponse,
  onboardingProjectPath,
  routeAfterOnboardingResponse,
  routeToOnboardingStep,
  type OnboardingProvider
} from './onboardingUtils';

const PROVIDERS: Array<{
  id: OnboardingProvider;
  name: string;
  signal: string;
  detail: string;
  enabled: boolean;
}> = [
  {
    id: 'aws',
    name: 'AWS',
    signal: 'IAM roles, trust policies, account paths',
    detail: 'Best first source for cloud identity blast-radius discovery.',
    enabled: FEATURE_ONBOARDING_CONNECTOR_AWS
  },
  {
    id: 'kubernetes',
    name: 'Kubernetes',
    signal: 'Service accounts, RBAC, workload identity',
    detail: 'Use when cluster access and service account paths matter most.',
    enabled: FEATURE_ONBOARDING_CONNECTOR_K8S
  },
  {
    id: 'github',
    name: 'GitHub',
    signal: 'Repositories, workflow identity, webhook scans',
    detail: 'Use when code and OIDC workflow access are the first security boundary.',
    enabled: FEATURE_ONBOARDING_CONNECTOR_GITHUB
  }
];

export function ConnectPage() {
  const navigate = useNavigate();
  const enabledProviders = useMemo(() => PROVIDERS.filter((provider) => provider.enabled), []);
  const [state, setState] = useState<OnboardingState | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<OnboardingProvider>(enabledProviders[0]?.id ?? 'aws');
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
        if (!nextState.org_id || !nextState.workspace_id || !nextState.project_id) {
          navigate('/onboarding/workspace', { replace: true });
          return;
        }
        if (routeToOnboardingStep(navigate, response, '/onboarding/connect', '/onboarding/connect')) {
          return;
        }
        if (nextState.connector_type && enabledProviders.some((provider) => provider.id === nextState.connector_type)) {
          setSelectedProvider(nextState.connector_type);
        }
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        setError(requestError instanceof Error ? requestError.message : 'Unable to load connector setup.');
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
  }, [enabledProviders, navigate]);

  if (!FEATURE_ONBOARDING_WIZARD) {
    return <Navigate to="/app" replace />;
  }

  const continueToScan = async () => {
    if (!enabledProviders.length) {
      return skipConnector();
    }
    setSaving(true);
    setError('');
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'connect',
        connector_type: selectedProvider,
        connector_skipped: false
      });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/scan');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to save connector choice.');
    } finally {
      setSaving(false);
    }
  };

  const openConnectorSetup = async () => {
    if (!enabledProviders.length) {
      return;
    }
    setSaving(true);
    setError('');
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'connect',
        connector_type: selectedProvider,
        connector_skipped: false
      });
      setState(response.state);
      navigate(onboardingProjectPath(response.state));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to open connector setup.');
    } finally {
      setSaving(false);
    }
  };

  const skipConnector = async () => {
    setSaving(true);
    setError('');
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'connect',
        connector_skipped: true
      });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/scan');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to skip connector setup.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <OnboardingFrame
      step="connect"
      eyebrow="Connect source"
      title="Choose the first identity source"
      description="Start with one read-only source. You can add the rest after the first scan proves the workflow."
      aside={
        <div className="idt-onboarding-assurance">
          <strong>Least privilege first</strong>
          <span>Connector setup uses the same project-scoped AWS, Kubernetes, and GitHub flows already reviewed in the product.</span>
        </div>
      }
    >
      {loading ? <p className="idt-muted-strong">Checking available connectors...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <div className="idt-onboarding-provider-grid">
        {PROVIDERS.map((provider) => (
          <button
            type="button"
            key={provider.id}
            className={`idt-onboarding-provider ${selectedProvider === provider.id ? 'is-selected' : ''}`}
            disabled={!provider.enabled || saving || loading}
            onClick={() => setSelectedProvider(provider.id)}
          >
            <span>{provider.name}</span>
            <strong>{provider.signal}</strong>
            <small>{provider.enabled ? provider.detail : 'Enable the connector feature flag to use this source.'}</small>
          </button>
        ))}
      </div>
      <div className="idt-onboarding-actions">
        <button type="button" className="idt-btn idt-btn-primary" disabled={saving || loading || !enabledProviders.length} onClick={continueToScan}>
          {saving ? 'Saving...' : 'Continue'}
        </button>
        <button type="button" className="idt-btn idt-btn-secondary" disabled={saving || loading || !enabledProviders.length} onClick={openConnectorSetup}>
          Open setup
        </button>
        <SkipForNow disabled={saving || loading} onSkip={skipConnector} />
      </div>
      {state?.project_id ? (
        <p className="idt-muted-strong">Setup target: {state.workspace_id}/{state.project_id}</p>
      ) : null}
    </OnboardingFrame>
  );
}
