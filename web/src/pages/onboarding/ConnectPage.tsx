import { useEffect, useMemo, useRef, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { apiClient, type OnboardingState } from '../../api/client';
import { SkipForNow } from '../../components/onboarding/SkipForNow';
import { isFeatureAvailable, useBackendFeatures } from '../../hooks/useBackendFeatures';
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

const PROVIDER_META: Array<{
  id: OnboardingProvider;
  name: string;
  signal: string;
  detail: string;
  viteFlag: boolean;
}> = [
  {
    id: 'aws',
    name: 'AWS',
    signal: 'IAM roles, trust policies, account paths',
    detail: 'Best first source for cloud identity blast-radius discovery.',
    viteFlag: FEATURE_ONBOARDING_CONNECTOR_AWS
  },
  {
    id: 'kubernetes',
    name: 'Kubernetes',
    signal: 'Service accounts, RBAC, workload identity',
    detail: 'Use when cluster access and service account paths matter most.',
    viteFlag: FEATURE_ONBOARDING_CONNECTOR_K8S
  },
  {
    id: 'github',
    name: 'GitHub',
    signal: 'Repositories, workflow identity, webhook scans',
    detail: 'Use when code and OIDC workflow access are the first security boundary.',
    viteFlag: FEATURE_ONBOARDING_CONNECTOR_GITHUB
  }
];

export function ConnectPage() {
  const navigate = useNavigate();
  const { features } = useBackendFeatures();
  const providers = useMemo(
    () =>
      PROVIDER_META.map((meta) => ({
        ...meta,
        enabled: isFeatureAvailable(meta.viteFlag, features.connectors[meta.id])
      })),
    [features]
  );
  const enabledProviders = useMemo(() => providers.filter((provider) => provider.enabled), [providers]);
  const [state, setState] = useState<OnboardingState | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<OnboardingProvider>('aws');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const enabledProviderIdsRef = useRef<OnboardingProvider[]>([]);
  enabledProviderIdsRef.current = enabledProviders.map((provider) => provider.id);

  // Keep the selection on an actionable connector once API-discovered
  // availability resolves (the bundle may ship a connector the API lacks).
  useEffect(() => {
    if (enabledProviders.length && !enabledProviders.some((provider) => provider.id === selectedProvider)) {
      setSelectedProvider(enabledProviders[0].id);
    }
  }, [enabledProviders, selectedProvider]);

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
        if (nextState.connector_type && enabledProviderIdsRef.current.includes(nextState.connector_type)) {
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
  }, [navigate]);

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
        {providers.map((provider) => (
          <button
            type="button"
            key={provider.id}
            className={`idt-onboarding-provider ${selectedProvider === provider.id ? 'is-selected' : ''}`}
            disabled={!provider.enabled || saving || loading}
            onClick={() => setSelectedProvider(provider.id)}
          >
            <span>{provider.name}</span>
            <strong>{provider.signal}</strong>
            <small>
              {provider.enabled
                ? provider.detail
                : provider.viteFlag
                  ? 'Not available on this API server.'
                  : 'Not included in this web build.'}
            </small>
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
