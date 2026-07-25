import { useEffect, useMemo, useRef, useState } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { apiClient } from '../../api/client';
import { EnterSubmitHint } from '../../components/common/EnterSubmitHint';
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
    signal: 'IAM roles and trust policies',
    detail: 'Best for cloud identity paths.',
    viteFlag: FEATURE_ONBOARDING_CONNECTOR_AWS
  },
  {
    id: 'kubernetes',
    name: 'Kubernetes',
    signal: 'Service accounts and RBAC',
    detail: 'Best for workload identity.',
    viteFlag: FEATURE_ONBOARDING_CONNECTOR_K8S
  },
  {
    id: 'github',
    name: 'GitHub',
    signal: 'Repos and workflow identity',
    detail: 'Best for code-to-cloud paths.',
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
  const [selectedProvider, setSelectedProvider] = useState<OnboardingProvider | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [providerError, setProviderError] = useState('');

  const enabledProviderIdsRef = useRef<OnboardingProvider[]>([]);
  enabledProviderIdsRef.current = enabledProviders.map((provider) => provider.id);

  useEffect(() => {
    if (selectedProvider && !enabledProviders.some((provider) => provider.id === selectedProvider)) {
      setSelectedProvider(null);
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
    setError('');
    setProviderError('');
    if (!enabledProviders.length) {
      setError('No sources are available. Skip for now to continue.');
      return;
    }
    const provider = selectedProvider;
    if (!provider || !enabledProviders.some((enabledProvider) => enabledProvider.id === provider)) {
      setProviderError('Choose a source');
      return;
    }
    setSaving(true);
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'connect',
        connector_type: provider,
        connector_skipped: false
      });
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/scan');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to save connector choice.');
    } finally {
      setSaving(false);
    }
  };

  const openConnectorSetup = async () => {
    setError('');
    setProviderError('');
    if (!enabledProviders.length) {
      setError('No sources are available. Skip for now to continue.');
      return;
    }
    const provider = selectedProvider;
    if (!provider || !enabledProviders.some((enabledProvider) => enabledProvider.id === provider)) {
      setProviderError('Choose a source');
      return;
    }
    setSaving(true);
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'connect',
        connector_type: provider,
        connector_skipped: false
      });
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
    setProviderError('');
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'connect',
        connector_skipped: true
      });
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
      title="Connect source"
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
            onClick={() => {
              setSelectedProvider(provider.id);
              if (providerError) {
                setProviderError('');
              }
            }}
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
      {providerError ? (
        <p className="idt-onboarding-inline-error" role="alert">
          {providerError}
        </p>
      ) : null}
      <div className="idt-onboarding-actions">
        <button type="button" className="idt-btn idt-btn-primary" disabled={saving || loading} onClick={continueToScan}>
          {saving ? (
            'Saving...'
          ) : (
            <>
              Continue
              <EnterSubmitHint />
            </>
          )}
        </button>
        <button type="button" className="idt-btn idt-btn-secondary" disabled={saving || loading} onClick={openConnectorSetup}>
          Open setup
        </button>
        <SkipForNow disabled={saving || loading} onSkip={skipConnector} />
      </div>
    </OnboardingFrame>
  );
}
