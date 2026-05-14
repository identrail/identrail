import { useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { apiClient, type OnboardingState, type ScanRecord } from '../../api/client';
import { SkipForNow } from '../../components/onboarding/SkipForNow';
import {
  FEATURE_ONBOARDING_WIZARD,
  OnboardingFrame,
  loadOrStartOnboardingResponse,
  onboardingAuth,
  routeAfterOnboardingResponse,
  routeToOnboardingStep
} from './onboardingUtils';

export function ScanPage() {
  const navigate = useNavigate();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [startingScan, setStartingScan] = useState(false);
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
        if (!nextState.org_id || !nextState.workspace_id) {
          navigate('/onboarding/workspace', { replace: true });
          return;
        }
        if (routeToOnboardingStep(navigate, response, '/onboarding/scan', '/onboarding/scan')) {
          return;
        }
        const scans = await apiClient.listScans(onboardingAuth(nextState));
        if (!mounted) {
          return;
        }
        setScan(scans.items[0] ?? null);
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        setError(requestError instanceof Error ? requestError.message : 'Unable to load scan state.');
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

  const startScan = async () => {
    if (!state) {
      return;
    }
    setStartingScan(true);
    setError('');
    try {
      const response = await apiClient.startScan(onboardingAuth(state));
      setScan(response.scan);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to start the first scan.');
    } finally {
      setStartingScan(false);
    }
  };

  const continueToInvite = async () => {
    setSaving(true);
    setError('');
    try {
      const response = await apiClient.updateOnboardingState({ current_step: 'scan' });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/invite');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to save scan progress.');
    } finally {
      setSaving(false);
    }
  };

  const skipScan = async () => {
    setSaving(true);
    setError('');
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'scan',
        scan_skipped: true
      });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/invite');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to skip scan.');
    } finally {
      setSaving(false);
    }
  };

  const canSkip = Boolean(state?.connector_skipped);
  const canContinue = canSkip || Boolean(scan);

  return (
    <OnboardingFrame
      step="scan"
      eyebrow="First scan"
      title="Run the first identity scan"
      description="The first scan proves that the workspace, connector boundary, queue, and findings path are connected end to end."
      aside={
        <div className="idt-onboarding-assurance">
          <strong>Queue backed</strong>
          <span>Scan creation uses the same authenticated scan endpoint as the dashboard and API clients.</span>
        </div>
      }
    >
      {loading ? <p className="idt-muted-strong">Loading scan readiness...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <div className="idt-onboarding-scan-status" aria-live="polite">
        <span>{scan?.status ?? (canSkip ? 'Connector skipped' : 'Ready')}</span>
        <strong>{scan ? `${scan.finding_count} findings` : 'No scan started yet'}</strong>
        <small>{scan ? `Provider: ${scan.provider}` : 'Start a scan after connector setup, or skip only when no connector was added.'}</small>
      </div>
      <div className="idt-onboarding-actions">
        {!canSkip ? (
          <button type="button" className="idt-btn idt-btn-primary" disabled={startingScan || saving || loading} onClick={startScan}>
            {startingScan ? 'Starting...' : scan ? 'Start another scan' : 'Start first scan'}
          </button>
        ) : null}
        <button type="button" className="idt-btn idt-btn-secondary" disabled={saving || loading || !canContinue} onClick={continueToInvite}>
          Continue
        </button>
        {canSkip ? <SkipForNow disabled={saving || loading} onSkip={skipScan} label="Skip scan" /> : null}
      </div>
    </OnboardingFrame>
  );
}
