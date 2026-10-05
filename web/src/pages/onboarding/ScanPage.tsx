import { useEffect, useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router';
import { ApiError, apiClient, type OnboardingState, type ScanRecord, type ScanRequest } from '../../api/client';
import { EnterSubmitHint } from '../../components/common/EnterSubmitHint';
import { SkipForNow } from '../../components/onboarding/SkipForNow';
import {
  FEATURE_ONBOARDING_WIZARD,
  OnboardingFrame,
  loadOrStartOnboardingResponse,
  onboardingAuth,
  routeAfterOnboardingResponse,
  routeToOnboardingStep
} from './onboardingUtils';

function isAccessDenied(error: unknown): boolean {
  return (
    (error instanceof ApiError && error.status === 403) ||
    (error instanceof Error && error.message.trim().toLowerCase() === 'forbidden')
  );
}

function scanErrorMessage(error: unknown, fallback: string): string {
  if (isAccessDenied(error)) {
    return 'This session can’t access scans in the selected workspace. Sign out and sign in again to check this account’s status, or ask a workspace owner to restore access.';
  }
  return error instanceof Error && error.message ? error.message : fallback;
}

function actionErrorMessage(error: unknown, fallback: string, deniedMessage: string): string {
  if (isAccessDenied(error)) {
    return deniedMessage;
  }
  return error instanceof Error && error.message ? error.message : fallback;
}

export function ScanPage() {
  const navigate = useNavigate();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [startingScan, setStartingScan] = useState(false);
  const [error, setError] = useState('');
  const [accessDenied, setAccessDenied] = useState(false);
  const [scanStatusLoaded, setScanStatusLoaded] = useState(false);
  const [scanRunDenied, setScanRunDenied] = useState(false);

  useEffect(() => {
    if (!FEATURE_ONBOARDING_WIZARD) {
      return;
    }
    let mounted = true;
    const run = async () => {
      setLoading(true);
      setError('');
      setAccessDenied(false);
      setScanStatusLoaded(false);
      setScanRunDenied(false);
      setScan(null);
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
        setScanStatusLoaded(true);
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        setAccessDenied(isAccessDenied(requestError));
        setError(scanErrorMessage(requestError, 'Unable to load scan status.'));
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
    setAccessDenied(false);
    try {
      const request: ScanRequest = {};
      if (state.project_id) {
        request.project_id = state.project_id;
      }
      if (state.connector_type === 'aws' && state.connector_id) {
        request.connector_id = state.connector_id;
      }
      const auth = onboardingAuth(state);
      const response = request.project_id || request.connector_id ? await apiClient.startScan(request, auth) : await apiClient.startScan(auth);
      setScan(response.scan);
      setScanRunDenied(false);
    } catch (requestError) {
      const denied = isAccessDenied(requestError);
      if (denied) {
        setScanRunDenied(true);
      }
      setError(actionErrorMessage(
        requestError,
        'Unable to start the first scan.',
        'You can still view existing scans, but this workspace denied the request to start one. Ask a workspace owner to review scan permissions.'
      ));
    } finally {
      setStartingScan(false);
    }
  };

  const continueToInvite = async () => {
    setSaving(true);
    setError('');
    setAccessDenied(false);
    try {
      const response = await apiClient.updateOnboardingState({ current_step: 'scan' });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/invite');
    } catch (requestError) {
      setError(actionErrorMessage(
        requestError,
        'Unable to save scan progress.',
        'This workspace denied the request to update onboarding. Ask a workspace owner to review your access.'
      ));
    } finally {
      setSaving(false);
    }
  };

  const skipScan = async () => {
    setSaving(true);
    setError('');
    setAccessDenied(false);
    try {
      const response = await apiClient.updateOnboardingState({
        current_step: 'scan',
        scan_skipped: true
      });
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/onboarding/invite');
    } catch (requestError) {
      setError(actionErrorMessage(
        requestError,
        'Unable to skip scan.',
        'This workspace denied the request to update onboarding. Ask a workspace owner to review your access.'
      ));
    } finally {
      setSaving(false);
    }
  };

  const canSkip = Boolean(state?.connector_skipped);
  const canContinue = scanStatusLoaded && (canSkip || Boolean(scan));

  return (
    <OnboardingFrame
      step="scan"
      title="Run scan"
    >
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
          {accessDenied ? (
            <>
              {' '}
              <Link to="/app/logout">Sign out and check account</Link>.
            </>
          ) : null}
        </div>
      ) : null}
      <div className="idt-onboarding-scan-status" aria-live="polite">
        {scanStatusLoaded ? (
          <>
            <span>{scan?.status ?? (canSkip ? 'Connector skipped' : 'Ready')}</span>
            <strong>{scan ? `${scan.finding_count} findings` : 'No scan started yet'}</strong>
            <small>{scan ? `Provider: ${scan.provider}` : 'Start a scan after connector setup, or skip only when no connector was added.'}</small>
          </>
        ) : (
          <>
            <span>{loading ? 'Checking access' : accessDenied ? 'Access denied' : 'Unavailable'}</span>
            <strong>{loading ? 'Loading scan status...' : 'Scan status unavailable'}</strong>
            <small>{loading ? 'Verifying workspace access.' : 'Scan actions stay disabled until access is confirmed.'}</small>
          </>
        )}
      </div>
      <div className="idt-onboarding-actions">
        {!canSkip ? (
          <button
            type="button"
            className="idt-btn idt-btn-primary"
            disabled={startingScan || saving || loading || !state || !scanStatusLoaded || scanRunDenied}
            onClick={startScan}
          >
            {startingScan ? 'Starting...' : scan ? 'Start another scan' : 'Start first scan'}
          </button>
        ) : null}
        <button type="button" className="idt-btn idt-btn-secondary" disabled={saving || loading || !canContinue} onClick={continueToInvite}>
          Continue
          <EnterSubmitHint />
        </button>
        {canSkip ? <SkipForNow disabled={saving || loading || !scanStatusLoaded} onSkip={skipScan} label="Skip scan" /> : null}
      </div>
    </OnboardingFrame>
  );
}
