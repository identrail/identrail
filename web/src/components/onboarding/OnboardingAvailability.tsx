import { ReactElement, ReactNode } from 'react';
import { FEATURE_ONBOARDING_WIZARD } from '../../pages/onboarding/onboardingUtils';
import { isFeatureAvailable, useBackendFeatures } from '../../hooks/useBackendFeatures';

// Whether self-serve onboarding should be shown: the web bundle must ship the
// wizard (Vite flag) AND the API must not explicitly report the onboarding
// route as missing. Returns undefined while backend availability is loading.
export function useOnboardingAvailable(): boolean | undefined {
  const { features, loading } = useBackendFeatures();
  if (!FEATURE_ONBOARDING_WIZARD) {
    // The bundle does not ship the wizard, so onboarding can never be shown
    // regardless of the API. Decide immediately instead of stranding a direct
    // /onboarding/* visit on a loading panel while auth/config settles.
    return false;
  }
  if (loading) {
    return undefined;
  }
  return isFeatureAvailable(FEATURE_ONBOARDING_WIZARD, features.onboardingWizard);
}

export function OnboardingFeatureLoading() {
  return (
    <section className="idt-app-shell-screen" aria-live="polite">
      <article className="idt-app-panel">
        <p className="idt-app-kicker">Loading</p>
        <h1>Checking onboarding availability</h1>
        <p>Confirming the API supports self-serve onboarding before continuing.</p>
      </article>
    </section>
  );
}

// Shown when the web bundle supports onboarding but the API does not register
// the onboarding routes. This replaces a raw "Request failed (404)" with a
// clear, user-safe explanation and a path forward.
export function OnboardingUnavailableNotice() {
  return (
    <section className="idt-app-shell-screen" role="alert">
      <article className="idt-app-panel">
        <p className="idt-app-kicker">Onboarding unavailable</p>
        <h1>Self-serve onboarding is not enabled on this API</h1>
        <p>
          Your account is active, but this Identrail API does not have the self-serve onboarding routes enabled, so the
          setup wizard cannot run here. Ask an administrator to assign your workspace, or enable onboarding on the API.
        </p>
      </article>
    </section>
  );
}

// Route guard for onboarding pages. While backend availability is loading it
// shows a neutral state; if onboarding is unavailable it renders the supplied
// fallback (kept generic so it does not import the product shell and create a
// cycle) instead of letting the page call a 404 backend route.
export function RequireOnboardingBackend({
  fallback,
  children
}: {
  fallback: ReactElement;
  children: ReactNode;
}) {
  const available = useOnboardingAvailable();
  if (available === undefined) {
    return <OnboardingFeatureLoading />;
  }
  if (!available) {
    return fallback;
  }
  return <>{children}</>;
}
