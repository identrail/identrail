import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';

// A tri-state per feature:
//   true      -> API explicitly advertises the backend route is registered
//   false     -> API explicitly advertises it is NOT registered
//   undefined -> API did not advertise availability (older API, or the
//                auth/config call failed) -> fall back to the Vite build flag
export type BackendFeatureState = boolean | undefined;

export type BackendFeatures = {
  onboardingWizard: BackendFeatureState;
  connectors: {
    github: BackendFeatureState;
    aws: BackendFeatureState;
    kubernetes: BackendFeatureState;
  };
};

const UNKNOWN_FEATURES: BackendFeatures = {
  onboardingWizard: undefined,
  connectors: { github: undefined, aws: undefined, kubernetes: undefined }
};

let cachedFeatures: Promise<BackendFeatures> | null = null;
// Synchronous snapshot once the one-shot fetch has resolved. This keeps
// remounts (e.g. navigating between onboarding steps, each wrapped by the
// route guard) from flashing a loading interstitial.
let resolvedFeatures: BackendFeatures | null = null;

async function fetchBackendFeatures(): Promise<BackendFeatures> {
  try {
    const config = await apiClient.getAuthConfig();
    const features = config.features;
    if (!features) {
      // Older API that predates this contract: stay on the Vite-flag
      // behavior. The production API preflight is the deploy-time guard
      // against an API that does not serve a backend-gated flow.
      return UNKNOWN_FEATURES;
    }
    return {
      onboardingWizard: features.onboarding_wizard,
      connectors: {
        github: features.connectors?.github,
        aws: features.connectors?.aws,
        kubernetes: features.connectors?.kubernetes
      }
    };
  } catch {
    // A failed auth/config call must not be more disruptive than today's
    // Vite-only behavior, so degrade to "unknown" rather than blocking.
    return UNKNOWN_FEATURES;
  }
}

export function loadBackendFeatures(): Promise<BackendFeatures> {
  if (!cachedFeatures) {
    cachedFeatures = fetchBackendFeatures().then((resolved) => {
      resolvedFeatures = resolved;
      return resolved;
    });
  }
  return cachedFeatures;
}

export function resetBackendFeaturesCacheForTests(): void {
  cachedFeatures = null;
  resolvedFeatures = null;
}

// The effective rule: a backend-dependent flow is shown only when the web
// bundle ships its UI (Vite flag) AND the API does not explicitly say the
// route is missing. Unknown backend state keeps the legacy Vite-only result.
export function isFeatureAvailable(viteFlag: boolean, backendState: BackendFeatureState): boolean {
  if (backendState === undefined) {
    return viteFlag;
  }
  return viteFlag && backendState;
}

type UseBackendFeaturesResult = {
  features: BackendFeatures;
  loading: boolean;
};

export function useBackendFeatures(): UseBackendFeaturesResult {
  const [features, setFeatures] = useState<BackendFeatures>(resolvedFeatures ?? UNKNOWN_FEATURES);
  const [loading, setLoading] = useState(resolvedFeatures === null);

  useEffect(() => {
    if (resolvedFeatures) {
      // Cache is already warm: serve it without a loading flash on remount.
      setFeatures(resolvedFeatures);
      setLoading(false);
      return;
    }
    let mounted = true;
    setLoading(true);
    loadBackendFeatures()
      .then((resolved) => {
        if (mounted) {
          setFeatures(resolved);
        }
      })
      .finally(() => {
        if (mounted) {
          setLoading(false);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  return { features, loading };
}
