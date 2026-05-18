import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient, type AuthConfigResponse } from '../api/client';
import {
  isFeatureAvailable,
  loadBackendFeatures,
  resetBackendFeaturesCacheForTests
} from './useBackendFeatures';

const baseAuth: AuthConfigResponse['auth'] = {
  manual_mode: false,
  workos_login_enabled: true,
  native_saml_enabled: false,
  providers: ['github_oauth']
};

afterEach(() => {
  resetBackendFeaturesCacheForTests();
  vi.restoreAllMocks();
});

describe('isFeatureAvailable', () => {
  it('keeps the Vite flag result when the API does not advertise the feature', () => {
    expect(isFeatureAvailable(true, undefined)).toBe(true);
    expect(isFeatureAvailable(false, undefined)).toBe(false);
  });

  it('requires both the bundle flag and the API to agree when the API advertises it', () => {
    expect(isFeatureAvailable(true, true)).toBe(true);
    expect(isFeatureAvailable(true, false)).toBe(false);
    expect(isFeatureAvailable(false, true)).toBe(false);
  });
});

describe('loadBackendFeatures', () => {
  it('maps the API features object', async () => {
    vi.spyOn(apiClient, 'getAuthConfig').mockResolvedValue({
      auth: baseAuth,
      features: {
        onboarding_wizard: true,
        connectors: { github: false, aws: true, kubernetes: false }
      }
    });

    const features = await loadBackendFeatures();
    expect(features.onboardingWizard).toBe(true);
    expect(features.connectors).toEqual({ github: false, aws: true, kubernetes: false });
    expect(features.configReachable).toBe(true);
  });

  it('treats a missing features object as unknown (legacy API)', async () => {
    vi.spyOn(apiClient, 'getAuthConfig').mockResolvedValue({ auth: baseAuth });

    const features = await loadBackendFeatures();
    expect(features.onboardingWizard).toBeUndefined();
    expect(features.connectors).toEqual({ github: undefined, aws: undefined, kubernetes: undefined });
    // A reachable API that simply omits feature metadata still counts as
    // reachable, so onboarding callers fail closed rather than falling back.
    expect(features.configReachable).toBe(true);
  });

  it('degrades to unknown rather than throwing when auth/config fails', async () => {
    vi.spyOn(apiClient, 'getAuthConfig').mockRejectedValue(new Error('network down'));

    const features = await loadBackendFeatures();
    expect(features.onboardingWizard).toBeUndefined();
    // A transient fetch failure is distinguishable from missing metadata so
    // onboarding callers can preserve the Vite-only fallback.
    expect(features.configReachable).toBe(false);
  });

  it('memoizes a single auth/config call across callers', async () => {
    const spy = vi.spyOn(apiClient, 'getAuthConfig').mockResolvedValue({ auth: baseAuth });

    await Promise.all([loadBackendFeatures(), loadBackendFeatures()]);
    await loadBackendFeatures();

    expect(spy).toHaveBeenCalledTimes(1);
  });
});
