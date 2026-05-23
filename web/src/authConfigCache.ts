import { apiClient, type AuthConfigResponse } from './api/client';

let cachedAuthConfig: AuthConfigResponse | null = null;
let pendingAuthConfig: Promise<AuthConfigResponse> | null = null;

export function getCachedAuthConfig(): AuthConfigResponse | null {
  return cachedAuthConfig;
}

export function loadAuthConfig(): Promise<AuthConfigResponse> {
  if (cachedAuthConfig) {
    return Promise.resolve(cachedAuthConfig);
  }
  if (pendingAuthConfig) {
    return pendingAuthConfig;
  }
  pendingAuthConfig = apiClient
    .getAuthConfig()
    .then((response) => {
      cachedAuthConfig = response;
      return response;
    })
    .finally(() => {
      pendingAuthConfig = null;
    });
  return pendingAuthConfig;
}

export function preloadAuthConfig() {
  void loadAuthConfig().catch(() => {
    // Prefetch failures are surfaced when the auth page explicitly loads.
  });
}

export function clearAuthConfigCacheForTests() {
  cachedAuthConfig = null;
  pendingAuthConfig = null;
}
