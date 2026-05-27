import { apiClient, type AuthConfigResponse } from './api/client';

let cachedAuthConfig: AuthConfigResponse | null = null;
let pendingAuthConfig: Promise<AuthConfigResponse> | null = null;
let authConfigCacheVersion = 0;

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
  const requestCacheVersion = authConfigCacheVersion;
  pendingAuthConfig = apiClient
    .getAuthConfig()
    .then((response) => {
      if (requestCacheVersion === authConfigCacheVersion) {
        cachedAuthConfig = response;
      }
      return response;
    })
    .finally(() => {
      if (requestCacheVersion === authConfigCacheVersion) {
        pendingAuthConfig = null;
      }
    });
  return pendingAuthConfig;
}

export function preloadAuthConfig() {
  void loadAuthConfig().catch(() => {
    // Prefetch failures are surfaced when the auth page explicitly loads.
  });
}

export function clearAuthConfigCacheForTests() {
  authConfigCacheVersion += 1;
  cachedAuthConfig = null;
  pendingAuthConfig = null;
}
