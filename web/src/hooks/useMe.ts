import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, apiClient, type CurrentUserContext } from '../api/client';

type UseMeState = {
  me: CurrentUserContext | null;
  loading: boolean;
  error: string;
  unauthenticated: boolean;
  refresh: (options?: { silent?: boolean }) => Promise<CurrentUserContext | null>;
};

let cachedMe: CurrentUserContext | null = null;
let cachedError = '';
let cachedUnauthenticated = false;
let meCacheVersion = 0;
const cacheListeners = new Set<() => void>();

function notifyMeCacheListeners() {
  cacheListeners.forEach((listener) => listener());
}

export function getCachedMe(): CurrentUserContext | null {
  return cachedMe;
}

export function primeMeCache(me: CurrentUserContext) {
  meCacheVersion += 1;
  cachedMe = me;
  cachedError = '';
  cachedUnauthenticated = false;
  notifyMeCacheListeners();
}

export function clearMeCache(options: { unauthenticated?: boolean } = {}) {
  meCacheVersion += 1;
  cachedMe = null;
  cachedError = '';
  cachedUnauthenticated = options.unauthenticated === true;
  notifyMeCacheListeners();
}

export function clearMeCacheForTests() {
  meCacheVersion += 1;
  cachedMe = null;
  cachedError = '';
  cachedUnauthenticated = false;
  notifyMeCacheListeners();
}

export function useMe(): UseMeState {
  const [me, setMe] = useState<CurrentUserContext | null>(() => cachedMe);
  const [loading, setLoading] = useState(() => !cachedMe && !cachedUnauthenticated && !cachedError);
  const [error, setError] = useState(() => cachedError);
  const [unauthenticated, setUnauthenticated] = useState(() => cachedUnauthenticated);
  const mountedRef = useRef(false);

  const refresh = useCallback(async (options: { silent?: boolean } = {}) => {
    const silent = options.silent === true;
    const hadCachedSession = Boolean(cachedMe);
    const requestCacheVersion = meCacheVersion;
    if (!silent) {
      setLoading(true);
    }
    setError('');
    setUnauthenticated(false);
    try {
      const response = await apiClient.getMe({ redirectOnUnauthorized: false });
      if (!mountedRef.current || requestCacheVersion !== meCacheVersion) {
        return cachedMe;
      }
      primeMeCache(response.me);
      setMe(response.me);
      return response.me;
    } catch (requestError) {
      if (!mountedRef.current || requestCacheVersion !== meCacheVersion) {
        return null;
      }
      if (requestError instanceof ApiError && requestError.status === 401) {
        clearMeCache({ unauthenticated: true });
        setMe(null);
        setUnauthenticated(true);
        return null;
      }
      const message = requestError instanceof Error ? requestError.message : 'Unable to load account session.';
      if (!silent || !hadCachedSession) {
        cachedMe = null;
        cachedError = message;
        cachedUnauthenticated = false;
        notifyMeCacheListeners();
        setMe(null);
        setError(message);
      }
      return null;
    } finally {
      if (mountedRef.current && requestCacheVersion === meCacheVersion) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const syncFromCache = () => {
      setMe(cachedMe);
      setError(cachedError);
      setUnauthenticated(cachedUnauthenticated);
      setLoading(false);
    };
    cacheListeners.add(syncFromCache);
    return () => {
      mountedRef.current = false;
      cacheListeners.delete(syncFromCache);
    };
  }, []);

  useEffect(() => {
    void refresh({ silent: Boolean(cachedMe) });
  }, [refresh]);

  return { me, loading, error, unauthenticated, refresh };
}
