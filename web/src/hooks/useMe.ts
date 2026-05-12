import { useCallback, useEffect, useState } from 'react';
import { ApiError, apiClient, type CurrentUserContext } from '../api/client';

type UseMeState = {
  me: CurrentUserContext | null;
  loading: boolean;
  error: string;
  unauthenticated: boolean;
  refresh: () => Promise<CurrentUserContext | null>;
};

export function useMe(): UseMeState {
  const [me, setMe] = useState<CurrentUserContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [unauthenticated, setUnauthenticated] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    setUnauthenticated(false);
    try {
      const response = await apiClient.getMe({ redirectOnUnauthorized: false });
      setMe(response.me);
      return response.me;
    } catch (requestError) {
      setMe(null);
      if (requestError instanceof ApiError && requestError.status === 401) {
        setUnauthenticated(true);
        return null;
      }
      const message = requestError instanceof Error ? requestError.message : 'Unable to load account session.';
      setError(message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { me, loading, error, unauthenticated, refresh };
}
