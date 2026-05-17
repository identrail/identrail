import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CurrentUserContext } from './api/client';
import type { BackendFeatureState } from './hooks/useBackendFeatures';

const loggedInWithoutWorkspace: CurrentUserContext = {
  user: {
    id: 'user-1',
    primary_email: 'owner@example.com',
    display_name: 'Owner User',
    status: 'active',
    created_at: '2026-05-16T10:00:00Z',
    updated_at: '2026-05-16T10:00:00Z'
  }
};

async function renderProductIndexRedirect(featureEnabled: boolean, backendOnboarding: BackendFeatureState) {
  vi.resetModules();
  vi.doMock('./hooks/useMe', () => ({
    useMe: () => ({
      me: loggedInWithoutWorkspace,
      loading: false,
      error: '',
      unauthenticated: false,
      refresh: vi.fn()
    })
  }));
  vi.doMock('./pages/onboarding/onboardingUtils', () => ({
    FEATURE_ONBOARDING_WIZARD: featureEnabled
  }));
  vi.doMock('./hooks/useBackendFeatures', async (importOriginal) => {
    const actual = await importOriginal<typeof import('./hooks/useBackendFeatures')>();
    return {
      ...actual,
      useBackendFeatures: () => ({
        features: {
          onboardingWizard: backendOnboarding,
          connectors: { github: undefined, aws: undefined, kubernetes: undefined }
        },
        loading: false
      })
    };
  });

  const { ProductAppIndexRedirect } = await import('./productShell');

  render(
    <MemoryRouter initialEntries={['/app']}>
      <Routes>
        <Route path="/app" element={<ProductAppIndexRedirect />} />
        <Route path="/onboarding/org" element={<h1>Start onboarding</h1>} />
      </Routes>
    </MemoryRouter>
  );
}

describe('ProductAppIndexRedirect', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('./hooks/useMe');
    vi.doUnmock('./pages/onboarding/onboardingUtils');
    vi.doUnmock('./hooks/useBackendFeatures');
    vi.resetModules();
  });

  it('starts self-serve onboarding when the bundle and API both enable it', async () => {
    await renderProductIndexRedirect(true, true);

    expect(await screen.findByRole('heading', { level: 1, name: 'Start onboarding' })).toBeInTheDocument();
    expect(screen.queryByText(/No workspace is attached yet/i)).not.toBeInTheDocument();
  });

  it('falls back to the bundle flag when the API does not advertise onboarding', async () => {
    await renderProductIndexRedirect(true, undefined);

    expect(await screen.findByRole('heading', { level: 1, name: 'Start onboarding' })).toBeInTheDocument();
  });

  it('shows a clear unavailable state instead of a 404 when the API lacks onboarding', async () => {
    await renderProductIndexRedirect(true, false);

    expect(
      await screen.findByRole('heading', { level: 1, name: /Self-serve onboarding is not enabled on this API/i })
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Start onboarding' })).not.toBeInTheDocument();
  });

  it('keeps the explicit workspace-required state when the bundle disables onboarding', async () => {
    await renderProductIndexRedirect(false, undefined);

    expect(await screen.findByRole('heading', { level: 1, name: /No workspace is attached yet/i })).toBeInTheDocument();
  });
});
