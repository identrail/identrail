import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BackendFeatureState } from '../../hooks/useBackendFeatures';

async function renderGuard(opts: {
  featureEnabled: boolean;
  loading: boolean;
  onboardingWizard?: BackendFeatureState;
}) {
  vi.resetModules();
  vi.doMock('../../pages/onboarding/onboardingUtils', () => ({
    FEATURE_ONBOARDING_WIZARD: opts.featureEnabled
  }));
  vi.doMock('../../hooks/useBackendFeatures', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../hooks/useBackendFeatures')>();
    return {
      ...actual,
      useBackendFeatures: () => ({
        features: {
          onboardingWizard: opts.onboardingWizard,
          connectors: { github: undefined, aws: undefined, kubernetes: undefined }
        },
        loading: opts.loading
      })
    };
  });

  const { RequireOnboardingBackend } = await import('./OnboardingAvailability');
  render(
    <RequireOnboardingBackend fallback={<h1>Fallback shown</h1>}>
      <h1>Onboarding page</h1>
    </RequireOnboardingBackend>
  );
}

describe('RequireOnboardingBackend', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.doUnmock('../../pages/onboarding/onboardingUtils');
    vi.doUnmock('../../hooks/useBackendFeatures');
    vi.resetModules();
  });

  it('returns the fallback immediately when the bundle disables onboarding, even while backend features load', async () => {
    await renderGuard({ featureEnabled: false, loading: true });

    expect(await screen.findByRole('heading', { name: 'Fallback shown' })).toBeInTheDocument();
    expect(screen.queryByText(/Checking onboarding availability/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Onboarding page' })).not.toBeInTheDocument();
  });

  it('shows the loading state while backend availability resolves when the bundle enables onboarding', async () => {
    await renderGuard({ featureEnabled: true, loading: true });

    expect(await screen.findByText(/Checking onboarding availability/i)).toBeInTheDocument();
  });

  it('renders the page when the bundle and API both enable onboarding', async () => {
    await renderGuard({ featureEnabled: true, loading: false, onboardingWizard: true });

    expect(await screen.findByRole('heading', { name: 'Onboarding page' })).toBeInTheDocument();
  });

  it('renders the fallback when the API does not serve onboarding', async () => {
    await renderGuard({ featureEnabled: true, loading: false, onboardingWizard: false });

    expect(await screen.findByRole('heading', { name: 'Fallback shown' })).toBeInTheDocument();
  });
});
