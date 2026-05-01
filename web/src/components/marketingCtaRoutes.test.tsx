import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { siteLinks } from '../siteConfig';
import { CtaBannerSection } from './CtaBannerSection';
import { HeroSection } from './HeroSection';
import { IntegrationsCtaSection } from './IntegrationsCtaSection';
import { MarketingHero } from './MarketingHero';
import { Header } from './layout/Header';

describe('marketing CTA routing', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network disabled in unit test')));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('routes product-access CTAs to the canonical /app entry point', () => {
    render(
      <>
        <MarketingHero />
        <HeroSection />
        <CtaBannerSection />
        <IntegrationsCtaSection />
      </>
    );

    expect(siteLinks.getStarted).toBe('/app');

    const openAppLinks = screen.getAllByRole('link', { name: 'Open App' });
    expect(openAppLinks).toHaveLength(4);
    for (const link of openAppLinks) {
      expect(link).toHaveAttribute('href', siteLinks.getStarted);
    }
  });

  it('preserves docs and GitHub intent links while switching app-entry CTAs', () => {
    render(<HeroSection />);

    expect(screen.getByRole('link', { name: 'Star on GitHub' })).toHaveAttribute('href', siteLinks.starOnGithub);
    expect(screen.getByRole('link', { name: /Self-host with Docker/i })).toHaveAttribute('href', siteLinks.quickstartDocker);
    expect(screen.getByRole('link', { name: /Read the Docs/i })).toHaveAttribute('href', siteLinks.docs);
  });

  it('keeps explicit sign-in actions mapped to /app/login', () => {
    render(
      <MemoryRouter>
        <Header
          navLinks={[
            { to: '/product', label: 'Product' },
            { to: '/docs', label: 'Docs' }
          ]}
          githubRepo={siteLinks.github}
          theme="dark"
          onToggleTheme={() => undefined}
        />
      </MemoryRouter>
    );

    expect(siteLinks.signIn).toBe('/app/login');
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', siteLinks.signIn);
  });
});
