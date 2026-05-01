import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { App } from './App';

describe('App', () => {
  beforeEach(() => {
    window.localStorage.removeItem('identrail-product-session');
  });

  it('renders homepage hero and conversion CTAs', () => {
    window.history.pushState({}, '', '/');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Identify risky machine trust paths before they become incidents.'
      })
    ).toBeInTheDocument();

    expect(screen.getAllByRole('link', { name: 'Start Free Risk Scan' }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('link', { name: 'Book Demo' }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Adoption Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Reachable Risk Paths/i).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('tab', { name: 'Graph' }).length).toBeGreaterThan(0);
  });

  it('renders pricing page routes and key elements', () => {
    window.history.pushState({}, '', '/pricing');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Pricing aligned to how teams adopt machine identity security/i
      })
    ).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /Annual/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Contact Sales' })).toBeInTheDocument();
  });

  it('renders read-only scan intake flow route', () => {
    window.history.pushState({}, '', '/read-only-scan');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Start a machine identity risk scan with deployment-safe onboarding/i
      })
    ).toBeInTheDocument();

    expect(screen.getByText(/Step 1 of 3/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeInTheDocument();
  });

  it('renders deployment models route', () => {
    window.history.pushState({}, '', '/deployment-models');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Choose your control boundary without changing operating model/i
      })
    ).toBeInTheDocument();
  });

  it('renders integrations route', () => {
    window.history.pushState({}, '', '/integrations');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Identity signal coverage across cloud, cluster, and code workflows/i
      })
    ).toBeInTheDocument();
  });

  it('renders ROI assessment route', () => {
    window.history.pushState({}, '', '/roi-assessment');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Model risk-reduction impact with transparent assumptions/i
      })
    ).toBeInTheDocument();
  });

  it('renders full FAQ route', () => {
    window.history.pushState({}, '', '/faq');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Technical and operational questions teams ask before rollout/i
      })
    ).toBeInTheDocument();
  });

  it('renders responsible disclosure route', () => {
    window.history.pushState({}, '', '/responsible-disclosure');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Report security issues through a coordinated disclosure process/i
      })
    ).toBeInTheDocument();
  });

  it('guards product shell routes and redirects unauthenticated users to app login', () => {
    window.history.pushState({}, '', '/app/default/default');
    render(<App />);

    expect(
      screen.getByRole('heading', {
        level: 1,
        name: /Sign in to the Identrail app shell/i
      })
    ).toBeInTheDocument();
  });

  it('loads authenticated product shell placeholders after login', async () => {
    window.history.pushState({}, '', '/app/login');
    render(<App />);

    fireEvent.change(screen.getByLabelText(/Tenant ID/i), { target: { value: 'tenant-a' } });
    fireEvent.change(screen.getByLabelText(/Workspace ID/i), { target: { value: 'workspace-a' } });
    fireEvent.click(screen.getByRole('button', { name: /Continue to app/i }));

    expect(await screen.findByRole('heading', { level: 1, name: /Identrail Workspace/i })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { level: 2, name: /Overview/i })).toBeInTheDocument();
  });

  it('renders tenancy-scoped project detail placeholder route inside app shell', async () => {
    window.localStorage.setItem(
      'identrail-product-session',
      JSON.stringify({
        tenantID: 'tenant-a',
        workspaceID: 'workspace-a'
      })
    );
    window.history.pushState({}, '', '/app/tenant-a/workspace-a/projects/project-1');
    render(<App />);

    expect(await screen.findByRole('heading', { level: 2, name: /Project detail/i })).toBeInTheDocument();
    expect(await screen.findByText(/Project project-1 placeholder/i)).toBeInTheDocument();
  });
});
