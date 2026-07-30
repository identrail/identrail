import { render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HeroOpenSourceProofPills } from './HeroOpenSourceProofPills';

function okJSON(payload: unknown): Response {
  return {
    ok: true,
    json: async () => payload
  } as Response;
}

function fetchURL(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.toString();
  return input.url;
}

describe('HeroOpenSourceProofPills', () => {
  afterEach(() => {
    window.localStorage.clear();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('does not show zero Docker pulls when pull metrics are unavailable', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(fetchURL(input));
      if (url.hostname === 'img.shields.io' && url.pathname.includes('/docker/pulls')) {
        return okJSON({ message: 'repo not found' });
      }
      return okJSON({});
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<HeroOpenSourceProofPills />);

    const dockerPill = (await screen.findByText('Docker pulls')).closest('a');
    expect(dockerPill).not.toBeNull();
    await waitFor(() =>
      expect(within(dockerPill as HTMLElement).getByText('Live')).toBeInTheDocument()
    );
    expect(within(dockerPill as HTMLElement).queryByText('0')).not.toBeInTheDocument();
  });

  it('loads pull metrics from the primary published Docker Hub repository', async () => {
    const dockerMetricPaths: string[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(fetchURL(input));
      if (url.hostname === 'img.shields.io' && url.pathname.includes('/docker/pulls')) {
        dockerMetricPaths.push(url.pathname);
        return okJSON({ message: '2.4k' });
      }
      return okJSON({});
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<HeroOpenSourceProofPills />);

    await waitFor(() => expect(screen.getByText('2.4k+')).toBeInTheDocument());

    expect(dockerMetricPaths).toEqual(['/docker/pulls/identrail/identrail.json']);
  });

  it('does not render a GitHub stars pill and does not call the GitHub API', async () => {
    const fetchedHostnames: string[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      fetchedHostnames.push(new URL(fetchURL(input)).hostname);
      return okJSON({ message: '2.4k' });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<HeroOpenSourceProofPills />);

    await waitFor(() => expect(screen.getByText('2.4k+')).toBeInTheDocument());
    expect(screen.queryByText('GitHub stars')).not.toBeInTheDocument();
    expect(fetchedHostnames).not.toContain('api.github.com');
    expect(screen.getByRole('link', { name: 'View Identrail on GitHub' })).toHaveAttribute(
      'href',
      'https://github.com/identrail/identrail'
    );
  });
});
