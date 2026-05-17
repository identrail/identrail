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
      if (url.hostname === 'api.github.com') return okJSON({ stargazers_count: 3 });
      if (url.hostname === 'img.shields.io' && url.pathname.includes('/docker/pulls')) {
        return okJSON({ message: 'repo not found' });
      }
      return okJSON({});
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<HeroOpenSourceProofPills />);

    await waitFor(() => expect(screen.getByText('3')).toBeInTheDocument());

    const dockerPill = screen.getByText('Docker pulls').closest('a');
    expect(dockerPill).not.toBeNull();
    expect(within(dockerPill as HTMLElement).getByText('Live')).toBeInTheDocument();
    expect(within(dockerPill as HTMLElement).queryByText('0')).not.toBeInTheDocument();
  });

  it('loads pull metrics from the published Docker Hub repositories', async () => {
    const dockerMetricPaths: string[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(fetchURL(input));
      if (url.hostname === 'api.github.com') return okJSON({ stargazers_count: 3 });
      if (url.hostname === 'img.shields.io' && url.pathname.includes('/docker/pulls')) {
        dockerMetricPaths.push(url.pathname);
        return okJSON({ message: '1' });
      }
      return okJSON({});
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<HeroOpenSourceProofPills />);

    await waitFor(() => expect(screen.getByText('5')).toBeInTheDocument());

    expect(dockerMetricPaths).toEqual([
      '/docker/pulls/identrail/identrail.json',
      '/docker/pulls/identrail/identrail-api.json',
      '/docker/pulls/identrail/identrail-worker.json',
      '/docker/pulls/identrail/identrail-web.json',
      '/docker/pulls/identrail/identrail-agent.json'
    ]);
  });
});
