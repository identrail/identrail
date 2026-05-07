import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { loadEnv } from 'vite';

function originFromURL(value?: string): string | null {
  const trimmed = value?.trim();
  if (!trimmed) {
    return null;
  }

  try {
    return new URL(trimmed).origin;
  } catch {
    return null;
  }
}

function buildConnectSrc(env: Record<string, string>, isProduction: boolean): string {
  const allowlist = new Set<string>(["'self'", 'https://api.github.com', 'https://img.shields.io']);
  const apiOrigin = originFromURL(env.VITE_IDENTRAIL_API_URL);
  const oidcOrigin = originFromURL(env.VITE_OIDC_ISSUER_URL);

  if (apiOrigin) {
    allowlist.add(apiOrigin);
  }
  if (oidcOrigin) {
    allowlist.add(oidcOrigin);
  }

  if (!isProduction) {
    allowlist.add('http://localhost:8080');
    allowlist.add('http://127.0.0.1:8080');
    allowlist.add('ws://localhost:5173');
    allowlist.add('ws://127.0.0.1:5173');
  }

  return Array.from(allowlist).join(' ');
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const connectSrc = buildConnectSrc(env, mode === 'production');

  return {
    plugins: [
      react(),
      {
        name: 'identrail-csp-connect-src',
        transformIndexHtml(html) {
          return html.replace(/__IDENTRAIL_CONNECT_SRC__/g, connectSrc);
        }
      }
    ],
    build: {
      cssCodeSplit: true,
      chunkSizeWarningLimit: 800,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('react') || id.includes('react-dom') || id.includes('react-router-dom')) {
              return 'react_vendor';
            }
            return undefined;
          }
        }
      }
    },
    server: {
      port: 5173,
      host: true
    },
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: ['./src/test/setup.ts'],
      coverage: {
        provider: 'v8',
        reporter: ['text', 'lcov'],
        thresholds: {
          lines: 60,
          functions: 53,
          statements: 60,
          branches: 50
        }
      }
    }
  };
});
