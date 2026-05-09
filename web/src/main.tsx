import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles/tokens.css';
// dashboard.css is loaded here (not lazily from productShell.tsx) because
// the build-time prerender (web/scripts/prerender-routes.ts) runs via tsx,
// which can't resolve CSS imports through the productShell module graph.
//
// All rules in dashboard.css are now scoped under `.idt-*` classes —
// either the original `.idt-app-*` selectors, or the `.idt-app-shell-screen`
// scope we wrap around the bare element selectors (h1/h2/h3, body
// backgrounds) that previously bled onto marketing pages. So loading the
// file globally is purely a code-size concern.
//
// TODO(perf): split dashboard.css off main.tsx so marketing visitors don't
// download it. Doing this safely needs either (a) a CSS loader for the
// prerender tsx process, or (b) a separate App entry for the prerender
// that doesn't pull in productShell.
import './styles/dashboard.css';
import './styles.css';

const THEME_STORAGE_KEY = 'identrail-theme';
const VALID_THEMES = ['light', 'dark'] as const;
type Theme = (typeof VALID_THEMES)[number];

function readStoredTheme(): Theme | null {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return VALID_THEMES.includes(stored as Theme) ? (stored as Theme) : null;
  } catch {
    return null;
  }
}

function applyInitialTheme() {
  if (typeof window === 'undefined') {
    return;
  }

  const stored = readStoredTheme();
  if (stored) {
    document.documentElement.dataset.theme = stored;
    return;
  }

  // No stored preference — let the OS preference drive via the
  // `prefers-color-scheme` block in tokens.css. Don't set data-theme.
}

applyInitialTheme();

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
