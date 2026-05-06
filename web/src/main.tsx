import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles/tokens.css';
import './styles.css';

const THEME_STORAGE_KEY = 'identrail-theme';

function applyInitialTheme() {
  if (typeof window === 'undefined') {
    return;
  }

  document.documentElement.dataset.theme = 'light';
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, 'light');
  } catch {
    // Ignore storage write failures (blocked/disabled storage).
  }
}

applyInitialTheme();

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
