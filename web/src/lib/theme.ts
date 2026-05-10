export const THEME_STORAGE_KEY = 'identrail-theme';

export type ThemeMode = 'dark' | 'light';

export function readStoredTheme(): ThemeMode | null {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    return stored === 'dark' || stored === 'light' ? stored : null;
  } catch {
    return null;
  }
}

export function resolveInitialTheme(): ThemeMode {
  const stored = readStoredTheme();
  if (stored) {
    return stored;
  }

  if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  return 'light';
}

export function resolveBootstrapTheme(pathname: string): ThemeMode {
  return pathname.startsWith('/app') ? 'light' : resolveInitialTheme();
}

export function setDocumentTheme(theme: ThemeMode) {
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = theme;
  }
}

export function persistTheme(theme: ThemeMode) {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // ignored: storage may be unavailable in private mode
  }
}

export function applyTheme(theme: ThemeMode, options?: { persist?: boolean }) {
  setDocumentTheme(theme);
  if (options?.persist) {
    persistTheme(theme);
  }
}

export function toggleTheme(theme: ThemeMode): ThemeMode {
  return theme === 'dark' ? 'light' : 'dark';
}
