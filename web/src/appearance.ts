export const LEGACY_THEME_STORAGE_KEY = 'identrail-theme';
export const APPEARANCE_STORAGE_KEY = 'identrail-appearance';

export type AppearanceThemeMode = 'light' | 'dark' | 'system';
export type AppearanceReduceMotion = 'system' | 'on' | 'off';
export type AppearanceDiffMarkers = 'color' | 'symbols';

export type AppearancePresetID =
  | 'absolutely'
  | 'catppuccin'
  | 'everforest'
  | 'github'
  | 'gruvbox'
  | 'identrail'
  | 'linear'
  | 'neon'
  | 'notion'
  | 'one'
  | 'proof'
  | 'raycast'
  | 'rose-pine'
  | 'shopify'
  | 'shopify-light'
  | 'slack'
  | 'slack-light'
  | 'solarized'
  | 'stripe'
  | 'stripe-light'
  | 'supabase'
  | 'vercel'
  | 'vs-code-plus'
  | 'xcode';

export type AppearanceFontID =
  | 'system'
  | 'inter'
  | 'geist'
  | 'space-grotesk'
  | 'barlow-condensed'
  | 'mono-system'
  | 'ibm-plex-mono'
  | 'jetbrains-mono';

export type AppearancePreferences = {
  themeMode: AppearanceThemeMode;
  lightPreset: AppearancePresetID;
  darkPreset: AppearancePresetID;
  accent: string;
  background: string;
  foreground: string;
  customColors: boolean;
  uiFont: AppearanceFontID;
  codeFont: AppearanceFontID;
  translucentSidebar: boolean;
  contrast: number;
  pointerCursors: boolean;
  reduceMotion: AppearanceReduceMotion;
  uiFontSize: number;
  codeFontSize: number;
  diffMarkers: AppearanceDiffMarkers;
  fontSmoothing: boolean;
};

export type AppearancePreset = {
  id: AppearancePresetID;
  label: string;
  mode: 'light' | 'dark' | 'both';
  accent: string;
  background: string;
  foreground: string;
  panel: string;
  border: string;
  muted: string;
};

export const APPEARANCE_PRESETS: AppearancePreset[] = [
  {
    id: 'notion',
    label: 'Notion',
    mode: 'light',
    accent: '#3183d8',
    background: '#ffffff',
    foreground: '#37352f',
    panel: '#f7f6f3',
    border: '#e6e4df',
    muted: '#787774'
  },
  {
    id: 'one',
    label: 'One',
    mode: 'both',
    accent: '#6c7cff',
    background: '#101217',
    foreground: '#f4f5f8',
    panel: '#171a21',
    border: '#2c313b',
    muted: '#aeb5c2'
  },
  {
    id: 'proof',
    label: 'Proof',
    mode: 'light',
    accent: '#1f8f68',
    background: '#f7faf6',
    foreground: '#1f2a22',
    panel: '#ffffff',
    border: '#dbe7dd',
    muted: '#627067'
  },
  {
    id: 'raycast',
    label: 'Raycast',
    mode: 'both',
    accent: '#ff6363',
    background: '#141112',
    foreground: '#fff7f7',
    panel: '#1e1819',
    border: '#3b282b',
    muted: '#d7b8bc'
  },
  {
    id: 'stripe-light',
    label: 'Stripe',
    mode: 'light',
    accent: '#635bff',
    background: '#f6f9fc',
    foreground: '#0a2540',
    panel: '#ffffff',
    border: '#d6dee8',
    muted: '#425466'
  },
  {
    id: 'stripe',
    label: 'Stripe',
    mode: 'dark',
    accent: '#99a3ff',
    background: '#0a1020',
    foreground: '#f6f9fc',
    panel: '#11182b',
    border: '#27324a',
    muted: '#a5b4c6'
  },
  {
    id: 'slack-light',
    label: 'Slack',
    mode: 'light',
    accent: '#611f69',
    background: '#f8f5f7',
    foreground: '#1d1c1d',
    panel: '#ffffff',
    border: '#e8dfe7',
    muted: '#616061'
  },
  {
    id: 'slack',
    label: 'Slack',
    mode: 'dark',
    accent: '#36c5f0',
    background: '#101014',
    foreground: '#f8f8f8',
    panel: '#1a1d21',
    border: '#34373b',
    muted: '#ababad'
  },
  {
    id: 'shopify-light',
    label: 'Shopify',
    mode: 'light',
    accent: '#008060',
    background: '#f6f6f7',
    foreground: '#202223',
    panel: '#ffffff',
    border: '#d5d8dc',
    muted: '#6d7175'
  },
  {
    id: 'shopify',
    label: 'Shopify',
    mode: 'dark',
    accent: '#95bf47',
    background: '#0b1411',
    foreground: '#f3f8f4',
    panel: '#101d18',
    border: '#284033',
    muted: '#b6c5bb'
  },
  {
    id: 'rose-pine',
    label: 'Rose Pine',
    mode: 'dark',
    accent: '#eb6f92',
    background: '#191724',
    foreground: '#e0def4',
    panel: '#1f1d2e',
    border: '#403d52',
    muted: '#908caa'
  },
  {
    id: 'solarized',
    label: 'Solarized',
    mode: 'both',
    accent: '#268bd2',
    background: '#002b36',
    foreground: '#fdf6e3',
    panel: '#073642',
    border: '#335b63',
    muted: '#93a1a1'
  },
  {
    id: 'vercel',
    label: 'Vercel',
    mode: 'both',
    accent: '#ffffff',
    background: '#000000',
    foreground: '#ededed',
    panel: '#0a0a0a',
    border: '#2a2a2a',
    muted: '#a1a1a1'
  },
  {
    id: 'vs-code-plus',
    label: 'VS Code Plus',
    mode: 'dark',
    accent: '#007acc',
    background: '#1e1e1e',
    foreground: '#d4d4d4',
    panel: '#252526',
    border: '#3c3c3c',
    muted: '#9cdcfe'
  },
  {
    id: 'xcode',
    label: 'Xcode',
    mode: 'light',
    accent: '#147efb',
    background: '#f5f7fb',
    foreground: '#1d2433',
    panel: '#ffffff',
    border: '#d8dde7',
    muted: '#667085'
  },
  {
    id: 'absolutely',
    label: 'Absolutely',
    mode: 'light',
    accent: '#3183d8',
    background: '#fbfcff',
    foreground: '#171923',
    panel: '#ffffff',
    border: '#dce5f2',
    muted: '#66758a'
  },
  {
    id: 'catppuccin',
    label: 'Catppuccin',
    mode: 'dark',
    accent: '#89b4fa',
    background: '#1e1e2e',
    foreground: '#cdd6f4',
    panel: '#181825',
    border: '#45475a',
    muted: '#a6adc8'
  },
  {
    id: 'everforest',
    label: 'Everforest',
    mode: 'dark',
    accent: '#a7c080',
    background: '#2d353b',
    foreground: '#d3c6aa',
    panel: '#232a2e',
    border: '#475258',
    muted: '#859289'
  },
  {
    id: 'github',
    label: 'GitHub',
    mode: 'both',
    accent: '#2f81f7',
    background: '#0d1117',
    foreground: '#f0f6fc',
    panel: '#010409',
    border: '#30363d',
    muted: '#8b949e'
  },
  {
    id: 'supabase',
    label: 'Supabase',
    mode: 'dark',
    accent: '#3ecf8e',
    background: '#0b0f0c',
    foreground: '#ecfdf5',
    panel: '#101815',
    border: '#1f3a2f',
    muted: '#9fb7aa'
  },
  {
    id: 'neon',
    label: 'Neon',
    mode: 'dark',
    accent: '#00e599',
    background: '#030712',
    foreground: '#f8fafc',
    panel: '#08111f',
    border: '#1f2a44',
    muted: '#94a3b8'
  },
  {
    id: 'gruvbox',
    label: 'Gruvbox',
    mode: 'dark',
    accent: '#fabd2f',
    background: '#282828',
    foreground: '#ebdbb2',
    panel: '#1d2021',
    border: '#504945',
    muted: '#a89984'
  },
  {
    id: 'identrail',
    label: 'Identrail',
    mode: 'dark',
    accent: '#7c6dff',
    background: '#121518',
    foreground: '#f5f7f8',
    panel: '#090b0e',
    border: '#2b3037',
    muted: '#adb5bf'
  },
  {
    id: 'linear',
    label: 'Linear',
    mode: 'dark',
    accent: '#5e6ad2',
    background: '#0f1014',
    foreground: '#f7f8f8',
    panel: '#16171d',
    border: '#2f3037',
    muted: '#a7aab3'
  }
];

export const APPEARANCE_FONTS: Record<AppearanceFontID, string> = {
  system: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif',
  inter: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  geist: 'Geist, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  'space-grotesk': '"Space Grotesk", Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  'barlow-condensed': '"Barlow Semi Condensed", Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
  'mono-system': 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  'ibm-plex-mono': '"IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  'jetbrains-mono': '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace'
};

export const APPEARANCE_FONT_LABELS: Record<AppearanceFontID, string> = {
  system: 'System',
  inter: 'Inter',
  geist: 'Geist',
  'space-grotesk': 'Space Grotesk',
  'barlow-condensed': 'Barlow Condensed',
  'mono-system': 'System Mono',
  'ibm-plex-mono': 'IBM Plex Mono',
  'jetbrains-mono': 'JetBrains Mono'
};

export const DEFAULT_APPEARANCE_PREFERENCES: AppearancePreferences = {
  themeMode: 'dark',
  lightPreset: 'notion',
  darkPreset: 'vercel',
  accent: '#ffffff',
  background: '#000000',
  foreground: '#ededed',
  customColors: false,
  uiFont: 'inter',
  codeFont: 'mono-system',
  translucentSidebar: false,
  contrast: 52,
  pointerCursors: false,
  reduceMotion: 'system',
  uiFontSize: 16,
  codeFontSize: 14,
  diffMarkers: 'color',
  fontSmoothing: true
};

const FONT_IDS: ReadonlySet<string> = new Set(Object.keys(APPEARANCE_FONTS));
const HEX_COLOR_PATTERN = /^#[0-9a-fA-F]{6}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sanitizeEnum<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && allowed.includes(value as T) ? (value as T) : fallback;
}

function sanitizePresetID(value: unknown, mode: 'light' | 'dark', fallback: AppearancePresetID): AppearancePresetID {
  if (typeof value !== 'string') {
    return fallback;
  }
  const preset = APPEARANCE_PRESETS.find((candidate) => candidate.id === value);
  if (!preset) {
    return fallback;
  }
  if (mode === 'light') {
    return preset.mode === 'light' ? preset.id : fallback;
  }
  return preset.mode === 'dark' || preset.mode === 'both' ? preset.id : fallback;
}

function sanitizeFontID(value: unknown, fallback: AppearanceFontID): AppearanceFontID {
  return typeof value === 'string' && FONT_IDS.has(value) ? (value as AppearanceFontID) : fallback;
}

function sanitizeHexColor(value: unknown, fallback: string): string {
  return typeof value === 'string' && HEX_COLOR_PATTERN.test(value) ? value.toLowerCase() : fallback;
}

function sanitizeNumber(value: unknown, fallback: number, min: number, max: number): number {
  const numberValue = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numberValue)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(numberValue)));
}

function sanitizeBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

export function normalizeAppearancePreferences(value: unknown): AppearancePreferences {
  const source = isRecord(value) ? value : {};
  return {
    themeMode: sanitizeEnum(source.themeMode, ['light', 'dark', 'system'], DEFAULT_APPEARANCE_PREFERENCES.themeMode),
    lightPreset: sanitizePresetID(source.lightPreset, 'light', DEFAULT_APPEARANCE_PREFERENCES.lightPreset),
    darkPreset: sanitizePresetID(source.darkPreset, 'dark', DEFAULT_APPEARANCE_PREFERENCES.darkPreset),
    accent: sanitizeHexColor(source.accent, DEFAULT_APPEARANCE_PREFERENCES.accent),
    background: sanitizeHexColor(source.background, DEFAULT_APPEARANCE_PREFERENCES.background),
    foreground: sanitizeHexColor(source.foreground, DEFAULT_APPEARANCE_PREFERENCES.foreground),
    customColors: sanitizeBoolean(source.customColors, DEFAULT_APPEARANCE_PREFERENCES.customColors),
    uiFont: sanitizeFontID(source.uiFont, DEFAULT_APPEARANCE_PREFERENCES.uiFont),
    codeFont: sanitizeFontID(source.codeFont, DEFAULT_APPEARANCE_PREFERENCES.codeFont),
    translucentSidebar: false,
    contrast: sanitizeNumber(source.contrast, DEFAULT_APPEARANCE_PREFERENCES.contrast, 0, 100),
    pointerCursors: sanitizeBoolean(source.pointerCursors, DEFAULT_APPEARANCE_PREFERENCES.pointerCursors),
    reduceMotion: sanitizeEnum(source.reduceMotion, ['system', 'on', 'off'], DEFAULT_APPEARANCE_PREFERENCES.reduceMotion),
    uiFontSize: sanitizeNumber(source.uiFontSize, DEFAULT_APPEARANCE_PREFERENCES.uiFontSize, 14, 22),
    codeFontSize: sanitizeNumber(source.codeFontSize, DEFAULT_APPEARANCE_PREFERENCES.codeFontSize, 12, 22),
    diffMarkers: sanitizeEnum(source.diffMarkers, ['color', 'symbols'], DEFAULT_APPEARANCE_PREFERENCES.diffMarkers),
    fontSmoothing: sanitizeBoolean(source.fontSmoothing, DEFAULT_APPEARANCE_PREFERENCES.fontSmoothing)
  };
}

function resolveSystemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return 'dark';
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function resolveAppearanceThemeMode(themeMode: AppearanceThemeMode): 'light' | 'dark' {
  return themeMode === 'system' ? resolveSystemTheme() : themeMode;
}

export function findAppearancePreset(id: AppearancePresetID): AppearancePreset {
  return APPEARANCE_PRESETS.find((preset) => preset.id === id) ?? APPEARANCE_PRESETS[0];
}

export function readAppearancePreferences(): AppearancePreferences {
  if (typeof window === 'undefined') {
    return DEFAULT_APPEARANCE_PREFERENCES;
  }

  try {
    const raw = window.localStorage.getItem(APPEARANCE_STORAGE_KEY);
    if (raw) {
      return normalizeAppearancePreferences(JSON.parse(raw));
    }
    const legacyTheme = window.localStorage.getItem(LEGACY_THEME_STORAGE_KEY);
    if (legacyTheme === 'light' || legacyTheme === 'dark') {
      return normalizeAppearancePreferences({
        ...DEFAULT_APPEARANCE_PREFERENCES,
        themeMode: legacyTheme
      });
    }
  } catch {
    return DEFAULT_APPEARANCE_PREFERENCES;
  }
  return DEFAULT_APPEARANCE_PREFERENCES;
}

export function saveAppearancePreferences(preferences: AppearancePreferences): AppearancePreferences {
  const normalized = normalizeAppearancePreferences(preferences);
  if (typeof window !== 'undefined') {
    try {
      window.localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify(normalized));
      window.localStorage.setItem(LEGACY_THEME_STORAGE_KEY, resolveAppearanceThemeMode(normalized.themeMode));
    } catch {
      // Storage can be blocked by the browser; the in-memory UI state still applies.
    }
  }
  return normalized;
}

export function applyAppearancePreferences(preferences: AppearancePreferences): AppearancePreferences {
  const normalized = normalizeAppearancePreferences(preferences);
  if (typeof document === 'undefined') {
    return normalized;
  }

  const resolvedTheme = resolveAppearanceThemeMode(normalized.themeMode);
  const presetID = resolvedTheme === 'light' ? normalized.lightPreset : normalized.darkPreset;
  const preset = findAppearancePreset(presetID);
  const root = document.documentElement;
  const style = root.style;
  const colors = normalized.customColors
    ? {
        accent: normalized.accent,
        background: normalized.background,
        foreground: normalized.foreground
      }
    : {
        accent: preset.accent,
        background: preset.background,
        foreground: preset.foreground
      };
  const contrast = normalized.contrast / 100;
  const panelMix = `${Math.round(64 + contrast * 24)}%`;
  const borderMix = `${Math.round(50 + contrast * 50)}%`;
  const mutedMix = `${Math.round(58 + contrast * 32)}%`;

  root.dataset.theme = resolvedTheme;
  root.dataset.appearanceReady = 'true';
  root.dataset.appearanceMode = normalized.themeMode;
  root.dataset.appearancePreset = preset.id;
  root.dataset.pointerCursors = normalized.pointerCursors ? 'true' : 'false';
  root.dataset.reduceMotion = normalized.reduceMotion;
  root.dataset.diffMarkers = normalized.diffMarkers;
  root.dataset.fontSmoothing = normalized.fontSmoothing ? 'true' : 'false';
  root.dataset.appearanceTranslucentSidebar = normalized.translucentSidebar ? 'true' : 'false';
  delete root.dataset.appearanceAppIcon;

  style.setProperty('--appearance-accent', colors.accent);
  style.setProperty('--appearance-bg', colors.background);
  style.setProperty('--appearance-fg', colors.foreground);
  style.setProperty('--appearance-panel', preset.panel);
  style.setProperty('--appearance-border', preset.border);
  style.setProperty('--appearance-muted', preset.muted);
  style.setProperty('--appearance-panel-mix', panelMix);
  style.setProperty('--appearance-border-mix', borderMix);
  style.setProperty('--appearance-muted-mix', mutedMix);
  style.setProperty('--appearance-ui-font', APPEARANCE_FONTS[normalized.uiFont]);
  style.setProperty('--appearance-code-font', APPEARANCE_FONTS[normalized.codeFont]);
  style.setProperty('--appearance-ui-font-size', `${normalized.uiFontSize}px`);
  style.setProperty('--appearance-code-font-size', `${normalized.codeFontSize}px`);
  style.setProperty('--appearance-contrast', String(normalized.contrast));

  return normalized;
}

export function applyStoredAppearancePreferences(): AppearancePreferences {
  return applyAppearancePreferences(readAppearancePreferences());
}

export function installAppearancePreferenceListener(): () => void {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return () => {};
  }
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const listener = () => {
    applyStoredAppearancePreferences();
  };
  if (typeof media.addEventListener === 'function') {
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }
  media.addListener(listener);
  return () => media.removeListener(listener);
}
