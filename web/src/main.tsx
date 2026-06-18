import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { applyStoredAppearancePreferences, installAppearancePreferenceListener } from './appearance';
import './styles/tokens.css';
import './styles.css';

applyStoredAppearancePreferences();
installAppearancePreferenceListener();

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
