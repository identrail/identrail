import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { Header } from './components/layout/Header';
import { Footer } from './components/layout/Footer';
import { useRouteSeo } from './lib/useRouteSeo';

import { HomePage } from './pages/HomePage';
import { ProductPage } from './pages/ProductPage';
import { PricingPage } from './pages/PricingPage';
import { AboutPage } from './pages/AboutPage';
import { DemoPage } from './pages/DemoPage';
import { SecurityPage } from './pages/SecurityPage';
import { SolutionDetailPage } from './pages/SolutionsPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { BlogPage, BlogArticlePage } from './pages/BlogPage';
import { FaqPage } from './pages/FaqPage';
import { EnterprisePage } from './pages/EnterprisePage';
import { ResponsibleDisclosurePage } from './pages/ResponsibleDisclosurePage';
import { DocsPage } from './pages/DocsPage';
import { LegalPage } from './pages/LegalPage';
import { NotFoundPage } from './pages/NotFoundPage';

import {
  ProductAppIndexRedirect,
  ProductFindingsPage,
  ProductLoginPage,
  ProductLogoutPage,
  ProductOIDCCallbackPage,
  ProductOverviewPage,
  ProductProjectDetailPage,
  ProductProjectsPage,
  ProductSettingsPage,
  ProductShellLayout,
  ProductWorkspacesPage,
  RequireProductAuth
} from './productShell';

/**
 * Routed site shell.
 *
 * Marketing routes get the public Header + Footer. Dashboard routes
 * (/app/*) render ProductShell only — no marketing chrome — so the
 * authenticated app keeps its own layout.
 */
export function RoutedSite() {
  useRouteSeo();
  const location = useLocation();
  const isDashboard = location.pathname.startsWith('/app');

  return (
    <div className="site-shell">
      {!isDashboard ? <Header /> : null}

      <main id="main-content">
        <Routes>
          {/* ---- Dashboard (/app/*) — auth surface, no marketing chrome ---- */}
          <Route path="/app/login" element={<ProductLoginPage />} />
          <Route path="/app/callback" element={<ProductOIDCCallbackPage />} />
          <Route path="/app/logout" element={<ProductLogoutPage />} />
          <Route
            path="/app"
            element={
              <RequireProductAuth>
                <ProductAppIndexRedirect />
              </RequireProductAuth>
            }
          />
          <Route
            path="/app/:tenantID/:workspaceID"
            element={
              <RequireProductAuth>
                <ProductShellLayout />
              </RequireProductAuth>
            }
          >
            <Route index element={<ProductOverviewPage />} />
            <Route path="workspaces" element={<ProductWorkspacesPage />} />
            <Route path="projects" element={<ProductProjectsPage />} />
            <Route path="projects/:projectID" element={<ProductProjectDetailPage />} />
            <Route path="findings" element={<ProductFindingsPage />} />
            <Route path="settings" element={<ProductSettingsPage />} />
          </Route>

          {/* ---- Marketing ---- */}
          <Route path="/" element={<HomePage />} />
          <Route path="/product" element={<ProductPage />} />
          <Route path="/integrations" element={<IntegrationsPage />} />
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="/demo" element={<DemoPage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/responsible-disclosure" element={<ResponsibleDisclosurePage />} />
          <Route path="/enterprise" element={<EnterprisePage />} />
          <Route path="/faq" element={<FaqPage />} />
          <Route path="/docs" element={<DocsPage />} />
          <Route path="/blog" element={<BlogPage />} />
          <Route path="/blog/:slug" element={<BlogArticlePage />} />

          {/* Solutions, consolidated to two audience pages. The bare
              /solutions URL 301s to security-teams (the most common
              landing) — declared here as a Navigate redirect so the
              route-integrity check (scripts/check_web_route_integrity.sh)
              treats it as a redirect, not a content route. */}
          <Route path="/solutions" element={<Navigate to="/for/security-teams" replace />} />
          <Route path="/for/security-teams" element={<SolutionDetailPage slug="security-teams" />} />
          <Route path="/for/platform-engineering" element={<SolutionDetailPage slug="platform-engineering" />} />

          {/* Legacy /solutions/* and /features/* URLs — keep them working
              with redirects so external links and search results don't 404. */}
          <Route path="/solutions/security-teams" element={<Navigate to="/for/security-teams" replace />} />
          <Route path="/solutions/aws" element={<Navigate to="/for/security-teams" replace />} />
          <Route path="/solutions/multi-cloud" element={<Navigate to="/for/security-teams" replace />} />
          <Route path="/solutions/kubernetes" element={<Navigate to="/for/platform-engineering" replace />} />
          <Route path="/solutions/platform-engineering" element={<Navigate to="/for/platform-engineering" replace />} />
          <Route path="/features" element={<Navigate to="/product" replace />} />
          <Route path="/features/aws" element={<Navigate to="/product" replace />} />
          <Route path="/features/kubernetes" element={<Navigate to="/product" replace />} />
          <Route path="/features/git-scanner" element={<Navigate to="/product" replace />} />
          <Route path="/features/trust-graph" element={<Navigate to="/product" replace />} />
          <Route path="/read-only-scan" element={<Navigate to="/demo" replace />} />
          <Route path="/roi-assessment" element={<Navigate to="/demo" replace />} />
          <Route path="/deployment-models" element={<Navigate to="/pricing" replace />} />

          {/* Legal */}
          <Route path="/privacy" element={<LegalPage kind="privacy" />} />
          <Route path="/terms" element={<LegalPage kind="terms" />} />
          <Route path="/privacy-choices" element={<LegalPage kind="privacy-choices" />} />

          {/* 404 */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>

      {!isDashboard ? <Footer /> : null}
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <RoutedSite />
    </BrowserRouter>
  );
}
