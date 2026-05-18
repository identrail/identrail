import { ReactNode } from 'react';
import { Link, NavigateFunction } from 'react-router-dom';
import {
  apiClient,
  ApiError,
  type OnboardingState,
  type OnboardingStateResponse,
  type OnboardingStep,
  type RequestAuthContext
} from '../../api/client';
import { OnboardingStepper } from '../../components/onboarding/Stepper';

const ONBOARDING_VITE_ENV = ((import.meta as unknown as { env?: Record<string, unknown> }).env ?? {}) as Record<
  string,
  unknown
>;

export const FEATURE_ONBOARDING_WIZARD =
  ONBOARDING_VITE_ENV.VITE_FEATURE_ONBOARDING_WIZARD === true ||
  ONBOARDING_VITE_ENV.VITE_FEATURE_ONBOARDING_WIZARD === 'true';

export const FEATURE_ONBOARDING_CONNECTOR_AWS =
  ONBOARDING_VITE_ENV.VITE_FEATURE_CONNECTOR_AWS === true ||
  ONBOARDING_VITE_ENV.VITE_FEATURE_CONNECTOR_AWS === 'true';

export const FEATURE_ONBOARDING_CONNECTOR_GITHUB =
  ONBOARDING_VITE_ENV.VITE_FEATURE_CONNECTOR_GITHUB_V2 === true ||
  ONBOARDING_VITE_ENV.VITE_FEATURE_CONNECTOR_GITHUB_V2 === 'true';

export const FEATURE_ONBOARDING_CONNECTOR_K8S =
  ONBOARDING_VITE_ENV.VITE_FEATURE_CONNECTOR_K8S === true ||
  ONBOARDING_VITE_ENV.VITE_FEATURE_CONNECTOR_K8S === 'true';

export type OnboardingProvider = 'aws' | 'github' | 'kubernetes';

export function onboardingAuth(state: OnboardingState | null): RequestAuthContext | undefined {
  if (!state?.org_id || !state.workspace_id) {
    return undefined;
  }
  return {
    tenantID: state.org_id,
    workspaceID: state.workspace_id
  };
}

export function onboardingAppPath(state: OnboardingState | null): string {
  if (!state?.org_id || !state.workspace_id) {
    return '/app';
  }
  return `/app/${encodeURIComponent(state.org_id)}/${encodeURIComponent(state.workspace_id)}`;
}

export function onboardingProjectPath(state: OnboardingState | null): string {
  const base = onboardingAppPath(state);
  if (!state?.project_id) {
    return `${base}/projects`;
  }
  return `${base}/projects/${encodeURIComponent(state.project_id)}`;
}

export function normalizeMemberToken(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 72);
}

export function routeAfterOnboardingResponse(navigate: NavigateFunction, redirectPath: string | undefined, fallback: string) {
  navigate(redirectPath && redirectPath.startsWith('/') ? redirectPath : fallback);
}

export function onboardingStepPath(step: OnboardingStep | undefined): string {
  switch (step) {
    case 'workspace':
      return '/onboarding/workspace';
    case 'connect':
      return '/onboarding/connect';
    case 'scan':
      return '/onboarding/scan';
    case 'invite':
      return '/onboarding/invite';
    case 'complete':
      return '/app';
    case 'org':
    default:
      return '/onboarding/org';
  }
}

export function routeToOnboardingStep(
  navigate: NavigateFunction,
  response: OnboardingStateResponse,
  currentPath: string,
  fallback: string
): boolean {
  const target = response.redirect_path?.startsWith('/') ? response.redirect_path : onboardingStepPath(response.state.current_step);
  const normalizedTarget = target === '/app' ? target : target.replace(/\/$/, '');
  if (normalizedTarget && normalizedTarget !== currentPath) {
    navigate(normalizedTarget, { replace: true });
    return true;
  }
  if (!normalizedTarget && fallback !== currentPath) {
    navigate(fallback, { replace: true });
    return true;
  }
  return false;
}

export async function loadOrStartOnboardingResponse(): Promise<OnboardingStateResponse> {
  try {
    return await apiClient.getOnboardingState();
  } catch (error) {
    if (error instanceof ApiError && error.status !== 404) {
      throw error;
    }
    return apiClient.startOnboarding();
  }
}

export async function loadOrStartOnboarding(): Promise<OnboardingState> {
  return (await loadOrStartOnboardingResponse()).state;
}

export function OnboardingFrame({
  step,
  eyebrow,
  title,
  description,
  children,
  aside
}: {
  step: OnboardingStep;
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
  aside?: ReactNode;
}) {
  return (
    <section className="idt-onboarding-shell">
      <header className="idt-onboarding-topbar">
        <Link to="/" className="idt-logo-link" aria-label="Identrail home">
          <span className="idt-onboarding-logo-mark">
            <img src="/identrail-logo.png" alt="" aria-hidden="true" />
          </span>
          <span>Identrail</span>
        </Link>
        <Link to="/app/logout" className="idt-btn idt-btn-ghost">
          Sign out
        </Link>
      </header>
      <div className="idt-onboarding-grid">
        <aside className="idt-onboarding-rail">
          <p className="idt-onboarding-rail-label">Setup progress</p>
          <OnboardingStepper currentStep={step} />
          {aside}
        </aside>
        <article className="idt-onboarding-panel">
          <p className="idt-app-kicker">{eyebrow}</p>
          <h1>{title}</h1>
          <p>{description}</p>
          {children}
        </article>
      </div>
    </section>
  );
}
