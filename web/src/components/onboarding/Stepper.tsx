import type { OnboardingStep } from '../../api/client';
import { Building2, PanelsTopLeft, PlugZap, ScanSearch, UserPlus, type LucideIcon } from 'lucide-react';

const STEP_ITEMS: Array<{ id: Exclude<OnboardingStep, 'complete'>; label: string; detail: string; icon: LucideIcon }> = [
  { id: 'org', label: 'Organization', detail: 'Boundary', icon: Building2 },
  { id: 'workspace', label: 'Workspace', detail: 'Scope', icon: PanelsTopLeft },
  { id: 'connect', label: 'Source', detail: 'AWS, GitHub, K8s', icon: PlugZap },
  { id: 'scan', label: 'Scan', detail: 'Baseline', icon: ScanSearch },
  { id: 'invite', label: 'Team', detail: 'Access', icon: UserPlus }
];

export function OnboardingStepper({ currentStep }: { currentStep: OnboardingStep }) {
  const currentIndex = STEP_ITEMS.findIndex((step) => step.id === currentStep);
  const activeIndex = currentStep === 'complete' ? STEP_ITEMS.length : Math.max(0, currentIndex);

  return (
    <nav className="idt-onboarding-stepper" aria-label="Onboarding progress">
      {STEP_ITEMS.map((step, index) => {
        const state = index < activeIndex ? 'complete' : index === activeIndex ? 'current' : 'pending';
        const StepIcon = step.icon;
        return (
          <div className={`idt-onboarding-step is-${state}`} key={step.id} aria-current={state === 'current' ? 'step' : undefined}>
            <span className="idt-onboarding-step-icon" aria-hidden="true">
              <StepIcon size={18} strokeWidth={2.2} />
            </span>
            <span className="idt-onboarding-step-copy">
              <strong>{step.label}</strong>
              <small>{step.detail}</small>
            </span>
          </div>
        );
      })}
    </nav>
  );
}
