import type { OnboardingStep } from '../../api/client';
import { CheckCircle2, Circle, CircleDot } from 'lucide-react';

const STEP_ITEMS: Array<{ id: Exclude<OnboardingStep, 'complete'>; label: string; detail: string }> = [
  { id: 'org', label: 'Organization', detail: 'Security boundary' },
  { id: 'workspace', label: 'Workspace', detail: 'First environment' },
  { id: 'connect', label: 'Connect source', detail: 'Read-only signal' },
  { id: 'scan', label: 'First scan', detail: 'Findings baseline' },
  { id: 'invite', label: 'Invite team', detail: 'Reviewer access' }
];

export function OnboardingStepper({ currentStep }: { currentStep: OnboardingStep }) {
  const currentIndex = STEP_ITEMS.findIndex((step) => step.id === currentStep);
  const activeIndex = currentStep === 'complete' ? STEP_ITEMS.length : Math.max(0, currentIndex);

  return (
    <nav className="idt-onboarding-stepper" aria-label="Onboarding progress">
      {STEP_ITEMS.map((step, index) => {
        const state = index < activeIndex ? 'complete' : index === activeIndex ? 'current' : 'pending';
        const StepIcon = state === 'complete' ? CheckCircle2 : state === 'current' ? CircleDot : Circle;
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
