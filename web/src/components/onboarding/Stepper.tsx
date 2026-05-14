import type { OnboardingStep } from '../../api/client';

const STEP_ITEMS: Array<{ id: Exclude<OnboardingStep, 'complete'>; label: string }> = [
  { id: 'org', label: 'Organization' },
  { id: 'workspace', label: 'Workspace' },
  { id: 'connect', label: 'Connect' },
  { id: 'scan', label: 'Scan' },
  { id: 'invite', label: 'Invite' }
];

export function OnboardingStepper({ currentStep }: { currentStep: OnboardingStep }) {
  const activeIndex = Math.max(
    0,
    STEP_ITEMS.findIndex((step) => step.id === currentStep)
  );

  return (
    <nav className="idt-onboarding-stepper" aria-label="Onboarding progress">
      {STEP_ITEMS.map((step, index) => {
        const state = index < activeIndex ? 'complete' : index === activeIndex ? 'current' : 'pending';
        return (
          <div className={`idt-onboarding-step is-${state}`} key={step.id} aria-current={state === 'current' ? 'step' : undefined}>
            <span>{String(index + 1).padStart(2, '0')}</span>
            <strong>{step.label}</strong>
          </div>
        );
      })}
    </nav>
  );
}
