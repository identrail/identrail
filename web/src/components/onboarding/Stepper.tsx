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
  const activeStep = STEP_ITEMS[activeIndex] ?? STEP_ITEMS[0];

  return (
    <nav className="idt-onboarding-stepper" aria-label="Onboarding progress">
      <div className="idt-onboarding-progress-summary">
        <span>
          Step {activeIndex + 1} of {STEP_ITEMS.length}
        </span>
        <strong>{activeStep.label}</strong>
      </div>
      <ol className="idt-onboarding-step-list">
        {STEP_ITEMS.map((step, index) => {
          const state = index < activeIndex ? 'complete' : index === activeIndex ? 'current' : 'pending';
          const stateLabel = state === 'complete' ? 'Done' : state === 'current' ? 'Current' : 'Next';
          return (
            <li className={`idt-onboarding-step is-${state}`} key={step.id} aria-current={state === 'current' ? 'step' : undefined}>
              <span className="idt-onboarding-step-index">{String(index + 1).padStart(2, '0')}</span>
              <span className="idt-onboarding-step-copy">
                <strong>{step.label}</strong>
                <small>{stateLabel}</small>
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
