import { ReactNode, useCallback, useEffect, useId, useRef, useState } from 'react';

const HOLD_TO_CONFIRM_MS = 900;
const HOLD_REJECT_RESET_MS = 320;

type DangerZoneProps = {
  description?: string;
  children: ReactNode;
};

export function DangerZone({ description, children }: DangerZoneProps) {
  return (
    <section
      aria-labelledby="idt-danger-zone-title"
      className="idt-settings-card idt-danger-zone"
      data-testid="idt-danger-zone"
    >
      <div>
        <h3 id="idt-danger-zone-title">Danger zone</h3>
        {description ? <p className="idt-danger-zone-description">{description}</p> : null}
      </div>
      <div className="idt-danger-zone-rows">{children}</div>
    </section>
  );
}

type DangerZoneRowProps = {
  title: string;
  description?: string;
  actionLabel: string;
  onAction: () => void;
  disabled?: boolean;
  pending?: boolean;
  testId?: string;
};

export function DangerZoneRow({
  title,
  description,
  actionLabel,
  onAction,
  disabled,
  pending,
  testId
}: DangerZoneRowProps) {
  return (
    <article className="idt-danger-zone-row" data-testid={testId}>
      <div>
        <strong>{title}</strong>
        {description ? <p>{description}</p> : null}
      </div>
      <button
        className="idt-btn idt-btn-danger"
        disabled={disabled || pending}
        onClick={onAction}
        type="button"
      >
        {pending ? 'Working…' : actionLabel}
      </button>
    </article>
  );
}

type DangerConfirmation =
  | { kind: 'checkbox'; label: string }
  | { kind: 'type-to-confirm'; expectedValue: string; inputLabel: ReactNode; helpText?: ReactNode };

type ConfirmDestructiveModalProps = {
  open: boolean;
  title: string;
  body: ReactNode;
  confirmation: DangerConfirmation;
  continueLabel: string;
  cancelLabel?: string;
  errorMessage?: string;
  pending?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
};

export function ConfirmDestructiveModal({
  open,
  title,
  body,
  confirmation,
  continueLabel,
  cancelLabel = 'Cancel',
  errorMessage,
  pending,
  onCancel,
  onConfirm
}: ConfirmDestructiveModalProps) {
  const titleId = useId();
  const inputId = useId();
  const helpId = useId();
  const [checked, setChecked] = useState(false);
  const [typed, setTyped] = useState('');
  const [holding, setHolding] = useState(false);
  const [rejectedHold, setRejectedHold] = useState(false);
  const confirmRef = useRef<HTMLButtonElement | null>(null);
  const holdTimerRef = useRef<number | null>(null);
  const rejectTimerRef = useRef<number | null>(null);
  // Tracks whether the current activation was initiated through the
  // pointer/keyboard hold flow. If a click arrives without this flag set
  // (assistive tech, voice control, programmatic .click()), we fall back to
  // a direct confirmation so those flows remain operable.
  const holdInteractionRef = useRef(false);

  const clearHoldTimer = useCallback(() => {
    if (holdTimerRef.current !== null) {
      window.clearTimeout(holdTimerRef.current);
      holdTimerRef.current = null;
    }
  }, []);

  const clearRejectTimer = useCallback(() => {
    if (rejectTimerRef.current !== null) {
      window.clearTimeout(rejectTimerRef.current);
      rejectTimerRef.current = null;
    }
  }, []);

  // Reset confirmation state every time the modal opens so a previously
  // accepted checkbox or typed value does not silently re-arm Continue on the
  // next destructive action.
  useEffect(() => {
    if (!open) {
      // The component can stay mounted across an open→close transition (the
      // parent re-renders with open=false). Any hold timer started before the
      // close would otherwise still fire onConfirm after the destructive
      // dialog was dismissed.
      clearHoldTimer();
      clearRejectTimer();
      return;
    }
    setChecked(false);
    setTyped('');
    setHolding(false);
    setRejectedHold(false);
    holdInteractionRef.current = false;
    clearHoldTimer();
    clearRejectTimer();
  }, [clearHoldTimer, clearRejectTimer, open]);

  useEffect(() => {
    return () => {
      clearHoldTimer();
      clearRejectTimer();
    };
  }, [clearHoldTimer, clearRejectTimer]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handler = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onCancel();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onCancel]);

  if (!open) {
    return null;
  }

  // Type-to-confirm intentionally compares the raw input to the expected
  // value without trimming. Pasted leading/trailing whitespace on identifiers
  // like emails or workspace slugs must keep the destructive action gated —
  // trimming here would defeat the whole purpose of the friction.
  const canContinue =
    confirmation.kind === 'checkbox' ? checked : typed === confirmation.expectedValue;

  const startConfirmHold = () => {
    if (!canContinue || pending || holdTimerRef.current !== null) {
      return;
    }
    clearRejectTimer();
    setRejectedHold(false);
    setHolding(true);
    holdTimerRef.current = window.setTimeout(() => {
      holdTimerRef.current = null;
      setHolding(false);
      onConfirm();
    }, HOLD_TO_CONFIRM_MS);
  };

  const cancelConfirmHold = (showRejection = true) => {
    if (holdTimerRef.current === null) {
      return;
    }
    clearHoldTimer();
    setHolding(false);
    if (!showRejection) {
      return;
    }
    setRejectedHold(true);
    clearRejectTimer();
    rejectTimerRef.current = window.setTimeout(() => {
      rejectTimerRef.current = null;
      setRejectedHold(false);
    }, HOLD_REJECT_RESET_MS);
  };

  const confirmButtonClassName = [
    'idt-btn',
    'idt-btn-danger',
    'idt-hold-confirm',
    holding ? 'is-holding' : '',
    rejectedHold ? 'is-rejected' : ''
  ].filter(Boolean).join(' ');

  return (
    <div className="idt-modal-backdrop idt-danger-modal-backdrop" role="presentation" onClick={onCancel}>
      <section
        aria-labelledby={titleId}
        aria-modal="true"
        className="idt-danger-modal"
        data-testid="idt-danger-modal"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
      >
        <header>
          <div>
            <h3 id={titleId}>{title}</h3>
          </div>
          <button
            aria-label="Close confirmation"
            className="idt-esc-close"
            onClick={onCancel}
            type="button"
          >
            ESC
          </button>
        </header>

        <div className="idt-danger-modal-body">{body}</div>

        {confirmation.kind === 'checkbox' ? (
          <label className="idt-danger-modal-checkbox">
            <input
              checked={checked}
              data-testid="idt-danger-modal-checkbox"
              onChange={(event) => setChecked(event.target.checked)}
              type="checkbox"
            />
            <span>{confirmation.label}</span>
          </label>
        ) : (
          <div className="idt-danger-modal-typed">
            <label htmlFor={inputId}>{confirmation.inputLabel}</label>
            {confirmation.helpText ? (
              <p className="idt-danger-modal-help" id={helpId}>
                {confirmation.helpText}
              </p>
            ) : null}
            <input
              aria-describedby={confirmation.helpText ? helpId : undefined}
              autoComplete="off"
              data-testid="idt-danger-modal-typed"
              id={inputId}
              onChange={(event) => setTyped(event.target.value)}
              spellCheck={false}
              type="text"
              value={typed}
            />
          </div>
        )}

        {errorMessage ? (
          <p className="idt-danger-modal-error" role="alert">
            {errorMessage}
          </p>
        ) : null}

        <footer className="idt-danger-modal-actions">
          <button
            className="idt-btn idt-btn-ghost"
            disabled={pending}
            onClick={onCancel}
            type="button"
          >
            {cancelLabel}
          </button>
          <button
            className={confirmButtonClassName}
            data-testid="idt-danger-modal-continue"
            disabled={!canContinue || pending}
            onClick={(event) => {
              event.preventDefault();
              if (holdInteractionRef.current) {
                holdInteractionRef.current = false;
                return;
              }
              if (!canContinue || pending) {
                return;
              }
              onConfirm();
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                holdInteractionRef.current = true;
                startConfirmHold();
              }
            }}
            onKeyUp={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                cancelConfirmHold();
              }
            }}
            onPointerCancel={() => cancelConfirmHold(false)}
            onPointerDown={(event) => {
              if (event.button !== 0) {
                return;
              }
              holdInteractionRef.current = true;
              startConfirmHold();
            }}
            onPointerLeave={() => cancelConfirmHold(false)}
            onPointerUp={() => cancelConfirmHold()}
            ref={confirmRef}
            type="button"
          >
            <span>{pending ? 'Working…' : canContinue ? `Hold ${continueLabel}` : continueLabel}</span>
          </button>
        </footer>
      </section>
    </div>
  );
}
