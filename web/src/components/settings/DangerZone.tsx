import { ReactNode, useEffect, useId, useRef, useState } from 'react';

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
        <p className="idt-app-kicker">Danger zone</p>
        <h3 id="idt-danger-zone-title">Account lifecycle</h3>
        {description ? <p className="idt-danger-zone-description">{description}</p> : null}
      </div>
      <div className="idt-danger-zone-rows">{children}</div>
    </section>
  );
}

type DangerZoneRowProps = {
  title: string;
  description: string;
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
        <p>{description}</p>
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
  | { kind: 'type-to-confirm'; expectedValue: string; inputLabel: string; helpText?: string };

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
  const confirmRef = useRef<HTMLButtonElement | null>(null);

  // Reset confirmation state every time the modal opens so a previously
  // accepted checkbox or typed value does not silently re-arm Continue on the
  // next destructive action.
  useEffect(() => {
    if (open) {
      setChecked(false);
      setTyped('');
    }
  }, [open]);

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

  return (
    <div className="idt-modal-backdrop" role="presentation" onClick={onCancel}>
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
            <p className="idt-app-kicker">Confirm destructive action</p>
            <h3 id={titleId}>{title}</h3>
          </div>
          <button
            aria-label="Close confirmation"
            className="idt-icon-btn"
            onClick={onCancel}
            type="button"
          >
            x
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
            <p className="idt-danger-modal-expected">
              Type <code>{confirmation.expectedValue}</code> exactly to enable the action.
            </p>
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
            className="idt-btn idt-btn-danger"
            data-testid="idt-danger-modal-continue"
            disabled={!canContinue || pending}
            onClick={onConfirm}
            ref={confirmRef}
            type="button"
          >
            {pending ? 'Working…' : continueLabel}
          </button>
        </footer>
      </section>
    </div>
  );
}
