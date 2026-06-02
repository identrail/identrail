import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConfirmDestructiveModal, DangerZone, DangerZoneRow } from './DangerZone';

describe('DangerZone', () => {
  it('renders the heading, description, and row children', () => {
    render(
      <DangerZone description="Heads up, destructive stuff lives here.">
        <DangerZoneRow
          actionLabel="Suspend"
          description="Sign out everywhere."
          onAction={() => undefined}
          title="Account access"
        />
      </DangerZone>
    );

    expect(screen.getByRole('heading', { name: 'Danger zone' })).toBeInTheDocument();
    expect(screen.getByText('Heads up, destructive stuff lives here.')).toBeInTheDocument();
    expect(screen.getByText('Account access')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Suspend' })).toBeEnabled();
  });

  it('invokes the row callback when the action button is clicked', () => {
    const handler = vi.fn();
    render(
      <DangerZone>
        <DangerZoneRow actionLabel="Suspend" description="" onAction={handler} title="Suspend" />
      </DangerZone>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Suspend' }));
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('shows pending state and disables the row button while working', () => {
    const handler = vi.fn();
    render(
      <DangerZone>
        <DangerZoneRow actionLabel="Suspend" description="" onAction={handler} pending title="Suspend" />
      </DangerZone>
    );

    const button = screen.getByRole('button', { name: 'Working…' });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(handler).not.toHaveBeenCalled();
  });
});

describe('ConfirmDestructiveModal — checkbox confirmation', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function renderCheckboxModal(overrides?: Partial<Parameters<typeof ConfirmDestructiveModal>[0]>) {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <ConfirmDestructiveModal
        body={<p>This is permanent-ish.</p>}
        confirmation={{ kind: 'checkbox', label: 'I understand.' }}
        continueLabel="Suspend"
        onCancel={onCancel}
        onConfirm={onConfirm}
        open
        title="Suspend your account"
        {...overrides}
      />
    );
    return { onConfirm, onCancel };
  }

  it('keeps Continue disabled until the checkbox is checked, then completes via a pointer hold', () => {
    const { onConfirm } = renderCheckboxModal();
    const cont = screen.getByRole('button', { name: 'Suspend' });
    expect(cont).toBeDisabled();
    fireEvent.click(cont);
    expect(onConfirm).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('checkbox'));
    const armed = screen.getByRole('button', { name: 'Hold Suspend' });
    expect(armed).toBeEnabled();
    fireEvent.pointerDown(armed, { button: 0 });
    act(() => {
      vi.advanceTimersByTime(899);
    });
    expect(onConfirm).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('cancels a pending hold timer when the modal closes mid-hold', () => {
    // Regression: if the destructive dialog is dismissed (Escape/Cancel or a
    // parent state change) while a hold is in progress, the pending 900ms
    // timeout must not fire onConfirm after the modal has been closed.
    const onConfirm = vi.fn();
    const { rerender } = render(
      <ConfirmDestructiveModal
        body={<p>This is permanent-ish.</p>}
        confirmation={{ kind: 'checkbox', label: 'I understand.' }}
        continueLabel="Suspend"
        onCancel={() => undefined}
        onConfirm={onConfirm}
        open
        title="Suspend your account"
      />
    );
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.pointerDown(screen.getByRole('button', { name: 'Hold Suspend' }), { button: 0 });
    act(() => {
      vi.advanceTimersByTime(400);
    });

    rerender(
      <ConfirmDestructiveModal
        body={<p>This is permanent-ish.</p>}
        confirmation={{ kind: 'checkbox', label: 'I understand.' }}
        continueLabel="Suspend"
        onCancel={() => undefined}
        onConfirm={onConfirm}
        open={false}
        title="Suspend your account"
      />
    );
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('confirms on a bare click so assistive-tech activations remain operable', () => {
    // Assistive tech (screen readers, voice control) often activates buttons
    // by dispatching a click without any preceding pointerdown/keydown. The
    // hold gate would lock those users out of the destructive flow, so a
    // bare click after the checkbox guard must still confirm.
    const { onConfirm } = renderCheckboxModal();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Hold Suspend' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('does not confirm when the hold is released early', () => {
    const { onConfirm } = renderCheckboxModal();
    fireEvent.click(screen.getByRole('checkbox'));

    const cont = screen.getByRole('button', { name: 'Hold Suspend' });
    fireEvent.pointerDown(cont, { button: 0 });
    act(() => {
      vi.advanceTimersByTime(400);
    });
    fireEvent.pointerUp(cont);
    act(() => {
      vi.advanceTimersByTime(900);
    });

    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('invokes Cancel when the backdrop is clicked', () => {
    const { onCancel } = renderCheckboxModal();
    // Click the backdrop (parent of the dialog). The dialog itself stops
    // propagation so clicks inside should not bubble.
    fireEvent.click(screen.getByRole('dialog').parentElement!);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('renders an error message and keeps Cancel enabled when pending=false', () => {
    renderCheckboxModal({ errorMessage: 'Something broke.', pending: false });
    expect(screen.getByRole('alert')).toHaveTextContent('Something broke.');
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled();
  });

  it('shows working state on Continue and disables both buttons when pending', () => {
    const { onConfirm } = renderCheckboxModal({ pending: true });
    fireEvent.click(screen.getByRole('checkbox'));
    const working = screen.getByRole('button', { name: 'Working…' });
    expect(working).toBeDisabled();
    fireEvent.click(working);
    expect(onConfirm).not.toHaveBeenCalled();
  });
});

describe('ConfirmDestructiveModal — type-to-confirm', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('only enables Continue when the typed value matches exactly', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDestructiveModal
        body={null}
        confirmation={{
          kind: 'type-to-confirm',
          expectedValue: 'user@example.com',
          inputLabel: 'Type your email'
        }}
        continueLabel="Delete"
        onCancel={() => undefined}
        onConfirm={onConfirm}
        open
        title="Delete account"
      />
    );

    const cont = screen.getByRole('button', { name: 'Delete' });
    expect(cont).toBeDisabled();

    const input = screen.getByLabelText('Type your email');
    fireEvent.change(input, { target: { value: 'user@example.co' } });
    expect(cont).toBeDisabled();

    fireEvent.change(input, { target: { value: 'user@example.com' } });
    const armed = screen.getByRole('button', { name: 'Hold Delete' });
    expect(armed).toBeEnabled();
    fireEvent.pointerDown(armed, { button: 0 });
    act(() => {
      vi.advanceTimersByTime(900);
    });
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('does not enable Continue when the typed value has stray whitespace', () => {
    // Regression: pasted leading/trailing whitespace must not satisfy the
    // type-to-confirm guard. Trimming either side would weaken irreversible
    // delete flows (e.g. an email or workspace slug copied with a trailing
    // space).
    const onConfirm = vi.fn();
    render(
      <ConfirmDestructiveModal
        body={null}
        confirmation={{
          kind: 'type-to-confirm',
          expectedValue: 'user@example.com',
          inputLabel: 'Type your email'
        }}
        continueLabel="Delete"
        onCancel={() => undefined}
        onConfirm={onConfirm}
        open
        title="Delete account"
      />
    );

    const cont = screen.getByRole('button', { name: 'Delete' });
    const input = screen.getByLabelText('Type your email');

    fireEvent.change(input, { target: { value: 'user@example.com ' } });
    expect(cont).toBeDisabled();
    fireEvent.change(input, { target: { value: ' user@example.com' } });
    expect(cont).toBeDisabled();
    fireEvent.change(input, { target: { value: '\tuser@example.com' } });
    expect(cont).toBeDisabled();

    fireEvent.click(cont);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('returns nothing when open=false', () => {
    const { container } = render(
      <ConfirmDestructiveModal
        body={null}
        confirmation={{ kind: 'checkbox', label: 'I am sure.' }}
        continueLabel="Go"
        onCancel={() => undefined}
        onConfirm={() => undefined}
        open={false}
        title="Closed"
      />
    );
    expect(container).toBeEmptyDOMElement();
  });
});
