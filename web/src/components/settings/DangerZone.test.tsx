import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
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

  it('keeps Continue disabled until the checkbox is checked', () => {
    const { onConfirm } = renderCheckboxModal();
    const cont = screen.getByRole('button', { name: 'Suspend' });
    expect(cont).toBeDisabled();
    fireEvent.click(cont);
    expect(onConfirm).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('checkbox'));
    expect(cont).toBeEnabled();
    fireEvent.click(cont);
    expect(onConfirm).toHaveBeenCalledTimes(1);
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
    expect(cont).toBeEnabled();
    fireEvent.click(cont);
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
