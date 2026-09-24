import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ToggleGroup, ToggleGroupItem } from './toggle-group';

describe('ToggleGroup', () => {
  it('supports an uncontrolled default value and updates selection', () => {
    render(
      <ToggleGroup defaultValue="monthly" aria-label="Billing cadence">
        <ToggleGroupItem value="monthly">Monthly</ToggleGroupItem>
        <ToggleGroupItem value="annual">Annual</ToggleGroupItem>
      </ToggleGroup>
    );

    const monthly = screen.getByRole('button', { name: 'Monthly' });
    const annual = screen.getByRole('button', { name: 'Annual' });
    expect(monthly).toHaveAttribute('aria-pressed', 'true');
    expect(annual).toHaveAttribute('aria-pressed', 'false');

    fireEvent.click(annual);

    expect(monthly).toHaveAttribute('aria-pressed', 'false');
    expect(annual).toHaveAttribute('aria-pressed', 'true');
  });
});
