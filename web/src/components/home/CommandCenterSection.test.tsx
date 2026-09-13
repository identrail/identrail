import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CommandCenterSection } from './CommandCenterSection';

describe('CommandCenterSection', () => {
  it('keeps the command center introduction to one focused headline', () => {
    render(<CommandCenterSection />);

    expect(
      screen.getByRole('heading', { name: 'One operating view for machine identity risk.' })
    ).toBeInTheDocument();
    expect(screen.queryByText('Trust operations layer')).not.toBeInTheDocument();
    expect(screen.queryByText(/same operating picture/)).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Triage' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Simulate' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Report' })).toBeInTheDocument();
  });
});
