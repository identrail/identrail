import { fireEvent, render, screen } from '@testing-library/react';
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

  it('supports roving keyboard navigation and activates the focused view', () => {
    render(<CommandCenterSection />);

    const triageTab = screen.getByRole('tab', { name: 'Triage' });
    const simulateTab = screen.getByRole('tab', { name: 'Simulate' });
    const reportTab = screen.getByRole('tab', { name: 'Report' });

    expect(triageTab).toHaveAttribute('tabIndex', '0');
    expect(simulateTab).toHaveAttribute('tabIndex', '-1');
    simulateTab.focus();
    fireEvent.keyDown(simulateTab, { key: 'ArrowRight' });

    expect(reportTab).toHaveFocus();
    expect(reportTab).toHaveAttribute('aria-selected', 'true');
    expect(reportTab).toHaveAttribute('tabIndex', '0');
    expect(simulateTab).toHaveAttribute('tabIndex', '-1');
    expect(screen.getByRole('tabpanel').querySelector('h3')).toHaveTextContent(
      'Package remediation progress for security, platform, and leadership.'
    );

    fireEvent.keyDown(reportTab, { key: 'Home' });
    expect(triageTab).toHaveFocus();
    expect(triageTab).toHaveAttribute('aria-selected', 'true');
  });
});
