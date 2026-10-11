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
    const exampleEyebrow = screen.getByRole('tabpanel').querySelector('p');
    expect(exampleEyebrow).toHaveTextContent('Exposure triage · Illustrative example');
    expect(exampleEyebrow?.querySelector('span')).toHaveAttribute('aria-hidden', 'true');

    fireEvent.click(screen.getByRole('tab', { name: 'Simulate' }));
    expect(screen.getByRole('tabpanel').querySelector('p')).toHaveTextContent('Policy simulation · Illustrative example');

    fireEvent.click(screen.getByRole('tab', { name: 'Report' }));
    expect(screen.getByRole('tabpanel').querySelector('p')).toHaveTextContent('Executive report · Illustrative example');
    expect(screen.getByRole('tabpanel').querySelector('p span[aria-hidden="true"]')).toHaveTextContent('·');
    expect(screen.getByRole('tabpanel').querySelector('h3')).toHaveTextContent(
      'Package remediation progress for security, platform, and leadership.'
    );
  });
});
