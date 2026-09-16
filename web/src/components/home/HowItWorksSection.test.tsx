import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { HowItWorksSection } from './HowItWorksSection';

describe('HowItWorksSection', () => {
  it('uses concise, current workflow language', () => {
    render(<HowItWorksSection />);

    expect(screen.getByRole('heading', { name: 'From evidence to the first safe fix' })).toBeInTheDocument();
    expect(screen.getByText('Each stage produces a reviewable artifact before any change is approved.')).toBeInTheDocument();
    expect(screen.getByText('Score findings by severity, confidence, and production blast radius.')).toBeInTheDocument();
    expect(screen.queryByText(/^Output:/)).not.toBeInTheDocument();
  });
});
