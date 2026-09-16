import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { HeroProductReveal } from './HeroProductReveal';

describe('HeroProductReveal', () => {
  it('labels the preview as illustrative and keeps each review step visible', () => {
    render(<HeroProductReveal />);

    expect(screen.getByText('Example workspace')).toBeInTheDocument();
    expect(screen.queryByText('AWS IAM live')).not.toBeInTheDocument();
    expect(screen.queryByText('Evidence ready')).not.toBeInTheDocument();
    expect(screen.queryByText('Critical path')).not.toBeInTheDocument();
    expect(screen.queryByText('PostgreSQL billing ledger')).not.toBeInTheDocument();
    expect(screen.getByText('RDS billing-ledger')).toBeInTheDocument();
    expect(screen.getByText('No critical workload impact predicted')).toBeInTheDocument();

    expect(screen.getByText('3/4')).toBeInTheDocument();

    const steps = screen.getByRole('list', { name: 'Kubernetes review steps' });
    expect(within(steps).getAllByRole('listitem')).toHaveLength(4);
  });
});
