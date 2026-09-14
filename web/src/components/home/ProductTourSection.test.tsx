import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { ProductTourSection } from '../../App';

describe('ProductTourSection', () => {
  it('keeps the workflow focused on three clear stages', () => {
    render(<ProductTourSection />);

    expect(
      screen.getByRole('heading', { name: 'From read-only signals to a safe fix.' })
    ).toBeInTheDocument();

    const steps = screen.getByRole('list', { name: 'Identrail workflow steps' });
    expect(within(steps).getAllByRole('listitem')).toHaveLength(3);
    expect(within(steps).getByRole('heading', { name: 'Connect' })).toBeInTheDocument();
    expect(within(steps).getByRole('heading', { name: 'Trace' })).toBeInTheDocument();
    expect(within(steps).getByRole('heading', { name: 'Fix' })).toBeInTheDocument();

    expect(screen.getByRole('heading', { name: 'Billing ledger reachable' })).toBeInTheDocument();
    expect(screen.getByText('Read-only preview')).toBeInTheDocument();
    expect(screen.queryByText('Product tour')).not.toBeInTheDocument();
    expect(screen.queryByText('Production workspace')).not.toBeInTheDocument();
    expect(screen.queryByText('Evidence ready')).not.toBeInTheDocument();
    expect(screen.queryByText('Export the review bundle')).not.toBeInTheDocument();
  });
});
