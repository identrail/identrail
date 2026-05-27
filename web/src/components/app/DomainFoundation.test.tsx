import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import {
  DomainActionFooter,
  DomainDataTable,
  DomainDetailPanel,
  DomainEmptyState,
  DomainErrorState,
  DomainEvidencePanel,
  DomainFilterBar,
  DomainHeader,
  DomainKpiStrip,
  DomainLoadingState,
  DomainLogoMark,
  DomainLogoStack,
  DomainPageShell,
  DomainStatusPanel,
  DomainSubnav
} from './DomainFoundation';

describe('DomainFoundation', () => {
  it('renders meaningful and decorative official domain marks accessibly', () => {
    const { container } = render(
      <>
        <DomainLogoMark domain="aws" />
        <DomainLogoMark domain="github" decorative />
      </>
    );

    expect(screen.getByRole('img', { name: 'AWS' })).toBeInTheDocument();
    expect(screen.queryByRole('img', { name: 'GitHub' })).not.toBeInTheDocument();
    expect(container.querySelector('img[src="/brand-logos/aws.svg"]')).toBeInTheDocument();
    expect(container.querySelector('.idt-domain-logo-mark.is-github')).toHaveAttribute('aria-hidden', 'true');
  });

  it('renders the provider logo stack through the same domain registry', () => {
    render(<DomainLogoStack domains={['aws', 'github', 'kubernetes']} label="Machine identity surfaces" />);

    const stack = screen.getByRole('group', { name: 'Machine identity surfaces' });
    expect(stack.querySelectorAll('.idt-domain-logo-mark')).toHaveLength(3);
  });

  it('provides a reusable domain page shell with header, actions, subnav, content, and aside', () => {
    render(
      <MemoryRouter>
        <DomainPageShell
          domain="aws"
          eyebrow="AWS Control Center"
          title="AWS machine identities"
          description="Connect accounts, inspect machine identities, and triage cloud findings."
          scope={<span>Production account</span>}
          status={<span>Healthy</span>}
          statusTone="success"
          primaryAction={{ label: 'Connect AWS', to: '/connect/aws', variant: 'primary' }}
          secondaryActions={[{ label: 'Refresh', onClick: vi.fn() }]}
          subnav={[
            {
              id: 'inventory',
              label: 'Inventory',
              defaultOpen: true,
              children: [
                { id: 'roles', label: 'Roles', to: '/aws/roles', active: true },
                { id: 'agents', label: 'Agents', to: '/aws/agents', badge: 'Soon' }
              ]
            },
            { id: 'findings', label: 'Findings', to: '/aws/findings', status: '7 open' }
          ]}
          aside={<DomainDetailPanel title="Coverage">3 regions scanned</DomainDetailPanel>}
        >
          <DomainKpiStrip items={[{ label: 'Identities', value: '128', detail: 'Across 3 accounts' }]} />
        </DomainPageShell>
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: 'AWS machine identities' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Connect AWS' })).toHaveAttribute('href', '/connect/aws');
    expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Domain sections' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Roles' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getByText('3 regions scanned')).toBeInTheDocument();
    expect(screen.getByText('128')).toBeInTheDocument();
  });

  it('renders subsection navigation groups as native collapsible sections', () => {
    const { container } = render(
      <MemoryRouter>
        <DomainSubnav
          label="GitHub sections"
          items={[
            {
              id: 'agentic-risk',
              label: 'AI / Agentic Risk',
              badge: 'GitHub',
              defaultOpen: false,
              children: [{ id: 'tools', label: 'MCP / tools / secrets', to: '/github/agentic-risk/tools' }]
            }
          ]}
        />
      </MemoryRouter>
    );

    const details = container.querySelector('details.idt-domain-subnav-group');
    expect(details).toBeInTheDocument();
    expect(details).not.toHaveAttribute('open');
    expect(screen.getByText('AI / Agentic Risk')).toBeInTheDocument();
  });

  it('auto-opens parent subnav when a nested child is active', () => {
    const { container } = render(
      <MemoryRouter>
        <DomainSubnav
          label="GitHub sections"
          items={[
            {
              id: 'agentic-risk',
              label: 'AI / Agentic Risk',
              children: [{ id: 'tools', label: 'MCP / tools / secrets', to: '/github/agentic-risk/tools', active: true }]
            }
          ]}
        />
      </MemoryRouter>
    );

    expect(container.querySelector('details.idt-domain-subnav-group')).toHaveAttribute('open');
  });

  it('covers operational states, dense tables, filters, evidence, and action footers', () => {
    render(
      <MemoryRouter>
        <DomainHeader
          domain="github"
          title="GitHub posture"
          description="Repository-native security posture."
          status="Degraded"
          statusTone="warning"
        />
        <DomainStatusPanel title="Collector health" status="Healthy" tone="success">
          Webhook delivery is current.
        </DomainStatusPanel>
        <DomainFilterBar>
          <label>
            Search
            <input aria-label="Search identities" />
          </label>
        </DomainFilterBar>
        <DomainDataTable
          label="Identity inventory"
          columns={[
            { key: 'name', header: 'Identity', render: (row: { id: string; name: string }) => row.name },
            { key: 'risk', header: 'Risk', align: 'right', render: () => 'High' }
          ]}
          rows={[{ id: 'role-1', name: 'Deploy role' }]}
          getRowKey={(row) => row.id}
        />
        <DomainDataTable
          label="Empty inventory"
          columns={[{ key: 'name', header: 'Identity', render: (row: { id: string; name: string }) => row.name }]}
          rows={[]}
          getRowKey={(row) => row.id}
        />
        <DomainEmptyState title="Nothing connected" body="Connect a provider to begin." />
        <DomainErrorState title="Sync failed" body="Retry the collector." />
        <DomainLoadingState label="Loading GitHub repositories" />
        <DomainEvidencePanel title="Trust policy evidence" code={'{"Effect":"Allow"}'} language="json" />
        <DomainActionFooter>
          <button type="button">Approve plan</button>
        </DomainActionFooter>
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: 'GitHub posture' })).toBeInTheDocument();
    expect(screen.getByText('Webhook delivery is current.')).toBeInTheDocument();
    expect(screen.getByRole('search', { name: 'Filter domain data' })).toBeInTheDocument();
    expect(within(screen.getByRole('table', { name: 'Identity inventory' })).getByText('Deploy role')).toBeInTheDocument();
    expect(screen.getByText('No records yet')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Sync failed');
    expect(screen.getByRole('status')).toHaveTextContent('Loading GitHub repositories');
    expect(screen.getByText('{"Effect":"Allow"}')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve plan' })).toBeInTheDocument();
  });

  it('always prevents native submit in filter bar handlers', () => {
    let eventWasPrevented = false;
    const handleSubmit = vi.fn((event: { defaultPrevented: boolean }) => {
      eventWasPrevented = event.defaultPrevented;
    });

    render(<DomainFilterBar onSubmit={handleSubmit} />);

    fireEvent.submit(screen.getByRole('search', { name: 'Filter domain data' }));
    expect(handleSubmit).toHaveBeenCalledTimes(1);
    expect(eventWasPrevented).toBe(true);
  });
});
