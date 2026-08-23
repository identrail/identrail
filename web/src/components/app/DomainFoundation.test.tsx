import { useState } from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import {
  DomainActionFooter,
  DomainCoverageCard,
  DomainDataTable,
  DomainDetailDrawer,
  DomainDetailPanel,
  DomainEmptyState,
  DomainErrorState,
  DomainEvidencePanel,
  DomainFilterBar,
  DomainFindingSummaryCard,
  DomainGraphPlaceholder,
  DomainHeader,
  DomainKpiStrip,
  DomainLoadingState,
  DomainLogoMark,
  DomainLogoStack,
  DomainPageShell,
  DomainRemediationQueue,
  DomainSortControl,
  DomainStatusBadge,
  DomainStatusPanel,
  DomainSubnav,
  DomainTimeline,
  domainStatusTone
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

  it('renders typed domain status badges with semantic tones', () => {
    render(
      <>
        <DomainStatusBadge variant="connected" />
        <DomainStatusBadge variant="degraded" detail="Webhook lag 8s" />
        <DomainStatusBadge variant="missing-permissions" />
        <DomainStatusBadge variant="running-scan" />
        <DomainStatusBadge variant="coming-soon" />
      </>
    );

    expect(screen.getByText('Connected').closest('.idt-domain-status-badge')).toHaveClass('is-success');
    expect(screen.getByText('Degraded').closest('.idt-domain-status-badge')).toHaveClass('is-warning');
    expect(screen.getByText('Missing permissions').closest('.idt-domain-status-badge')).toHaveClass('is-danger');
    expect(screen.getByText('Running scan').closest('.idt-domain-status-badge')).toHaveClass('is-info');
    expect(screen.getByText('Webhook lag 8s')).toBeInTheDocument();
    expect(domainStatusTone('connected')).toBe('success');
    expect(domainStatusTone('missing-permissions')).toBe('danger');
  });

  it('exposes empty next action and error retry action as primary controls', () => {
    const onRetry = vi.fn();
    const onConnect = vi.fn();

    render(
      <MemoryRouter>
        <DomainEmptyState
          title="No identities yet"
          body="Connect an AWS account to begin."
          nextAction={{ label: 'Connect AWS', onClick: onConnect }}
        />
        <DomainErrorState title="Sync failed" body="Reach out if this persists." retryAction={{ label: 'Retry sync', onClick: onRetry }} />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Connect AWS' }));
    fireEvent.click(screen.getByRole('button', { name: 'Retry sync' }));
    expect(onConnect).toHaveBeenCalledTimes(1);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('renders coverage cards with a labeled progress bar', () => {
    render(<DomainCoverageCard label="Accounts" scanned={3} total={4} detail="us-east, us-west" />);

    const progress = screen.getByRole('progressbar', { name: /accounts coverage/i });
    expect(progress).toHaveAttribute('aria-valuenow', '3');
    expect(progress).toHaveAttribute('aria-valuemax', '4');
    expect(screen.getByText('75%')).toBeInTheDocument();
    expect(screen.getByText(/3 of 4 scanned/)).toBeInTheDocument();
  });

  it('renders finding summary cards with severity, count, and navigation', () => {
    render(
      <MemoryRouter>
        <DomainFindingSummaryCard severity="critical" count={4} to="/aws/findings?severity=critical" />
        <DomainFindingSummaryCard severity="medium" count={12} trend="+3 this week" />
      </MemoryRouter>
    );

    const link = screen.getByRole('link', { name: '4 Critical findings' });
    expect(link).toHaveAttribute('href', '/aws/findings?severity=critical');
    expect(screen.getByText('+3 this week')).toBeInTheDocument();
  });

  it('renders the timeline as an ordered list with semantic entries', () => {
    render(
      <DomainTimeline
        label="Scan history"
        entries={[
          { id: 'a', timestamp: '12:01', title: 'Scan started', actor: 'collector' },
          { id: 'b', timestamp: '12:04', title: 'Findings published', detail: '7 new', tone: 'success' }
        ]}
      />
    );

    const list = screen.getByRole('list', { name: 'Scan history' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(2);
    expect(within(list).getByText('Findings published')).toBeInTheDocument();
    expect(within(list).getByText('collector')).toBeInTheDocument();
  });

  it('renders a graph placeholder region with an inline call to action', () => {
    render(
      <MemoryRouter>
        <DomainGraphPlaceholder
          title="Trust graph coming soon"
          description="Cross-account trust will appear once collectors complete."
          action={{ label: 'See sample graph', href: '/docs/graph' }}
        />
      </MemoryRouter>
    );

    expect(screen.getByRole('region', { name: 'Trust graph coming soon' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'See sample graph' })).toHaveAttribute('href', '/docs/graph');
  });

  it('renders the remediation queue with action affordances and an empty fallback', () => {
    const approve = vi.fn();
    render(
      <MemoryRouter>
        <DomainRemediationQueue
          items={[
            {
              id: 'q1',
              title: 'Rotate access key AKIA…',
              detail: 'Last used 142 days ago',
              severity: 'high',
              owner: 'sec-platform',
              primaryAction: { label: 'Approve', onClick: approve },
              secondaryAction: { label: 'Defer', onClick: vi.fn() }
            }
          ]}
        />
        <DomainRemediationQueue label="Cleared queue" items={[]} />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    expect(approve).toHaveBeenCalledTimes(1);
    expect(screen.getByText('sec-platform')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Cleared queue' })).toHaveTextContent('Queue is clear');
  });

  it('lets sort controls flip direction without changing the key', () => {
    const onChange = vi.fn();
    render(
      <DomainSortControl
        options={[
          { key: 'risk', label: 'Risk' },
          { key: 'updated', label: 'Updated' }
        ]}
        value="risk"
        direction="desc"
        onChange={onChange}
      />
    );

    fireEvent.click(screen.getByRole('button', { name: /sort direction: descending/i }));
    expect(onChange).toHaveBeenCalledWith({ key: 'risk', direction: 'asc' });
  });

  it('focuses the drawer and closes via the explicit close affordance', () => {
    const onClose = vi.fn();
    render(
      <DomainDetailDrawer open title="Identity detail" eyebrow="Inventory" onClose={onClose} footer={<button type="button">Approve</button>}>
        <p>Identity payload</p>
        <a href="/inventory">View inventory</a>
      </DomainDetailDrawer>
    );

    expect(screen.getByRole('dialog', { name: 'Identity detail' })).toBeInTheDocument();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Close detail drawer' }));
    fireEvent.click(screen.getByRole('button', { name: 'Close detail drawer' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('closes the drawer on Escape and traps Tab inside its contents', () => {
    const onClose = vi.fn();
    render(
      <DomainDetailDrawer open title="Identity detail" onClose={onClose} footer={<button type="button">Approve</button>}>
        <a href="/inventory">View inventory</a>
      </DomainDetailDrawer>
    );

    const dialog = screen.getByRole('dialog', { name: 'Identity detail' });
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);

    const closeButton = screen.getByRole('button', { name: 'Close detail drawer' });
    const approveButton = screen.getByRole('button', { name: 'Approve' });
    approveButton.focus();
    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement).toBe(closeButton);

    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(approveButton);
  });

  it('does not trap focus on a hidden resize handle', () => {
    render(
      <DomainDetailDrawer open title="Identity detail" onClose={() => undefined} resizable footer={<button type="button">Approve</button>}>
        <a href="/inventory">View inventory</a>
      </DomainDetailDrawer>
    );

    const dialog = screen.getByRole('dialog', { name: 'Identity detail' });
    const closeButton = screen.getByRole('button', { name: 'Close detail drawer' });
    const approveButton = screen.getByRole('button', { name: 'Approve' });
    const resizeHandle = screen.getByRole('button', { name: 'Resize detail drawer' });
    resizeHandle.style.display = 'none';

    approveButton.focus();
    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement).toBe(closeButton);

    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(approveButton);
  });

  it('restores focus to the prior element when the drawer closes', () => {
    function Host() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Open
          </button>
          <DomainDetailDrawer open={open} title="Identity detail" onClose={() => setOpen(false)}>
            <p>payload</p>
          </DomainDetailDrawer>
        </>
      );
    }
    render(<Host />);

    const opener = screen.getByRole('button', { name: 'Open' });
    opener.focus();
    fireEvent.click(opener);
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Close detail drawer' }));
    expect(document.activeElement).toBe(opener);
  });

  it('supports expanding and keyboard resizing the detail drawer', () => {
    const { unmount } = render(
      <DomainDetailDrawer open title="Identity detail" onClose={() => undefined} resizable expandable>
        <p>Identity payload</p>
      </DomainDetailDrawer>
    );

    const drawer = screen.getByText('Identity payload').closest<HTMLElement>('.idt-domain-drawer')!;
    const expandButton = screen.getByRole('button', { name: 'Expand detail drawer' });
    expect(drawer).not.toHaveClass('is-expanded');
    expect(document.body.style.overflow).toBe('hidden');

    Object.defineProperty(drawer, 'getBoundingClientRect', {
      configurable: true,
      value: () => ({ width: 448 } as DOMRect)
    });

    const resizeHandle = screen.getByRole('button', { name: 'Resize detail drawer' });
    fireEvent.keyDown(resizeHandle, { key: 'ArrowLeft' });
    expect(drawer.style.getPropertyValue('--idt-domain-drawer-width')).toBe('472px');

    fireEvent.click(expandButton);
    expect(drawer).toHaveClass('is-expanded');
    expect(drawer.style.getPropertyValue('--idt-domain-drawer-width')).toBe('');
    expect(screen.getByRole('button', { name: 'Restore detail drawer' })).toBeInTheDocument();

    fireEvent.keyDown(resizeHandle, { key: 'ArrowLeft' });
    expect(drawer.style.getPropertyValue('--idt-domain-drawer-width')).toBe('472px');
    fireEvent.keyDown(resizeHandle, { key: 'ArrowRight' });
    expect(drawer.style.getPropertyValue('--idt-domain-drawer-width')).toBe('448px');

    fireEvent.click(screen.getByRole('button', { name: 'Restore detail drawer' }));
    expect(drawer).not.toHaveClass('is-expanded');
    expect(drawer.style.getPropertyValue('--idt-domain-drawer-width')).toBe('472px');

    unmount();
    expect(document.body.style.overflow).toBe('');
  });

  it('closes the drawer when swiped off screen on touch devices', () => {
    const onClose = vi.fn();
    render(
      <DomainDetailDrawer open title="Identity detail" onClose={onClose}>
        <p>payload</p>
      </DomainDetailDrawer>
    );

    const drawer = screen.getByText('payload').closest('.idt-domain-drawer')!;
    fireEvent.pointerDown(drawer, { button: 0, clientX: 20, clientY: 12, pointerId: 1, pointerType: 'touch' });
    fireEvent.pointerMove(drawer, { clientX: 180, clientY: 16, pointerId: 1, pointerType: 'touch' });
    fireEvent.pointerUp(drawer, { clientX: 180, clientY: 16, pointerId: 1, pointerType: 'touch' });

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not render the drawer when closed', () => {
    const { queryByRole } = render(
      <DomainDetailDrawer open={false} title="Hidden" onClose={() => undefined}>
        <p>nope</p>
      </DomainDetailDrawer>
    );
    expect(queryByRole('dialog')).toBeNull();
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
