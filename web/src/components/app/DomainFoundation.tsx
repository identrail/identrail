import { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { CSSProperties, FormEvent, KeyboardEvent as ReactKeyboardEvent, PointerEvent as ReactPointerEvent, ReactNode } from 'react';
import { Link } from 'react-router';
import { DOMAIN_ASSET_ORDER, getDomainAsset, type DomainAssetKey } from '../../design/domainAssets';

type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info';

function classNames(values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ');
}

export function DomainLogoMark({
  domain,
  className = '',
  size = 'default',
  decorative = false,
  label
}: {
  domain: DomainAssetKey;
  className?: string;
  size?: 'compact' | 'default' | 'row' | 'hero';
  decorative?: boolean;
  label?: string;
}) {
  const asset = getDomainAsset(domain);
  const classes = classNames([
    'idt-domain-logo-mark',
    'idt-source-logo-mark',
    `is-${domain}`,
    size !== 'default' ? `is-${size}` : '',
    className
  ]);

  if (decorative) {
    return (
      <span className={classes} aria-hidden="true">
        <img src={asset.logoSrc} alt="" aria-hidden="true" loading="lazy" decoding="async" />
      </span>
    );
  }

  return (
    <span className={classes} role="img" aria-label={label ?? asset.label}>
      <img src={asset.logoSrc} alt="" aria-hidden="true" loading="lazy" decoding="async" />
    </span>
  );
}

export function DomainLogoStack({
  domains = DOMAIN_ASSET_ORDER,
  label = 'Domain coverage stack',
  className = ''
}: {
  domains?: readonly DomainAssetKey[];
  label?: string;
  className?: string;
}) {
  return (
    <div className={classNames(['idt-domain-logo-stack', 'idt-source-logo-stack', className])} role="group" aria-label={label}>
      {domains.map((domain) => (
        <DomainLogoMark key={domain} domain={domain} decorative />
      ))}
    </div>
  );
}

export type DomainAction = {
  id?: string;
  label: string;
  to?: string;
  href?: string;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'ghost';
  disabled?: boolean;
  ariaLabel?: string;
  target?: string;
  rel?: string;
  icon?: ReactNode;
};

function renderDomainAction(action: DomainAction, key: string) {
  const variant = action.variant === 'primary' ? 'idt-btn-primary' : action.variant === 'secondary' ? 'idt-btn-dark' : 'idt-btn-ghost';
  const className = classNames(['idt-btn', variant, 'idt-domain-action']);
  const content = (
    <>
      {action.icon ? <span className="idt-domain-action-icon" aria-hidden="true">{action.icon}</span> : null}
      <span>{action.label}</span>
    </>
  );

  if (action.disabled) {
    return (
      <span key={key} className={className} aria-disabled="true" role="link" aria-label={action.ariaLabel ?? action.label}>
        {content}
      </span>
    );
  }

  if (action.to) {
    return (
      <Link key={key} className={className} to={action.to} aria-label={action.ariaLabel}>
        {content}
      </Link>
    );
  }

  if (action.href) {
    return (
      <a
        key={key}
        className={className}
        href={action.href}
        target={action.target}
        rel={action.rel ?? (action.target === '_blank' ? 'noreferrer' : undefined)}
        aria-label={action.ariaLabel}
      >
        {content}
      </a>
    );
  }

  return (
    <button key={key} className={className} type="button" onClick={action.onClick} aria-label={action.ariaLabel}>
      {content}
    </button>
  );
}

export type DomainHeaderProps = {
  domain: DomainAssetKey;
  eyebrow?: string | null;
  title: string;
  description?: ReactNode;
  scope?: ReactNode;
  status?: ReactNode;
  statusTone?: Tone;
  primaryAction?: DomainAction;
  secondaryActions?: DomainAction[];
  titleId?: string;
  hideLogo?: boolean;
};

export function DomainHeader({
  domain,
  eyebrow,
  title,
  description,
  scope,
  status,
  statusTone = 'neutral',
  primaryAction,
  secondaryActions = [],
  titleId,
  hideLogo = false
}: DomainHeaderProps) {
  const asset = getDomainAsset(domain);
  const actions = primaryAction ? [primaryAction, ...secondaryActions] : secondaryActions;
  const resolvedEyebrow = eyebrow === null ? null : eyebrow ?? asset.description;
  const hasDescription = description !== undefined && description !== null && description !== '';

  return (
    <header className={classNames(['idt-domain-header', `is-${domain}`, hideLogo ? 'is-logoless' : ''])}>
      <div className="idt-domain-header-main">
        {hideLogo ? null : <DomainLogoMark domain={domain} size="hero" />}
        <div>
          {resolvedEyebrow ? <p className="idt-app-kicker">{resolvedEyebrow}</p> : null}
          <h2 id={titleId}>{title}</h2>
          {hasDescription ? <p>{description}</p> : null}
        </div>
      </div>
      <div className="idt-domain-header-aside">
        {scope ? <div className="idt-domain-scope-slot">{scope}</div> : null}
        {status ? <div className={classNames(['idt-domain-status-summary', `is-${statusTone}`])}>{status}</div> : null}
        {actions.length > 0 ? (
          <div className="idt-domain-header-actions">
            {actions.map((action, index) => renderDomainAction(action, action.id ?? `${action.label}-${index}`))}
          </div>
        ) : null}
      </div>
    </header>
  );
}

export type DomainSubnavItem = {
  id: string;
  label: string;
  to?: string;
  active?: boolean;
  badge?: string;
  status?: string;
  children?: DomainSubnavItem[];
  defaultOpen?: boolean;
};

function renderSubnavLabel(item: DomainSubnavItem) {
  return (
    <>
      <span>{item.label}</span>
      {item.badge ? <small>{item.badge}</small> : null}
      {item.status ? <em>{item.status}</em> : null}
    </>
  );
}

function hasActiveDescendant(item: DomainSubnavItem): boolean {
  return item.children?.some((child) => child.active || hasActiveDescendant(child)) ?? false;
}

function renderSubnavItem(item: DomainSubnavItem): ReactNode {
  if (item.children?.length) {
    const shouldOpen = item.defaultOpen || item.active || hasActiveDescendant(item);
    const detailsOpenProps = shouldOpen ? { open: true } : {};
    return (
      <details key={item.id} className="idt-domain-subnav-group" {...detailsOpenProps}>
        <summary>{renderSubnavLabel(item)}</summary>
        <div className="idt-domain-subnav-children">{item.children.map((child) => renderSubnavItem(child))}</div>
      </details>
    );
  }

  if (item.to) {
    return (
      <Link key={item.id} className={classNames(['idt-domain-subnav-item', item.active ? 'is-active' : ''])} to={item.to} aria-current={item.active ? 'page' : undefined}>
        {renderSubnavLabel(item)}
      </Link>
    );
  }

  return (
    <span key={item.id} className={classNames(['idt-domain-subnav-item', item.active ? 'is-active' : ''])}>
      {renderSubnavLabel(item)}
    </span>
  );
}

export function DomainSubnav({ label = 'Domain sections', items }: { label?: string; items: DomainSubnavItem[] }) {
  return (
    <nav className="idt-domain-subnav" aria-label={label}>
      {items.map((item) => renderSubnavItem(item))}
    </nav>
  );
}

export type DomainStatusVariant =
  | 'connected'
  | 'disconnected'
  | 'needs-attention'
  | 'degraded'
  | 'running-scan'
  | 'missing-permissions'
  | 'coming-soon';

const DOMAIN_STATUS_TONE: Record<DomainStatusVariant, Tone> = {
  connected: 'success',
  disconnected: 'neutral',
  'needs-attention': 'warning',
  degraded: 'warning',
  'running-scan': 'info',
  'missing-permissions': 'danger',
  'coming-soon': 'neutral'
};

const DOMAIN_STATUS_LABEL: Record<DomainStatusVariant, string> = {
  connected: 'Connected',
  disconnected: 'Disconnected',
  'needs-attention': 'Needs attention',
  degraded: 'Degraded',
  'running-scan': 'Running scan',
  'missing-permissions': 'Missing permissions',
  'coming-soon': 'Coming soon'
};

export function domainStatusTone(variant: DomainStatusVariant): Tone {
  return DOMAIN_STATUS_TONE[variant];
}

export function DomainStatusBadge({
  variant,
  label,
  detail
}: {
  variant: DomainStatusVariant;
  label?: string;
  detail?: ReactNode;
}) {
  const tone = DOMAIN_STATUS_TONE[variant];
  const text = label ?? DOMAIN_STATUS_LABEL[variant];
  return (
    <span
      className={classNames(['idt-domain-status-badge', `is-${variant}`, `is-${tone}`])}
      data-variant={variant}
      role="status"
      aria-label={detail ? `${text}. ${typeof detail === 'string' ? detail : ''}`.trim() : text}
    >
      <span aria-hidden="true" className="idt-domain-status-dot" />
      <strong>{text}</strong>
      {detail ? <span className="idt-domain-status-detail">{detail}</span> : null}
    </span>
  );
}

export type DomainPageShellProps = DomainHeaderProps & {
  subnav?: DomainSubnavItem[];
  subnavLabel?: string;
  aside?: ReactNode;
  children: ReactNode;
};

export function DomainPageShell({ subnav, subnavLabel, aside, children, ...headerProps }: DomainPageShellProps) {
  const generatedId = useId();
  const titleId = headerProps.titleId ?? `idt-domain-title-${generatedId}`;

  return (
    <section className={classNames(['idt-domain-page-shell', `is-${headerProps.domain}`])} aria-labelledby={titleId}>
      <DomainHeader {...headerProps} titleId={titleId} />
      <div className={classNames(['idt-domain-page-body', subnav?.length ? 'has-subnav' : '', aside ? 'has-aside' : ''])}>
        {subnav?.length ? <DomainSubnav label={subnavLabel} items={subnav} /> : null}
        <div className="idt-domain-page-content">{children}</div>
        {aside ? <aside className="idt-domain-page-aside">{aside}</aside> : null}
      </div>
    </section>
  );
}

export type DomainKpiItem = {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  tone?: Tone;
};

export function DomainKpiStrip({ label = 'Domain metrics', items }: { label?: string; items: DomainKpiItem[] }) {
  return (
    <section className="idt-domain-kpi-strip" aria-label={label}>
      {items.map((item) => (
        <article key={item.label} className={classNames(['idt-domain-kpi', item.tone ? `is-${item.tone}` : ''])}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
          {item.detail ? <p>{item.detail}</p> : null}
        </article>
      ))}
    </section>
  );
}

export function DomainStatusPanel({
  eyebrow,
  title,
  status,
  tone = 'neutral',
  children,
  actions
}: {
  eyebrow?: string;
  title: string;
  status?: ReactNode;
  tone?: Tone;
  children: ReactNode;
  actions?: DomainAction[];
}) {
  return (
    <article className={classNames(['idt-domain-status-panel', `is-${tone}`])}>
      <header>
        <div>
          {eyebrow ? <p className="idt-app-kicker">{eyebrow}</p> : null}
          <h3>{title}</h3>
        </div>
        {status ? <span>{status}</span> : null}
      </header>
      <div className="idt-domain-panel-body">{children}</div>
      {actions?.length ? (
        <footer>{actions.map((action, index) => renderDomainAction(action, action.id ?? `${action.label}-${index}`))}</footer>
      ) : null}
    </article>
  );
}

export function DomainEmptyState({
  eyebrow,
  title,
  body,
  nextAction,
  children
}: {
  eyebrow?: string;
  title: string;
  body: ReactNode;
  nextAction?: DomainAction;
  children?: ReactNode;
}) {
  return (
    <article className="idt-domain-empty-state">
      {eyebrow ? <p className="idt-app-kicker">{eyebrow}</p> : null}
      <h3>{title}</h3>
      <p>{body}</p>
      {nextAction || children ? (
        <div className="idt-inline-actions">
          {nextAction ? renderDomainAction({ variant: 'primary', ...nextAction }, 'next-action') : null}
          {children}
        </div>
      ) : null}
    </article>
  );
}

export function DomainErrorState({
  title,
  body,
  retryAction,
  children
}: {
  title: string;
  body: ReactNode;
  retryAction?: DomainAction;
  children?: ReactNode;
}) {
  return (
    <article className="idt-domain-error-state" role="alert">
      <p className="idt-app-kicker">Needs attention</p>
      <h3>{title}</h3>
      <p>{body}</p>
      {retryAction || children ? (
        <div className="idt-inline-actions">
          {retryAction ? renderDomainAction({ variant: 'primary', ...retryAction }, 'retry-action') : null}
          {children}
        </div>
      ) : null}
    </article>
  );
}

export function DomainLoadingState({ label = 'Loading domain data' }: { label?: string }) {
  return (
    <div className="idt-domain-loading-state" role="status" aria-live="polite">
      <span aria-hidden="true" />
      <p>{label}</p>
    </div>
  );
}

export function DomainFilterBar({
  label = 'Filter domain data',
  children,
  actions,
  onSubmit
}: {
  label?: string;
  children?: ReactNode;
  actions?: ReactNode;
  onSubmit?: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form
      className="idt-domain-filter-bar"
      role="search"
      aria-label={label}
      onSubmit={(event) => {
        event.preventDefault();
        if (onSubmit) {
          onSubmit(event);
        }
      }}
    >
      <div className="idt-domain-filter-fields">{children}</div>
      {actions ? <div className="idt-domain-filter-actions">{actions}</div> : null}
    </form>
  );
}

export type DomainDataTableColumn<Row> = {
  key: string;
  header: string;
  render: (row: Row) => ReactNode;
  align?: 'left' | 'right';
};

export function DomainDataTable<Row>({
  label,
  columns,
  rows,
  getRowKey,
  emptyState
}: {
  label: string;
  columns: DomainDataTableColumn<Row>[];
  rows: Row[];
  getRowKey: (row: Row) => string;
  emptyState?: ReactNode;
}) {
  return (
    <div className="idt-domain-table-wrap">
      <table className="idt-domain-data-table" aria-label={label}>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key} scope="col" className={column.align === 'right' ? 'is-right' : undefined}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={getRowKey(row)}>
              {columns.map((column) => (
                <td key={column.key} className={column.align === 'right' ? 'is-right' : undefined}>
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 ? (
        <div className="idt-domain-table-empty">
          {emptyState ?? <DomainEmptyState title="No records yet" body="Connect the domain or adjust filters to populate this table." />}
        </div>
      ) : null}
    </div>
  );
}

export function DomainDetailPanel({
  title,
  eyebrow,
  children,
  footer
}: {
  title: string;
  eyebrow?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <aside className="idt-domain-detail-panel" aria-label={title}>
      <header>
        {eyebrow ? <p className="idt-app-kicker">{eyebrow}</p> : null}
        <h3>{title}</h3>
      </header>
      <div>{children}</div>
      {footer ? <footer>{footer}</footer> : null}
    </aside>
  );
}

export function DomainEvidencePanel({
  title,
  code,
  language = 'text',
  caption
}: {
  title: string;
  code: string;
  language?: string;
  caption?: ReactNode;
}) {
  return (
    <figure className="idt-domain-evidence-panel">
      <figcaption>
        <strong>{title}</strong>
        {caption ? <span>{caption}</span> : null}
      </figcaption>
      <pre>
        <code className={`language-${language}`}>{code}</code>
      </pre>
    </figure>
  );
}

export function DomainActionFooter({ children }: { children: ReactNode }) {
  return <footer className="idt-domain-action-footer">{children}</footer>;
}

export type DomainCoverageCardProps = {
  label: string;
  scanned: number;
  total: number;
  detail?: ReactNode;
};

export function DomainCoverageCard({ label, scanned, total, detail }: DomainCoverageCardProps) {
  const pct = total > 0 ? Math.min(100, Math.round((scanned / total) * 100)) : 0;
  const tone: Tone = pct >= 90 ? 'success' : pct >= 60 ? 'info' : pct >= 30 ? 'warning' : 'danger';
  return (
    <article className={classNames(['idt-domain-coverage-card', `is-${tone}`])} aria-label={`${label} coverage`}>
      <header>
        <span>{label}</span>
        <strong>{pct}%</strong>
      </header>
      <div
        className="idt-domain-coverage-bar"
        role="progressbar"
        aria-label={`${label} coverage`}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={scanned}
        aria-valuetext={`${scanned} of ${total} ${label.toLowerCase()} scanned`}
      >
        <span style={{ width: `${pct}%` }} aria-hidden="true" />
      </div>
      <p>
        {scanned} of {total} scanned
        {detail ? <> · {detail}</> : null}
      </p>
    </article>
  );
}

export type DomainSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const DOMAIN_SEVERITY_LABEL: Record<DomainSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info'
};

export type DomainFindingSummaryCardProps = {
  severity: DomainSeverity;
  count: number;
  label?: string;
  trend?: ReactNode;
  to?: string;
  onClick?: () => void;
};

export function DomainFindingSummaryCard({ severity, count, label, trend, to, onClick }: DomainFindingSummaryCardProps) {
  const displayLabel = label ?? `${DOMAIN_SEVERITY_LABEL[severity]} findings`;
  const body = (
    <>
      <header>
        <span className={classNames(['idt-domain-severity-pill', `is-${severity}`])}>{DOMAIN_SEVERITY_LABEL[severity]}</span>
        {trend ? <span className="idt-domain-finding-trend">{trend}</span> : null}
      </header>
      <strong>{count}</strong>
      <p>{displayLabel}</p>
    </>
  );

  const className = classNames(['idt-domain-finding-card', `is-${severity}`]);

  if (to) {
    return (
      <Link className={className} to={to} aria-label={`${count} ${displayLabel}`}>
        {body}
      </Link>
    );
  }

  if (onClick) {
    return (
      <button type="button" className={className} onClick={onClick} aria-label={`${count} ${displayLabel}`}>
        {body}
      </button>
    );
  }

  return (
    <article className={className} aria-label={`${count} ${displayLabel}`}>
      {body}
    </article>
  );
}

export type DomainTimelineEntry = {
  id: string;
  timestamp: string;
  title: ReactNode;
  detail?: ReactNode;
  actor?: ReactNode;
  tone?: Tone;
};

export function DomainTimeline({ label = 'Recent activity', entries }: { label?: string; entries: DomainTimelineEntry[] }) {
  if (entries.length === 0) {
    return null;
  }
  return (
    <ol className="idt-domain-timeline" aria-label={label}>
      {entries.map((entry) => (
        <li key={entry.id} className={classNames(['idt-domain-timeline-row', entry.tone ? `is-${entry.tone}` : ''])}>
          <time>{entry.timestamp}</time>
          <div>
            <p className="idt-domain-timeline-title">{entry.title}</p>
            {entry.detail ? <p className="idt-domain-timeline-detail">{entry.detail}</p> : null}
          </div>
          {entry.actor ? <span className="idt-domain-timeline-actor">{entry.actor}</span> : null}
        </li>
      ))}
    </ol>
  );
}

export function DomainGraphPlaceholder({
  title,
  description,
  action
}: {
  title: string;
  description: ReactNode;
  action?: DomainAction;
}) {
  return (
    <section className="idt-domain-graph-placeholder" aria-label={title}>
      <div className="idt-domain-graph-canvas" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
      <div className="idt-domain-graph-copy">
        <p className="idt-app-kicker">Graph</p>
        <h3>{title}</h3>
        <p>{description}</p>
        {action ? <div className="idt-inline-actions">{renderDomainAction(action, 'graph-action')}</div> : null}
      </div>
    </section>
  );
}

export type DomainRemediationItem = {
  id: string;
  title: ReactNode;
  detail?: ReactNode;
  severity?: DomainSeverity;
  owner?: ReactNode;
  primaryAction?: DomainAction;
  secondaryAction?: DomainAction;
};

export function DomainRemediationQueue({
  label = 'Remediation queue',
  items,
  emptyState
}: {
  label?: string;
  items: DomainRemediationItem[];
  emptyState?: ReactNode;
}) {
  if (items.length === 0) {
    return (
      <section className="idt-domain-remediation-queue idt-domain-remediation-queue-empty" aria-label={label}>
        {emptyState ?? <DomainEmptyState title="Queue is clear" body="No remediation actions are waiting." />}
      </section>
    );
  }
  return (
    <section className="idt-domain-remediation-queue" aria-label={label}>
      <ol>
        {items.map((item) => (
          <li key={item.id} className="idt-domain-remediation-item">
            <div className="idt-domain-remediation-main">
              {item.severity ? (
                <span className={classNames(['idt-domain-severity-pill', `is-${item.severity}`])}>
                  {DOMAIN_SEVERITY_LABEL[item.severity]}
                </span>
              ) : null}
              <div>
                <p className="idt-domain-remediation-title">{item.title}</p>
                {item.detail ? <p className="idt-domain-remediation-detail">{item.detail}</p> : null}
              </div>
            </div>
            <div className="idt-domain-remediation-aside">
              {item.owner ? <span className="idt-domain-remediation-owner">{item.owner}</span> : null}
              <div className="idt-inline-actions">
                {item.secondaryAction ? renderDomainAction({ variant: 'ghost', ...item.secondaryAction }, `${item.id}-secondary`) : null}
                {item.primaryAction ? renderDomainAction({ variant: 'primary', ...item.primaryAction }, `${item.id}-primary`) : null}
              </div>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}

export type DomainSortDirection = 'asc' | 'desc';
export type DomainSortOption = { key: string; label: string };

export function DomainSortControl({
  label = 'Sort',
  options,
  value,
  direction = 'desc',
  onChange
}: {
  label?: string;
  options: DomainSortOption[];
  value: string;
  direction?: DomainSortDirection;
  onChange: (next: { key: string; direction: DomainSortDirection }) => void;
}) {
  const directionLabel = direction === 'asc' ? 'Ascending' : 'Descending';
  return (
    <div className="idt-domain-sort-control">
      <label>
        <span>{label}</span>
        <select
          value={value}
          onChange={(event) => onChange({ key: event.target.value, direction })}
          aria-label={`${label} field`}
        >
          {options.map((option) => (
            <option key={option.key} value={option.key}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        className="idt-domain-sort-direction"
        aria-label={`${label} direction: ${directionLabel}. Toggle.`}
        aria-pressed={direction === 'asc'}
        onClick={() => onChange({ key: value, direction: direction === 'asc' ? 'desc' : 'asc' })}
      >
        <span aria-hidden="true">{direction === 'asc' ? '↑' : '↓'}</span>
        <span className="idt-visually-hidden">{directionLabel}</span>
      </button>
    </div>
  );
}

const DOMAIN_DRAWER_FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

function getDomainDrawerFocusable(root: HTMLElement | null): HTMLElement[] {
  if (!root) {
    return [];
  }
  return Array.from(root.querySelectorAll<HTMLElement>(DOMAIN_DRAWER_FOCUSABLE_SELECTOR)).filter(
    (el) => el.getAttribute('aria-hidden') !== 'true'
  );
}

export function DomainDetailDrawer({
  open,
  title,
  eyebrow,
  onClose,
  closeLabel = 'Close detail drawer',
  children,
  footer
}: {
  open: boolean;
  title: string;
  eyebrow?: string;
  onClose: () => void;
  closeLabel?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const drawerRef = useRef<HTMLElement | null>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  const [dragOffset, setDragOffset] = useState(0);
  const [isSwiping, setIsSwiping] = useState(false);
  const dragOffsetRef = useRef(0);
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    startTime: number;
    active: boolean;
  } | null>(null);

  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) {
      return;
    }
    restoreFocusRef.current = (document.activeElement as HTMLElement | null) ?? null;
    const focusables = getDomainDrawerFocusable(drawerRef.current);
    (focusables[0] ?? drawerRef.current)?.focus();
    return () => {
      restoreFocusRef.current?.focus?.();
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      setDragOffset(0);
      dragOffsetRef.current = 0;
      setIsSwiping(false);
      dragRef.current = null;
    }
  }, [open]);

  const handleKeyDown = useCallback((event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.stopPropagation();
      onCloseRef.current();
      return;
    }
    if (event.key !== 'Tab') {
      return;
    }
    const focusables = getDomainDrawerFocusable(drawerRef.current);
    if (focusables.length === 0) {
      event.preventDefault();
      drawerRef.current?.focus();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement as HTMLElement | null;
    if (event.shiftKey) {
      if (active === first || !drawerRef.current?.contains(active)) {
        event.preventDefault();
        last.focus();
      }
      return;
    }
    if (active === last) {
      event.preventDefault();
      first.focus();
    }
  }, []);

  const finishSwipe = useCallback((event?: ReactPointerEvent<HTMLElement>) => {
    const drag = dragRef.current;
    if (!drag) {
      return;
    }
    const finalOffset = dragOffsetRef.current;
    const elapsed = Math.max(1, Date.now() - drag.startTime);
    const velocity = finalOffset / elapsed;
    dragRef.current = null;
    event?.currentTarget.releasePointerCapture?.(drag.pointerId);
    setIsSwiping(false);
    if (finalOffset > 112 || (finalOffset > 52 && velocity > 0.45)) {
      onCloseRef.current();
      return;
    }
    dragOffsetRef.current = 0;
    setDragOffset(0);
  }, []);

  const handleDrawerPointerDown = (event: ReactPointerEvent<HTMLElement>) => {
    if (event.pointerType === 'mouse' || event.button !== 0) {
      return;
    }
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      startTime: Date.now(),
      active: false
    };
    dragOffsetRef.current = 0;
    setDragOffset(0);
    event.currentTarget.setPointerCapture?.(event.pointerId);
  };

  const handleDrawerPointerMove = (event: ReactPointerEvent<HTMLElement>) => {
    const drag = dragRef.current;
    if (!drag) {
      return;
    }
    const deltaX = event.clientX - drag.startX;
    const deltaY = event.clientY - drag.startY;
    if (!drag.active) {
      if (Math.abs(deltaY) > Math.abs(deltaX) && Math.abs(deltaY) > 12) {
        dragRef.current = null;
        dragOffsetRef.current = 0;
        setDragOffset(0);
        event.currentTarget.releasePointerCapture?.(drag.pointerId);
        return;
      }
      if (deltaX < 12 || deltaX < Math.abs(deltaY)) {
        return;
      }
      drag.active = true;
      setIsSwiping(true);
    }
    event.preventDefault();
    const nextOffset = Math.min(260, Math.max(0, deltaX));
    dragOffsetRef.current = nextOffset;
    setDragOffset(nextOffset);
  };

  const drawerStyle = {
    '--idt-domain-drawer-swipe-x': `${dragOffset}px`
  } as CSSProperties;

  if (!open) {
    return null;
  }
  return (
    <div className="idt-domain-drawer-root" role="dialog" aria-modal="true" aria-label={title} onKeyDown={handleKeyDown}>
      <button type="button" className="idt-domain-drawer-scrim" aria-hidden="true" tabIndex={-1} onClick={onClose} />
      <aside
        className={classNames(['idt-domain-drawer', isSwiping ? 'is-swiping' : ''])}
        onPointerCancel={() => finishSwipe()}
        onPointerDown={handleDrawerPointerDown}
        onPointerMove={handleDrawerPointerMove}
        onPointerUp={finishSwipe}
        ref={drawerRef}
        style={drawerStyle}
        tabIndex={-1}
      >
        <header>
          <div>
            {eyebrow ? <p className="idt-app-kicker">{eyebrow}</p> : null}
            <h3>{title}</h3>
          </div>
          <button type="button" className="idt-domain-drawer-close" onClick={onClose} aria-label={closeLabel}>
            ESC
          </button>
        </header>
        <div className="idt-domain-drawer-body">{children}</div>
        {footer ? <footer>{footer}</footer> : null}
      </aside>
    </div>
  );
}
