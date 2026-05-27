import { useId } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Link } from 'react-router-dom';
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
  eyebrow?: string;
  title: string;
  description: ReactNode;
  scope?: ReactNode;
  status?: ReactNode;
  statusTone?: Tone;
  primaryAction?: DomainAction;
  secondaryActions?: DomainAction[];
  titleId?: string;
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
  titleId
}: DomainHeaderProps) {
  const asset = getDomainAsset(domain);
  const actions = primaryAction ? [primaryAction, ...secondaryActions] : secondaryActions;

  return (
    <header className={classNames(['idt-domain-header', `is-${domain}`])}>
      <div className="idt-domain-header-main">
        <DomainLogoMark domain={domain} size="hero" />
        <div>
          <p className="idt-app-kicker">{eyebrow ?? asset.description}</p>
          <h2 id={titleId}>{title}</h2>
          <p>{description}</p>
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

export function DomainEmptyState({ eyebrow, title, body, children }: { eyebrow?: string; title: string; body: ReactNode; children?: ReactNode }) {
  return (
    <article className="idt-domain-empty-state">
      {eyebrow ? <p className="idt-app-kicker">{eyebrow}</p> : null}
      <h3>{title}</h3>
      <p>{body}</p>
      {children ? <div className="idt-inline-actions">{children}</div> : null}
    </article>
  );
}

export function DomainErrorState({ title, body, children }: { title: string; body: ReactNode; children?: ReactNode }) {
  return (
    <article className="idt-domain-error-state" role="alert">
      <p className="idt-app-kicker">Needs attention</p>
      <h3>{title}</h3>
      <p>{body}</p>
      {children ? <div className="idt-inline-actions">{children}</div> : null}
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
