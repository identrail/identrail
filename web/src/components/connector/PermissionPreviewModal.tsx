import type { AWSCapabilityPermissionTier, AWSPermissionPreviewItem } from '../../api/client';

type PermissionPreviewModalProps = {
  open: boolean;
  title: string;
  items: AWSPermissionPreviewItem[];
  tiers?: AWSCapabilityPermissionTier[];
  onClose: () => void;
};

const CAPABILITY_LABELS: Record<string, string> = {
  discovery: 'Discovery',
  runtime_evidence: 'Runtime evidence',
  remediation_plan: 'Remediation plan',
  approved_remediation: 'Approved remediation',
  authorization_advisory: 'Authorization advisory',
  authorization_enforcement: 'Authorization enforcement',
};

function PermissionList({ items }: { items: AWSPermissionPreviewItem[] }) {
  return (
    <div className="idt-permission-preview-list">
      {items.map((item) => (
        <article key={item.service}>
          <div>
            <strong>{item.service}</strong>
            <p>{item.reason}</p>
          </div>
          <code>{item.actions.join(', ')}</code>
        </article>
      ))}
    </div>
  );
}

export function PermissionPreviewModal({ open, title, items, tiers, onClose }: PermissionPreviewModalProps) {
  if (!open) {
    return null;
  }

  return (
    <div className="idt-modal-backdrop" role="presentation" onClick={onClose}>
      <section
        aria-modal="true"
        className="idt-permission-preview-modal"
        role="dialog"
        aria-labelledby="permission-preview-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <p className="idt-app-kicker">Permission preview</p>
            <h3 id="permission-preview-title">{title}</h3>
          </div>
          <button className="idt-esc-close" type="button" aria-label="Close permission preview" onClick={onClose}>
            ESC
          </button>
        </header>
        {tiers && tiers.length > 0 ? (
          <div className="idt-permission-tier-list">
            {tiers.map((tier) => (
              <section key={tier.capability} className="idt-permission-tier" data-tier={tier.tier}>
                <header className="idt-permission-tier-header">
                  <strong>{CAPABILITY_LABELS[tier.capability] ?? tier.capability}</strong>
                  <span className="idt-permission-tier-badges">
                    <span className="idt-badge">{tier.tier === 'write' ? 'Write' : 'Read-only'}</span>
                    <span className="idt-badge">{tier.available ? 'Available now' : 'Not yet enabled'}</span>
                  </span>
                </header>
                <p>{tier.summary}</p>
                <PermissionList items={tier.permissions} />
              </section>
            ))}
          </div>
        ) : (
          <PermissionList items={items} />
        )}
      </section>
    </div>
  );
}
