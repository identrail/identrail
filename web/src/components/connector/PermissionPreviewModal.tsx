import type { AWSPermissionPreviewItem } from '../../api/client';

type PermissionPreviewModalProps = {
  open: boolean;
  title: string;
  items: AWSPermissionPreviewItem[];
  onClose: () => void;
};

export function PermissionPreviewModal({ open, title, items, onClose }: PermissionPreviewModalProps) {
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
          <button className="idt-icon-btn" type="button" aria-label="Close permission preview" onClick={onClose}>
            x
          </button>
        </header>
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
      </section>
    </div>
  );
}
