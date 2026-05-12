type ErrorStateProps = {
  title?: string;
  message: string;
  actionLabel?: string;
  onAction?: () => void;
};

export function ErrorState({ title = 'Something needs attention', message, actionLabel, onAction }: ErrorStateProps) {
  return (
    <article className="idt-error-panel" role="alert">
      <p className="idt-app-kicker">Error</p>
      <h2>{title}</h2>
      <p>{message}</p>
      {actionLabel && onAction ? (
        <div className="idt-inline-actions">
          <button className="idt-btn idt-btn-ghost" type="button" onClick={onAction}>
            {actionLabel}
          </button>
        </div>
      ) : null}
    </article>
  );
}
