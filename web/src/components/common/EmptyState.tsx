import { ReactNode } from 'react';

type EmptyStateProps = {
  eyebrow?: string;
  title: string;
  body: string;
  children?: ReactNode;
};

export function EmptyState({ eyebrow, title, body, children }: EmptyStateProps) {
  return (
    <article className="idt-empty-panel">
      {eyebrow ? <p className="idt-app-kicker">{eyebrow}</p> : null}
      <h2>{title}</h2>
      <p>{body}</p>
      {children ? <div className="idt-inline-actions">{children}</div> : null}
    </article>
  );
}
