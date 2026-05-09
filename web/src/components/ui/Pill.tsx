import { HTMLAttributes, ReactNode } from 'react';

type PillVariant = 'neutral' | 'accent' | 'danger' | 'success' | 'warning';

type PillProps = HTMLAttributes<HTMLSpanElement> & {
  variant?: PillVariant;
  dot?: boolean;
  children: ReactNode;
};

const variantClass: Record<PillVariant, string> = {
  neutral: '',
  accent: 'pill-accent',
  danger: 'pill-danger',
  success: 'pill-success',
  warning: 'pill-warning'
};

export function Pill({ variant = 'neutral', dot, className, children, ...rest }: PillProps) {
  return (
    <span
      {...rest}
      className={['pill', variantClass[variant], dot ? 'pill-dot' : '', className].filter(Boolean).join(' ')}
    >
      {children}
    </span>
  );
}

type TagProps = HTMLAttributes<HTMLSpanElement> & { children: ReactNode };
export function Tag({ className, children, ...rest }: TagProps) {
  return (
    <span {...rest} className={['tag', className].filter(Boolean).join(' ')}>
      {children}
    </span>
  );
}
