import { ButtonHTMLAttributes, ReactNode } from 'react';
import { Link } from 'react-router-dom';

type ButtonVariant = 'primary' | 'secondary' | 'ghost';
type ButtonSize = 'sm' | 'md' | 'lg';

function classes(variant: ButtonVariant, size: ButtonSize, block?: boolean) {
  return [
    'btn',
    `btn-${variant}`,
    size !== 'md' ? `btn-${size}` : '',
    block ? 'btn-block' : ''
  ]
    .filter(Boolean)
    .join(' ');
}

type ButtonOwnProps = {
  variant?: ButtonVariant;
  size?: ButtonSize;
  block?: boolean;
  children: ReactNode;
};

export type ButtonProps = ButtonOwnProps & Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'>;

export function Button({ variant = 'primary', size = 'md', block, className, children, ...rest }: ButtonProps) {
  return (
    <button {...rest} className={[classes(variant, size, block), className].filter(Boolean).join(' ')}>
      {children}
    </button>
  );
}

type LinkButtonProps = ButtonOwnProps & {
  to: string;
  external?: boolean;
  className?: string;
  ariaLabel?: string;
};

/**
 * LinkButton renders as an <a> for external destinations and as a
 * react-router <Link> for internal ones. Style matches Button.
 */
export function LinkButton({
  to,
  external,
  variant = 'primary',
  size = 'md',
  block,
  className,
  ariaLabel,
  children
}: LinkButtonProps) {
  const cls = [classes(variant, size, block), className].filter(Boolean).join(' ');

  const isExternal =
    external ?? (to.startsWith('http://') || to.startsWith('https://') || to.startsWith('mailto:') || to.startsWith('tel:'));

  if (isExternal) {
    return (
      <a
        href={to}
        className={cls}
        target={to.startsWith('mailto:') || to.startsWith('tel:') ? undefined : '_blank'}
        rel={to.startsWith('mailto:') || to.startsWith('tel:') ? undefined : 'noopener noreferrer'}
        aria-label={ariaLabel}
      >
        {children}
      </a>
    );
  }

  return (
    <Link to={to} className={cls} aria-label={ariaLabel}>
      {children}
    </Link>
  );
}

type ArrowLinkProps = {
  to: string;
  external?: boolean;
  children: ReactNode;
  className?: string;
};

/** Small inline link with a trailing arrow that nudges on hover. */
export function ArrowLink({ to, external, children, className }: ArrowLinkProps) {
  const cls = ['btn-arrow', className].filter(Boolean).join(' ');
  const isMailOrTel = to.startsWith('mailto:') || to.startsWith('tel:');
  const isExternal =
    external ?? (to.startsWith('http://') || to.startsWith('https://') || isMailOrTel);

  const inner = (
    <>
      {children}
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path
          d="M3.5 8h9M9 4.5L12.5 8 9 11.5"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </>
  );

  if (isExternal) {
    // mailto:/tel: should open in the user's mail or dialer app, not a blank
    // browser tab. http(s) external links keep target="_blank" with safe rel.
    return (
      <a
        href={to}
        className={cls}
        target={isMailOrTel ? undefined : '_blank'}
        rel={isMailOrTel ? undefined : 'noopener noreferrer'}
      >
        {inner}
      </a>
    );
  }
  return (
    <Link to={to} className={cls}>
      {inner}
    </Link>
  );
}
