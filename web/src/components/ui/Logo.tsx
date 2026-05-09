import { Link } from 'react-router-dom';
import { SITE_NAME } from '../../siteConfig';

type LogoMarkProps = {
  size?: number;
  className?: string;
};

/**
 * Identrail glyph — two converging trails terminating at a single node.
 * Reads as identity (multiple sources) → trail (path) → resource (one node).
 */
export function LogoMark({ size = 26, className }: LogoMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      className={className}
      role="img"
      aria-label={`${SITE_NAME} mark`}
    >
      <rect x="0.5" y="0.5" width="31" height="31" rx="7.5" fill="currentColor" opacity="0.06" />
      <rect x="0.5" y="0.5" width="31" height="31" rx="7.5" stroke="currentColor" strokeOpacity="0.18" />
      <circle cx="9" cy="9" r="2.4" fill="currentColor" />
      <circle cx="9" cy="23" r="2.4" fill="currentColor" />
      <circle cx="23" cy="16" r="3" fill="currentColor" />
      <path
        d="M11 9 L20 16 M11 23 L20 16"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}

type LogoProps = {
  /** When true, the wordmark omits the link wrapper (used on /). */
  noLink?: boolean;
  className?: string;
};

export function Logo({ noLink, className }: LogoProps) {
  const inner = (
    <>
      <LogoMark size={26} className="site-logo-mark" />
      <span>{SITE_NAME}</span>
    </>
  );

  if (noLink) {
    return <span className={['site-logo', className].filter(Boolean).join(' ')}>{inner}</span>;
  }

  return (
    <Link to="/" className={['site-logo', className].filter(Boolean).join(' ')} aria-label={`${SITE_NAME} home`}>
      {inner}
    </Link>
  );
}
