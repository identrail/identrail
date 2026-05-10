import { Link } from 'react-router-dom';
import { SITE_NAME } from '../../siteConfig';

type LogoMarkProps = {
  size?: number;
  className?: string;
};

/**
 * Identrail glyph - two converging trails terminating at a single node.
 * Reads as identity (multiple sources) → trail (path) → resource (one node).
 */
export function LogoMark({ size = 26, className }: LogoMarkProps) {
  return (
    <img
      src="/identrail-logo-official.jpeg"
      width={size}
      height={size}
      className={className}
      alt=""
      aria-hidden="true"
      decoding="async"
    />
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
