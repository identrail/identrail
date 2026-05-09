import { SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

const baseProps = (size: number, rest: SVGProps<SVGSVGElement>) => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.6,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
  ...rest
});

export function ArrowRightIcon({ size = 16, ...rest }: IconProps) {
  return (
    <svg {...baseProps(size, rest)}>
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  );
}

export function CheckIcon({ size = 16, ...rest }: IconProps) {
  return (
    <svg {...baseProps(size, rest)}>
      <path d="M5 12.5l4 4L19 7" />
    </svg>
  );
}

export function XCloseIcon({ size = 18, ...rest }: IconProps) {
  return (
    <svg {...baseProps(size, rest)}>
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}

export function MenuIcon({ size = 20, ...rest }: IconProps) {
  return (
    <svg {...baseProps(size, rest)}>
      <path d="M4 7h16M4 17h16" />
    </svg>
  );
}

export function GitHubIcon({ size = 18, ...rest }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...rest}>
      <path
        d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56v-2c-3.2.7-3.87-1.36-3.87-1.36-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.72-1.53-2.55-.29-5.24-1.27-5.24-5.66 0-1.25.45-2.27 1.18-3.07-.12-.29-.51-1.46.11-3.04 0 0 .96-.31 3.15 1.17.92-.26 1.9-.39 2.88-.39.98 0 1.96.13 2.88.39 2.18-1.48 3.14-1.17 3.14-1.17.62 1.58.23 2.75.11 3.04.74.8 1.18 1.82 1.18 3.07 0 4.4-2.69 5.36-5.25 5.65.41.35.78 1.05.78 2.12v3.14c0 .31.21.67.79.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z"
      />
    </svg>
  );
}

export function XIcon({ size = 16, ...rest }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...rest}>
      <path d="M17.53 3H20.5l-6.54 7.47L22 21h-6l-4.7-6.13L5.7 21H2.74l7.05-8.06L2 3h6.16l4.26 5.63L17.53 3zm-1.05 16h1.65L7.6 4.74H5.83L16.48 19z" />
    </svg>
  );
}

export function LinkedInIcon({ size = 18, ...rest }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...rest}>
      <path d="M20.45 20.45h-3.55v-5.57c0-1.33-.02-3.04-1.85-3.04-1.85 0-2.13 1.45-2.13 2.95v5.66H9.36V9h3.41v1.56h.05c.47-.9 1.63-1.85 3.36-1.85 3.6 0 4.27 2.37 4.27 5.45v6.29zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zM7.12 20.45H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.72v20.55C0 23.23.79 24 1.77 24h20.45c.98 0 1.78-.77 1.78-1.73V1.72C24 .77 23.2 0 22.22 0z" />
    </svg>
  );
}

export function DiscordIcon({ size = 18, ...rest }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...rest}>
      <path d="M20.32 4.37A19.78 19.78 0 0 0 16.06 3c-.21.38-.42.78-.6 1.18a18.27 18.27 0 0 0-5.92 0c-.18-.4-.4-.8-.6-1.18a19.85 19.85 0 0 0-4.27 1.37C2.07 9.06 1.4 13.6 1.71 18.07a19.94 19.94 0 0 0 5.97 3.05c.48-.66.91-1.36 1.27-2.1-.7-.27-1.36-.6-1.99-.99.17-.12.33-.24.49-.37 3.96 1.86 8.24 1.86 12.16 0 .16.13.32.25.49.37-.63.39-1.3.72-2 .99.37.74.79 1.44 1.28 2.1 2.16-.67 4.18-1.69 5.97-3.05.4-5.18-.69-9.69-3.03-13.7zm-12.4 10.95c-1.18 0-2.15-1.07-2.15-2.39 0-1.31.95-2.39 2.15-2.39 1.21 0 2.18 1.08 2.16 2.39 0 1.32-.96 2.39-2.16 2.39zm7.95 0c-1.18 0-2.15-1.07-2.15-2.39 0-1.31.95-2.39 2.15-2.39 1.21 0 2.18 1.08 2.16 2.39 0 1.32-.95 2.39-2.16 2.39z" />
    </svg>
  );
}

export function StarIcon({ size = 14, ...rest }: IconProps) {
  return (
    <svg {...baseProps(size, rest)} fill="currentColor" stroke="none">
      <path d="M12 2l2.6 6.5L21 9.3l-5 4.6L17.5 21 12 17.5 6.5 21 8 13.9 3 9.3l6.4-.8L12 2z" />
    </svg>
  );
}

export function DotIcon({ size = 8, ...rest }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 8 8" aria-hidden="true" {...rest}>
      <circle cx="4" cy="4" r="4" fill="currentColor" />
    </svg>
  );
}

export function ShieldIcon({ size = 18, ...rest }: IconProps) {
  return (
    <svg {...baseProps(size, rest)}>
      <path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

export function GraphIcon({ size = 18, ...rest }: IconProps) {
  return (
    <svg {...baseProps(size, rest)}>
      <circle cx="6" cy="6" r="2.5" />
      <circle cx="6" cy="18" r="2.5" />
      <circle cx="18" cy="12" r="2.5" />
      <path d="M8.2 7l7.6 4M8.2 17l7.6-4" />
    </svg>
  );
}
