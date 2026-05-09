import {
  ComponentPropsWithoutRef,
  ElementType,
  ReactElement,
  ReactNode
} from 'react';

const variantClass = {
  default: 'section',
  tight: 'section-tight',
  loose: 'section-loose'
} as const;

const containerClass = {
  default: 'container',
  narrow: 'container-narrow',
  wide: 'container-wide',
  none: ''
} as const;

type SectionOwnProps<T extends ElementType> = {
  as?: T;
  variant?: keyof typeof variantClass;
  container?: keyof typeof containerClass;
  children: ReactNode;
};

/**
 * Polymorphic typing: the rendered element type drives which intrinsic
 * attributes the component accepts. Defaults to <section>; pass `as="aside"`
 * (etc.) to render a different tag and get the matching attributes typed.
 */
export type SectionProps<T extends ElementType = 'section'> = SectionOwnProps<T> &
  Omit<ComponentPropsWithoutRef<T>, keyof SectionOwnProps<T>>;

export function Section<T extends ElementType = 'section'>({
  as,
  variant = 'default',
  container = 'default',
  className,
  children,
  ...rest
}: SectionProps<T>): ReactElement {
  const Tag = (as ?? 'section') as ElementType;
  const merged = [variantClass[variant], className as string | undefined].filter(Boolean).join(' ');
  return (
    <Tag {...rest} className={merged}>
      {container === 'none' ? children : <div className={containerClass[container]}>{children}</div>}
    </Tag>
  );
}

type SectionHeaderProps = {
  eyebrow?: string;
  title: ReactNode;
  /**
   * Short prose displayed under the title. Constrained to a string (or
   * ReactNode chain that resolves to inline content) because it is rendered
   * inside a <p>; passing block elements would produce invalid HTML.
   */
  lede?: ReactNode;
  align?: 'left' | 'center';
  children?: ReactNode;
};

export function SectionHeader({ eyebrow, title, lede, align = 'left', children }: SectionHeaderProps) {
  return (
    <header
      className={['section-head', align === 'center' ? 'u-center-text u-mx-auto' : ''].filter(Boolean).join(' ')}
    >
      {eyebrow ? <span className="t-eyebrow">{eyebrow}</span> : null}
      {typeof title === 'string' ? <h2 className="t-h2">{title}</h2> : title}
      {/*
       * Render the lede in a <div> rather than a <p>: the prop type permits
       * any ReactNode and a few callers do compose richer content, which
       * would generate <p><div/></p> (invalid) when wrapped in <p>.
       */}
      {lede ? <div className="t-lede">{lede}</div> : null}
      {children}
    </header>
  );
}

type EyebrowProps = { children: ReactNode; plain?: boolean; className?: string };
export function Eyebrow({ children, plain, className }: EyebrowProps) {
  return (
    <span className={['t-eyebrow', plain ? 'is-plain' : '', className].filter(Boolean).join(' ')}>{children}</span>
  );
}
