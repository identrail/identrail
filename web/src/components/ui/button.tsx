import type { ButtonHTMLAttributes, ReactElement, ReactNode } from 'react';
import { cloneElement, isValidElement } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from './utils';

const buttonVariants = cva('ui-button', {
  variants: {
    variant: {
      primary: 'ui-button--primary',
      secondary: 'ui-button--secondary',
      outline: 'ui-button--outline',
      ghost: 'ui-button--ghost'
    },
    size: {
      default: 'ui-button--default',
      sm: 'ui-button--sm'
    }
  },
  defaultVariants: {
    variant: 'primary',
    size: 'default'
  }
});

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
    children?: ReactNode;
  };

export function Button({ className, variant, size, asChild = false, children, ...props }: ButtonProps) {
  const classes = cn(buttonVariants({ variant, size }), className);

  if (asChild && isValidElement(children)) {
    const child = children as ReactElement<{ className?: string }>;
    return cloneElement(child, {
      ...props,
      className: cn(child.props.className, classes)
    });
  }

  return (
    <button {...props} type={props.type ?? 'button'} className={classes}>
      {children}
    </button>
  );
}
