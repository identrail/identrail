import type { HTMLAttributes, ReactNode } from 'react';
import { createContext, useContext, useState } from 'react';
import { cn } from './utils';

type ToggleGroupContextValue = {
  value?: string;
  onValueChange?: (value: string) => void;
};

const ToggleGroupContext = createContext<ToggleGroupContextValue | null>(null);

type ToggleGroupProps = HTMLAttributes<HTMLDivElement> & {
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  children?: ReactNode;
};

export function ToggleGroup({ className, value: controlledValue, defaultValue, onValueChange, children, ...props }: ToggleGroupProps) {
  const [uncontrolledValue, setUncontrolledValue] = useState(defaultValue);
  const value = controlledValue ?? uncontrolledValue;
  const handleValueChange = (nextValue: string) => {
    if (controlledValue === undefined) {
      setUncontrolledValue(nextValue);
    }
    onValueChange?.(nextValue);
  };

  return (
    <ToggleGroupContext.Provider value={{ value, onValueChange: handleValueChange }}>
      <div className={cn('ui-toggle-group', className)} role="group" {...props}>
        {children}
      </div>
    </ToggleGroupContext.Provider>
  );
}

type ToggleGroupItemProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  value: string;
};

export function ToggleGroupItem({ className, value, children, onClick, ...props }: ToggleGroupItemProps) {
  const context = useContext(ToggleGroupContext);
  const isActive = context?.value === value;

  return (
    <button
      {...props}
      type="button"
      className={cn('ui-toggle-group__item', className)}
      data-state={isActive ? 'on' : 'off'}
      aria-pressed={isActive}
      onClick={(event) => {
        onClick?.(event);
        context?.onValueChange?.(value);
      }}
    >
      {children}
    </button>
  );
}
