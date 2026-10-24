import { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { handleTabListKeyDown } from './tabKeyboard';

function TabFixture({ orientation = 'horizontal' }: { orientation?: 'horizontal' | 'vertical' }) {
  const [active, setActive] = useState(0);
  return (
    <div role="tablist" aria-orientation={orientation} onKeyDown={handleTabListKeyDown}>
      {['First', 'Second', 'Third'].map((label, index) => (
        <button
          key={label}
          type="button"
          role="tab"
          tabIndex={active === index ? 0 : -1}
          aria-selected={active === index}
          onFocus={() => setActive(index)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

describe('handleTabListKeyDown', () => {
  it('wraps horizontal navigation and supports Home and End', () => {
    render(<TabFixture />);
    const first = screen.getByRole('tab', { name: 'First' });
    const third = screen.getByRole('tab', { name: 'Third' });

    first.focus();
    fireEvent.keyDown(first, { key: 'ArrowLeft' });
    expect(third).toHaveFocus();
    fireEvent.keyDown(third, { key: 'Home' });
    expect(first).toHaveFocus();
    fireEvent.keyDown(first, { key: 'End' });
    expect(third).toHaveFocus();
  });

  it('uses vertical arrows and leaves modified browser shortcuts alone', () => {
    render(<TabFixture orientation="vertical" />);
    const first = screen.getByRole('tab', { name: 'First' });
    const second = screen.getByRole('tab', { name: 'Second' });

    first.focus();
    fireEvent.keyDown(first, { key: 'ArrowDown' });
    expect(second).toHaveFocus();
    fireEvent.keyDown(second, { key: 'ArrowUp', altKey: true });
    expect(second).toHaveFocus();
  });
});
