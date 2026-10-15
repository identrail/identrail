import type { KeyboardEvent } from 'react';

export function handleTabListKeyDown(event: KeyboardEvent<HTMLElement>) {
  if (event.altKey || event.ctrlKey || event.metaKey) {
    return;
  }

  const tabs = Array.from(event.currentTarget.querySelectorAll<HTMLElement>('[role="tab"]:not([disabled])'));
  const currentTab = (event.target as HTMLElement).closest<HTMLElement>('[role="tab"]');
  const currentIndex = currentTab ? tabs.indexOf(currentTab) : -1;
  if (currentIndex < 0 || tabs.length < 2) {
    return;
  }

  const isVertical = event.currentTarget.getAttribute('aria-orientation') === 'vertical';
  let nextIndex: number | null = null;

  if (event.key === (isVertical ? 'ArrowDown' : 'ArrowRight')) {
    nextIndex = (currentIndex + 1) % tabs.length;
  } else if (event.key === (isVertical ? 'ArrowUp' : 'ArrowLeft')) {
    nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
  } else if (event.key === 'Home') {
    nextIndex = 0;
  } else if (event.key === 'End') {
    nextIndex = tabs.length - 1;
  }

  if (nextIndex === null) {
    return;
  }

  event.preventDefault();
  tabs[nextIndex].focus();
}
