import { describe, it, expect, beforeEach } from 'vitest';
import '../src/tokens/tokens.css';

function cssVar(el: HTMLElement, name: string): string {
  return getComputedStyle(el).getPropertyValue(name).trim();
}

describe('design tokens', () => {
  beforeEach(() => {
    document.documentElement.removeAttribute('data-theme');
  });

  it('defines structural tokens on :root regardless of theme', () => {
    const root = document.documentElement;
    expect(cssVar(root, '--sidebar-w')).toBe('256px');
    expect(cssVar(root, '--topbar-h')).toBe('44px');
    expect(cssVar(root, '--radius')).toBe('8px');
  });

  it('resolves dark palette when data-theme="dark"', () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    const root = document.documentElement;
    expect(cssVar(root, '--bg-base')).toBe('#0f172a');
    expect(cssVar(root, '--text-primary')).toBe('#f1f5f9');
    expect(cssVar(root, '--safe')).toBe('#34d399');
    expect(cssVar(root, '--unsafe')).toBe('#f87171');
  });

  it('resolves light palette when data-theme="light"', () => {
    document.documentElement.setAttribute('data-theme', 'light');
    const root = document.documentElement;
    expect(cssVar(root, '--bg-base')).toBe('#f8fafc');
    expect(cssVar(root, '--text-primary')).toBe('#0f172a');
    expect(cssVar(root, '--safe')).toBe('#059669');
    expect(cssVar(root, '--unsafe')).toBe('#dc2626');
  });
});
