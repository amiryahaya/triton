import { describe, it, expect, afterEach } from 'vitest';
import { readTheme } from '../src/charts/chartTheme';

describe('chartTheme.readTheme', () => {
  afterEach(() => {
    document.documentElement.style.cssText = '';
  });

  it('reads colour values from CSS variables on the root element', () => {
    document.documentElement.style.setProperty('--text-muted', '#94a3b8');
    document.documentElement.style.setProperty('--border', '#334155');
    document.documentElement.style.setProperty('--safe', '#34d399');
    document.documentElement.style.setProperty('--accent', '#0891b2');
    document.documentElement.style.setProperty('--accent-strong', '#22d3ee');
    const t = readTheme();
    expect(t.grid).toBe('#334155');
    expect(t.axisLabel).toBe('#94a3b8');
    expect(t.safe).toBe('#34d399');
    expect(t.accent).toBe('#0891b2');
    expect(t.accentStrong).toBe('#22d3ee');
  });
});
