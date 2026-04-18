export interface ChartTheme {
  axisLabel: string;
  grid: string;
  safe: string;
  warn: string;
  deprecated: string;
  unsafe: string;
  accent: string;
  accentStrong: string;
}

function v(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function readTheme(): ChartTheme {
  return {
    axisLabel:    v('--text-muted'),
    grid:         v('--border'),
    safe:         v('--safe'),
    warn:         v('--warn'),
    deprecated:   v('--deprecated'),
    unsafe:       v('--unsafe'),
    accent:       v('--accent'),
    accentStrong: v('--accent-strong'),
  };
}
