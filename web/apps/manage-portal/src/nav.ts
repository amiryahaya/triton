import type { NavSection, AppEntry } from '@triton/ui';

// Sidebar nav per portal-unification spec §8.1 (Manage Server).
// Grouped three-section layout: Inventory / Operations / Admin.
export const nav: NavSection[] = [
  {
    label: 'Inventory',
    items: [
      { href: '#/inventory/zones',  label: 'Zones' },
      { href: '#/inventory/hosts',  label: 'Hosts' },
      { href: '#/inventory/agents', label: 'Agents' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { href: '#/dashboard',              label: 'Dashboard' },
      { href: '#/operations/scan-jobs',   label: 'Scan Jobs' },
      { href: '#/operations/push-status', label: 'Push Status' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '#/admin/users',    label: 'Users' },
      { href: '#/admin/security', label: 'Security' },
      { href: '#/admin/licence',  label: 'Licence' },
      { href: '#/admin/settings', label: 'Settings' },
    ],
  },
];

// Build-time env vars wire cross-portal URLs in the app-switcher. When
// a deployment doesn't set them, the sibling portal tile renders greyed.
const licenseUrl = import.meta.env.VITE_LICENSE_URL as string | undefined;
const reportUrl  = import.meta.env.VITE_REPORT_URL  as string | undefined;

export const apps: AppEntry[] = [
  { id: 'license', name: 'Licence', subtitle: 'Vendor ops', url: licenseUrl ?? null, accent: '#a78bfa' },
  { id: 'report',  name: 'Report',  subtitle: 'Security',   url: reportUrl  ?? null, accent: '#22d3ee' },
  { id: 'manage',  name: 'Manage',  subtitle: 'Network',    url: null,               accent: '#a3e635' },
];

// Portal accent — lime family per spec §5.2. Applied to logo rail stripe
// + active nav border + :focus outlines. Primary buttons stay on the
// shared --accent token so CTAs read consistently across all portals.
export const PORTAL_ACCENT = '#a3e635';
