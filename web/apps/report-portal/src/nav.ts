import type { NavSection, AppEntry } from '@triton/ui';

// Sidebar nav per portal-unification spec §8.1 (Report Server).
// The three-section layout mirrors the spec — unsectioned primary views
// on top, then Compliance, then Trend & diff, then Admin (role-gated
// visibility handled at composition time, not here).
export const nav: NavSection[] = [
  {
    items: [
      { href: '#/',         label: 'Overview' },
      { href: '#/machines', label: 'Machines' },
      { href: '#/scans',    label: 'Scans' },
    ],
  },
  {
    label: 'Compliance',
    items: [
      { href: '#/nacsa',        label: 'NACSA Arahan 9' },
      { href: '#/priority',     label: 'Priority' },
      { href: '#/inventory',    label: 'Inventory' },
      { href: '#/certificates', label: 'Certificates' },
    ],
  },
  {
    label: 'Trend & diff',
    items: [
      { href: '#/trend', label: 'Migration trend' },
      { href: '#/diff',  label: 'Scan diff' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '#/admin/users',   label: 'Users' },
      { href: '#/admin/tenants', label: 'Tenants' },
      { href: '#/admin/audit',   label: 'Audit log' },
    ],
  },
  {
    label: 'Platform',
    items: [
      { href: '#/platform/admins',  label: 'Platform Admins' },
      { href: '#/platform/tenants', label: 'Tenants' },
    ],
  },
];

// Build-time env vars wire cross-portal URLs in the app-switcher. When
// a deployment doesn't set them, the sibling portal tile renders greyed.
const licenseUrl = import.meta.env.VITE_LICENSE_URL as string | undefined;
const manageUrl  = import.meta.env.VITE_MANAGE_URL as string | undefined;

export const apps: AppEntry[] = [
  { id: 'license', name: 'Licence', subtitle: 'Vendor ops', url: licenseUrl ?? null, accent: '#a78bfa' },
  { id: 'report',  name: 'Report',  subtitle: 'Security',   url: null,               accent: '#22d3ee' },
  { id: 'manage',  name: 'Manage',  subtitle: 'Network',    url: manageUrl ?? null,  accent: '#a3e635' },
];

// Portal accent — cyan family per spec §5.2. Applied to logo rail stripe
// + active nav border + :focus outlines. Primary buttons stay on the
// shared --accent token so CTAs read consistently across all portals.
export const PORTAL_ACCENT = '#22d3ee';
