import type { NavSection, AppEntry } from '@triton/ui';

export const nav: NavSection[] = [
  {
    items: [
      { href: '#/',            label: 'Dashboard' },
      { href: '#/orgs',        label: 'Organisations' },
      { href: '#/licenses',    label: 'Licences' },
      { href: '#/activations', label: 'Activations' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '#/audit',       label: 'Audit log' },
      { href: '#/binaries',    label: 'Binaries' },
      { href: '#/superadmins', label: 'Superadmins' },
    ],
  },
];

// Build-time env vars let deployments wire cross-portal URLs.
// Undeployed portals show up greyed in the app-switcher.
const reportUrl = import.meta.env.VITE_REPORT_URL as string | undefined;
const manageUrl = import.meta.env.VITE_MANAGE_URL as string | undefined;

export const apps: AppEntry[] = [
  { id: 'license', name: 'Licence', subtitle: 'Vendor ops', url: null,              accent: '#a78bfa' },
  { id: 'report',  name: 'Report',  subtitle: 'Security',   url: reportUrl ?? null, accent: '#22d3ee' },
  { id: 'manage',  name: 'Manage',  subtitle: 'Network',    url: manageUrl ?? null, accent: '#a3e635' },
];

export const PORTAL_ACCENT = '#a78bfa';
