export interface Organisation {
  id: string;
  name: string;
  contact: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export type LicenceTier = 'free' | 'pro' | 'enterprise';
export type ProductScope = 'legacy' | 'report' | 'manage' | 'bundle';
export type LimitMetric =
  | 'seats' | 'tenants' | 'hosts' | 'scans' | 'retention_days';
export type LimitWindow = 'total' | 'daily' | 'monthly';

export interface LicenceFeatures {
  report: boolean;
  manage: boolean;
  comprehensive_profile: boolean;
  diff_trend: boolean;
  custom_policy: boolean;
  sso: boolean;
  export_formats?: string[];
}

export interface LicenceLimit {
  metric: LimitMetric;
  window: LimitWindow;
  cap: number;
}

export interface Licence {
  id: string;
  orgID: string;
  orgName: string;
  tier: LicenceTier;
  seats: number;
  seatsUsed: number;
  issuedAt: string;
  expiresAt: string;
  revoked: boolean;
  revokedAt?: string | null;
  notes: string;
  createdAt: string;
  features: LicenceFeatures;
  limits: LicenceLimit[];
  soft_buffer_pct: number;
  product_scope: ProductScope;
  schedule: string;
  scheduleJitterSeconds: number;
}

export interface Activation {
  id: string;
  licenseID: string;
  machineID: string;
  hostname: string;
  os: string;
  arch: string;
  token: string;
  activatedAt: string;
  lastSeenAt: string;
  deactivatedAt?: string | null;
  active: boolean;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  eventType: string;
  licenseID?: string;
  orgID?: string;
  machineID?: string;
  actor: string;
  details: Record<string, unknown>;
  ipAddress: string;
}

export interface DashboardStats {
  totalOrgs: number;
  totalLicenses: number;
  activeLicenses: number;
  revokedLicenses: number;
  expiredLicenses: number;
  totalActivations: number;
  activeSeats: number;
}
