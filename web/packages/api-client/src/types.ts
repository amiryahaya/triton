export interface Organisation {
  id: string;
  name: string;
  createdAt: string;
}

export type LicenceTier = 'free' | 'pro' | 'enterprise';

export interface Licence {
  id: string;
  orgId: string;
  key: string;
  tier: LicenceTier;
  seats: number;
  issuedAt: string;
  expiresAt: string;
  bound: boolean;
  revokedAt?: string | null;
  revokedBy?: string | null;
}

export type ActivationStatus = 'online' | 'offline' | 'degraded';

export interface Activation {
  id: string;
  licenceId: string;
  machineFingerprint: string;
  boundBy: string;
  boundAt: string;
  lastSeenAt: string;
  status: ActivationStatus;
}

export type AuditKind = 'info' | 'success' | 'warn' | 'error';

export interface AuditEntry {
  id: string;
  kind: AuditKind;
  subject: string;
  actor: string;
  createdAt: string;
  meta?: Record<string, unknown>;
}

export interface DashboardStats {
  orgs: number;
  seatsUsed: number;
  seatsTotal: number;
  expiringIn30d: number;
}

export interface Paged<T> {
  rows: T[];
  total: number;
  page: number;
  pageSize: number;
}
