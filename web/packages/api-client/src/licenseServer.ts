import type { Http } from './http';
import type {
  Organisation,
  Licence,
  LicenceTier,
  LicenceFeatures,
  LicenceLimit,
  ProductScope,
  Activation,
  AuditEntry,
  DashboardStats,
} from './types';

export interface LoginResponse {
  token: string;
  expiresAt: string;
  mustChangePassword: boolean;
}

export interface ChangePasswordRequest {
  current: string;
  next: string;
}

export interface ChangePasswordResponse {
  token: string;
  expiresAt: string;
}

export interface SetupStatus {
  needsSetup: boolean;
}

export interface SetupFirstAdminRequest {
  name: string;
  email: string;
}

export interface CreateUserRequest {
  name: string;
  email: string;
}

export interface UserWithTempPassword {
  user: import('./types').User;
  tempPassword: string;
  emailSent: boolean;
}

export interface ResendInviteResponse {
  tempPassword: string;
  emailSent: boolean;
}

export interface CreateOrgRequest {
  name: string;
  contact?: string;
  notes?: string;
}

export interface CreateLicenceRequest {
  orgID: string;
  tier: LicenceTier;
  seats: number;
  days: number;
  notes?: string;
  features: LicenceFeatures;
  limits: LicenceLimit[];
  product_scope: ProductScope;
}

export function createLicenseApi(http: Http) {
  return {
    dashboard: () => http.get<DashboardStats>('/v1/admin/stats'),
    orgs: () => http.get<Organisation[]>('/v1/admin/orgs'),
    org: (id: string) => http.get<Organisation>(`/v1/admin/orgs/${id}`),
    createOrg: (req: CreateOrgRequest) =>
      http.post<Organisation>('/v1/admin/orgs', req),
    deleteOrg: (id: string) => http.del<void>(`/v1/admin/orgs/${id}`),
    licences: (filter?: { org?: string }) => {
      const qs = filter?.org
        ? `?org=${encodeURIComponent(filter.org)}`
        : '';
      return http.get<Licence[]>(`/v1/admin/licenses${qs}`);
    },
    licence: (id: string) => http.get<Licence>(`/v1/admin/licenses/${id}`),
    createLicence: (req: CreateLicenceRequest) =>
      http.post<Licence>('/v1/admin/licenses', req),
    revokeLicence: (id: string) =>
      http.post<void>(`/v1/admin/licenses/${id}/revoke`, {}),
    // Returns raw YAML text — backend Content-Type is application/x-yaml
    // so the Http wrapper's non-JSON fallback yields the body as a
    // string. Callers wrap it in a Blob for the browser download.
    downloadAgentYaml: (id: string) =>
      http.post<string>(`/v1/admin/licenses/${id}/agent-yaml`, {}),
    activations: (licenceId: string) =>
      http.get<Activation[]>(
        `/v1/admin/activations?license=${encodeURIComponent(licenceId)}`,
      ),
    audit: (p = 1) =>
      http.get<AuditEntry[]>(`/v1/admin/audit?page=${p}`),

    // Auth
    login: (req: { email: string; password: string }) =>
      http.post<LoginResponse>('/v1/auth/login', req),
    logout: () => http.post<{ status: string }>('/v1/auth/logout', {}),
    refresh: () => http.post<LoginResponse>('/v1/auth/refresh', {}),
    changePassword: (req: ChangePasswordRequest) =>
      http.post<ChangePasswordResponse>('/v1/auth/change-password', req),

    // Setup
    setupStatus: () => http.get<SetupStatus>('/v1/setup/status'),
    setupFirstAdmin: (req: SetupFirstAdminRequest) =>
      http.post<UserWithTempPassword>('/v1/setup/first-admin', req),

    // Users (admin)
    listUsers: () => http.get<import('./types').User[]>('/v1/admin/superadmins/'),
    createUser: (req: CreateUserRequest) =>
      http.post<UserWithTempPassword>('/v1/admin/superadmins/', req),
    deleteUser: (id: string) =>
      http.del<void>(`/v1/admin/superadmins/${id}`),
    resendInvite: (id: string) =>
      http.post<ResendInviteResponse>(
        `/v1/admin/superadmins/${id}/resend-invite`, {}),
  };
}

export type LicenseApi = ReturnType<typeof createLicenseApi>;
