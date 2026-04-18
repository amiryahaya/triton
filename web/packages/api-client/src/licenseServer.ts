import type { Http } from './http';
import type {
  Organisation,
  Licence,
  Activation,
  AuditEntry,
  DashboardStats,
  Paged,
} from './types';

export function createLicenseApi(http: Http) {
  return {
    dashboard: () => http.get<DashboardStats>('/v1/dashboard/stats'),
    orgs: (p = 1) => http.get<Paged<Organisation>>(`/v1/orgs?page=${p}`),
    org: (id: string) => http.get<Organisation>(`/v1/orgs/${id}`),
    createOrg: (name: string) => http.post<Organisation>('/v1/orgs', { name }),
    deleteOrg: (id: string) => http.del<void>(`/v1/orgs/${id}`),
    licences: (p = 1) => http.get<Paged<Licence>>(`/v1/licenses?page=${p}`),
    licence: (id: string) => http.get<Licence>(`/v1/licenses/${id}`),
    revokeLicence: (id: string) =>
      http.post<void>(`/v1/licenses/${id}/revoke`, {}),
    activations: (licenceId: string) =>
      http.get<Paged<Activation>>(`/v1/licenses/${licenceId}/activations`),
    audit: (p = 1) => http.get<Paged<AuditEntry>>(`/v1/audit?page=${p}`),
  };
}

export type LicenseApi = ReturnType<typeof createLicenseApi>;
