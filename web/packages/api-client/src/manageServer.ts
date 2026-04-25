import type { Http } from './http';
import type {
  SetupStatus, CreateAdminReq, CreateAdminResp,
  ActivateLicenseReq, ActivateLicenseResp,
  LoginResp, ManageUser,
  Tag, CreateTagReq, UpdateTagReq,
  Host, CreateHostReq, UpdateHostReq,
  Agent, ScanJob, EnqueueReq, PushStatus,
  CreateUserReq, CreateUserResp,
  LicenceSummary, SettingsSummary, GatewayHealthResponse,
  SecurityEventsResponse,
  LicenceLifecycleResp, ReplaceLicenceKeyReq, DeactivateLicenceResp,
  DiscoveryJob, DiscoveryStatus, DiscoveryImportReq, DiscoveryImportResp,
} from './manageServer.types';

/**
 * createManageApi wraps an Http client with the Manage Server's v1 REST
 * surface. Paths begin with `/v1/` — caller's baseUrl is expected to be
 * `/api` so full URLs resolve to `/api/v1/...`.
 *
 * The `enrolAgent` method is special: it returns a raw Blob (tar.gz
 * bundle). The UI turns it into a download via URL.createObjectURL —
 * see the Agents view.
 */
export function createManageApi(http: Http) {
  return {
    // Setup + auth
    getSetupStatus: () => http.get<SetupStatus>('/v1/setup/status'),
    createAdmin: (req: CreateAdminReq) => http.post<CreateAdminResp>('/v1/setup/admin', req),
    activateLicense: (req: ActivateLicenseReq) => http.post<ActivateLicenseResp>('/v1/setup/license', req),
    login: (email: string, password: string) => http.post<LoginResp>('/v1/auth/login', { email, password }),
    logout: () => http.post<{ ok: boolean }>('/v1/auth/logout', {}),
    refresh: () => http.post<LoginResp>('/v1/auth/refresh', {}),
    changePassword: (req: { current: string; next: string }) =>
      http.post<LoginResp>('/v1/auth/change-password', req),
    me: () => http.get<ManageUser>('/v1/me'),

    // Tags
    listTags: () => http.get<Tag[]>('/v1/admin/tags/'),
    createTag: (req: CreateTagReq) => http.post<Tag>('/v1/admin/tags/', req),
    updateTag: (id: string, req: UpdateTagReq) => http.patch<Tag>(`/v1/admin/tags/${id}`, req),
    deleteTag: (id: string) => http.del<void>(`/v1/admin/tags/${id}`),
    setHostTags: (hostID: string, tagIDs: string[]) =>
      http.put<Host>(`/v1/admin/hosts/${hostID}/tags`, { tag_ids: tagIDs }),

    // Hosts
    listHosts: (tagID?: string) => {
      const qs = tagID ? `?tag_id=${encodeURIComponent(tagID)}` : '';
      return http.get<Host[]>(`/v1/admin/hosts/${qs}`);
    },
    createHost: (req: CreateHostReq) => http.post<Host>('/v1/admin/hosts/', req),
    bulkCreateHosts: (req: { hosts: CreateHostReq[] }) => http.post<Host[]>('/v1/admin/hosts/bulk', req),
    updateHost: (id: string, req: UpdateHostReq) => http.patch<Host>(`/v1/admin/hosts/${id}`, req),
    deleteHost: (id: string) => http.del<void>(`/v1/admin/hosts/${id}`),

    // Agents
    listAgents: () => http.get<Agent[]>('/v1/admin/agents/'),
    enrolAgent: async (req: { name: string }): Promise<Blob> => {
      // enrolAgent returns a tar.gz stream; the shared Http client only
      // reads JSON/text. Call fetch() directly here so we get the Blob.
      const res = await fetch('/api/v1/admin/enrol/agent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Auth header is re-injected by a per-call closure in apiClient
          // store — see stores/apiClient.ts where this wrapper is built.
          ...(http as unknown as { _authHeader?: () => Record<string, string> })._authHeader?.() ?? {},
        },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`${res.status} ${res.statusText}: ${text}`);
      }
      return res.blob();
    },
    revokeAgent: (id: string) => http.del<void>(`/v1/admin/agents/${id}`),

    // Scan jobs
    listScanJobs: (opts?: { status?: string; limit?: number }) => {
      const params = new URLSearchParams();
      if (opts?.status) params.set('status', opts.status);
      if (opts?.limit !== undefined) params.set('limit', String(opts.limit));
      const qs = params.toString() ? `?${params}` : '';
      return http.get<ScanJob[]>(`/v1/admin/scan-jobs/${qs}`);
    },
    getScanJob: (id: string) => http.get<ScanJob>(`/v1/admin/scan-jobs/${id}`),
    enqueueScanJobs: (req: EnqueueReq) => http.post<ScanJob[]>('/v1/admin/scan-jobs/', req),
    cancelScanJob: (id: string) => http.post<void>(`/v1/admin/scan-jobs/${id}/cancel`, {}),

    // Push status
    getPushStatus: () => http.get<PushStatus>('/v1/admin/push-status/'),

    // Users
    listUsers: () => http.get<ManageUser[]>('/v1/admin/users/'),
    createUser: (req: CreateUserReq) => http.post<CreateUserResp>('/v1/admin/users/', req),
    deleteUser: (id: string) => http.del<void>(`/v1/admin/users/${id}`),

    // Licence summary (Batch E)
    getLicence: () => http.get<LicenceSummary>('/v1/admin/licence'),

    // Licence lifecycle (Batch E.1 — Task 9)
    refreshLicence: () =>
      http.post<LicenceLifecycleResp>('/v1/admin/licence/refresh', {}),

    replaceLicenceKey: (req: ReplaceLicenceKeyReq) =>
      http.post<LicenceLifecycleResp>('/v1/admin/licence/replace', req),

    deactivateLicence: () =>
      http.post<DeactivateLicenceResp>('/v1/admin/licence/deactivate', {}),

    cancelDeactivation: () =>
      http.del<{ ok: boolean }>('/v1/admin/licence/deactivation'),

    // Runtime settings (Batch F)
    getSettings: () => http.get<SettingsSummary>('/v1/admin/settings'),

    // Gateway cert / listener health (Batch G)
    getGatewayHealth: () => http.get<GatewayHealthResponse>('/v1/admin/gateway-health'),

    // Security events (login lockouts)
    listLockouts: () => http.get<SecurityEventsResponse>('/v1/admin/security-events'),
    clearLockout: (email: string, ip: string) =>
      http.del<void>(
        `/v1/admin/security-events?email=${encodeURIComponent(email)}&ip=${encodeURIComponent(ip)}`,
      ),

    // Discovery
    startDiscovery: (req: { cidr: string; ports?: number[] }) =>
      http.post<DiscoveryJob>('/v1/admin/discovery/', req),
    getDiscovery: () =>
      http.get<DiscoveryStatus>('/v1/admin/discovery/'),
    cancelDiscovery: () =>
      http.post<void>('/v1/admin/discovery/cancel', {}),
    importDiscovery: (req: DiscoveryImportReq) =>
      http.post<DiscoveryImportResp>('/v1/admin/discovery/import', req),
  };
}

export type ManageApi = ReturnType<typeof createManageApi>;
