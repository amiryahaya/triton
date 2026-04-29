import type { Http } from './http';

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  expiresAt: string;
  mustChangePassword: boolean;
}

export interface RefreshResponse {
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

// ===== Data types (Phase 2-4) =====

export type PqcStatus = 'SAFE' | 'TRANSITIONAL' | 'DEPRECATED' | 'UNSAFE';
export type TrendDirection = 'improving' | 'declining' | 'stable' | 'insufficient';
export type UserRole = 'super_admin' | 'org_admin' | 'viewer';

export interface ScanSummary {
  id: string;
  hostname: string;
  org_id: string;
  created_at: string;
  finding_count: number;
  pqc_safe: number;
  pqc_transitional: number;
  pqc_deprecated: number;
  pqc_unsafe: number;
  readiness_pct: number;
}

export interface ScanDetail extends ScanSummary {
  result: Record<string, unknown>;
}

export interface Finding {
  id: string;
  scan_id: string;
  finding_index: number;
  subject: string;
  algorithm: string;
  key_size: number;
  pqc_status: PqcStatus;
  file_path: string;
  category: string;
  migration_priority: number;
  not_after?: string;
}

export interface SparklinePoint {
  month: string;
  readiness_pct: number;
}

export interface HostSummary {
  hostname: string;
  readiness_pct: number;
  safe_count: number;
  transitional_count: number;
  deprecated_count: number;
  unsafe_count: number;
  sparkline: SparklinePoint[];
  trend_direction: TrendDirection;
  trend_delta_pct: number;
  refreshed_at: string;
}

export interface PolicyVerdictSummary {
  policy_name: string;
  policy_label: string;
  verdict: 'PASS' | 'WARN' | 'FAIL';
  violation_count: number;
  findings_checked: number;
}

export interface MachineHealthTiers {
  red: number;
  yellow: number;
  green: number;
}

export interface TrendMonthPoint {
  month: string;
  readiness_pct: number;
  safe_count: number;
  unsafe_count: number;
}

export interface TrendSummary {
  monthly_points: TrendMonthPoint[];
  direction: TrendDirection;
  delta_pct: number;
}

export interface ProjectionSummary {
  target_pct: number;
  deadline_year: number;
  est_completion_year: number | null;
  on_track: boolean;
}

export interface ReadinessSummary {
  readiness_pct: number;
  safe_count: number;
  transitional_count: number;
  deprecated_count: number;
  unsafe_count: number;
  total_findings: number;
  machine_count: number;
}

export interface PriorityRow {
  subject: string;
  hostname: string;
  algorithm: string;
  pqc_status: PqcStatus;
  migration_priority: number;
  file_path: string;
  category: string;
}

// ===== NACSA Arahan 9 (Phase 3) =====

export interface NacsaBlocker {
  algorithm: string;
  hostname: string;
  severity: string;
  asset_count: number;
}

export interface NacsaPhase {
  phase: number;
  name: string;
  status: 'not_started' | 'in_progress' | 'complete';
  progress_pct: number;
}

export interface NacsaSummary {
  readiness_pct: number;
  target_pct: number;
  target_year: number;
  compliant: number;
  transitional: number;
  non_compliant: number;
  safe: number;
  total_assets: number;
  top_blockers: NacsaBlocker[];
  migration_phases: NacsaPhase[];
}

export interface NacsaServerRow {
  id: string;
  name: string;
  host_count: number;
  readiness_pct: number;
  last_scan_at?: string;
}

export interface NacsaHostRow {
  hostname: string;
  scan_profile?: string;
  readiness_pct: number;
  last_scan_at?: string;
  module_count: number;
}

export interface NacsaCBOMRow {
  algorithm: string;
  key_size?: number;
  pqc_status: PqcStatus;
  asset_count: number;
  module: string;
}

export interface NacsaRiskRow {
  algorithm: string;
  hostname: string;
  impact: number;
  likelihood: number;
  score: number;
  risk_band: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  asset_count: number;
}

export interface NacsaMigActivity {
  name: string;
  status: 'pending' | 'active' | 'done';
  budget_rm: number;
}

export interface NacsaMigPhase {
  phase: number;
  name: string;
  status: 'not_started' | 'in_progress' | 'complete';
  progress_pct: number;
  period: string;
  activities: NacsaMigActivity[];
  budget_total_rm: number;
  budget_spent_rm: number;
}

export interface NacsaMigResponse {
  phases: NacsaMigPhase[];
}

export interface ExecutiveSummary {
  readiness: ReadinessSummary;
  trend: TrendSummary;
  projection: ProjectionSummary;
  policy_verdicts: PolicyVerdictSummary[];
  top_blockers: PriorityRow[];
  machine_health: MachineHealthTiers;
}

export interface InventoryRow {
  algorithm: string;
  key_size: number;
  pqc_status: PqcStatus;
  instance_count: number;
  machine_count: number;
  max_priority: number;
}

export interface ExpiringCertRow {
  subject: string;
  hostname: string;
  algorithm: string;
  not_after: string;
  days_remaining: number;
  pqc_status: PqcStatus;
}

export interface FilterOptions {
  hostnames: string[];
  algorithms: string[];
  pqc_statuses: string[];
}

export interface DiffSummary {
  added: number;
  removed: number;
  changed: number;
}

export interface DiffResult {
  base_id: string;
  compare_id: string;
  added: Finding[];
  removed: Finding[];
  changed: Finding[];
  summary: DiffSummary;
}

export interface OrgTrendResult {
  monthly_points: TrendMonthPoint[];
  direction: string;
  delta_pct: number;
  data_as_of?: string;
  pipeline_lag?: number;
}

export interface AuditEvent {
  id: string;
  org_id: string;
  actor_id: string;
  actor_email: string;
  action: string;
  target_type: string;
  target_id: string;
  created_at: string;
  detail: Record<string, unknown>;
}

export interface ReportUser {
  id: string;
  org_id: string;
  email: string;
  name: string;
  role: UserRole;
  must_change_password: boolean;
  created_at: string;
}

export interface ReportUserCreate {
  email: string;
  name: string;
  role: UserRole;
  temp_password: string;
}

export interface ReportUserUpdate {
  name?: string;
  role?: UserRole;
}

export interface TenantResponse {
  id: string;
  name: string;
  licenceId: string;
  licenceStatus: 'active' | 'grace' | 'expired';
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * createReportApi wraps an Http client with the Report Server's v1 REST
 * surface. Paths begin with `/v1/` — the caller's baseUrl is expected to
 * be `/api` so full URLs resolve to `/api/v1/...`.
 */
export function createReportApi(http: Http) {
  return {
    // Auth (Phase 1 — unchanged)
    login: (req: LoginRequest) => http.post<LoginResponse>('/v1/auth/login', req),
    logout: () => http.post<{ status: string }>('/v1/auth/logout', {}),
    refresh: () => http.post<RefreshResponse>('/v1/auth/refresh', {}),
    changePassword: (req: ChangePasswordRequest) =>
      http.post<ChangePasswordResponse>('/v1/auth/change-password', req),

    // Scans (Phase 2)
    listScans: (filter?: { hostname?: string; limit?: number; offset?: number }) => {
      const qs = buildQS(filter);
      return http.get<ScanSummary[]>(`/v1/scans${qs}`);
    },
    getScan: (id: string) => http.get<ScanDetail>(`/v1/scans/${encodeURIComponent(id)}`),
    getFindings: (id: string) =>
      http.get<Finding[]>(`/v1/scans/${encodeURIComponent(id)}/findings`),

    // Machines (Phase 2)
    listMachines: () => http.get<HostSummary[]>('/v1/systems'),
    getMachineHistory: (hostname: string) =>
      http.get<ScanSummary[]>(`/v1/machines/${encodeURIComponent(hostname)}`),

    // Overview (Phase 2)
    executive: () => http.get<ExecutiveSummary>('/v1/executive'),
    aggregate: () => http.get<Record<string, number>>('/v1/aggregate'),

    // Analytics (Phase 3)
    inventory: (p?: { hostname?: string; pqc_status?: string }) =>
      http.get<InventoryRow[]>(`/v1/inventory${buildQS(p)}`),
    expiringCerts: (p?: { within?: number | 'all'; hostname?: string; algorithm?: string }) =>
      http.get<ExpiringCertRow[]>(`/v1/certificates/expiring${buildQS(p)}`),
    priority: (p?: { limit?: number; hostname?: string; pqc_status?: string }) =>
      http.get<PriorityRow[]>(`/v1/priority${buildQS(p)}`),
    filters: () => http.get<FilterOptions>('/v1/filters'),
    orgTrend: (hostname?: string) =>
      http.get<OrgTrendResult>(
        `/v1/trends${hostname ? `?hostname=${encodeURIComponent(hostname)}` : ''}`,
      ),
    diff: (base: string, compare: string) =>
      http.get<DiffResult>(
        `/v1/diff?base=${encodeURIComponent(base)}&compare=${encodeURIComponent(compare)}`,
      ),

    // NACSA Arahan 9 (Phase 3)
    nacsaSummary: (p?: { manage_server_id?: string; hostname?: string }) =>
      http.get<NacsaSummary>(`/v1/nacsa/summary${buildQS(p)}`),
    nacsaServers: () =>
      http.get<NacsaServerRow[]>('/v1/nacsa/servers'),
    nacsaHosts: (serverID: string) =>
      http.get<NacsaHostRow[]>(`/v1/nacsa/servers/${encodeURIComponent(serverID)}/hosts`),
    nacsaCBOM: (hostname: string, p?: { status?: string }) =>
      http.get<NacsaCBOMRow[]>(`/v1/nacsa/hosts/${encodeURIComponent(hostname)}/cbom${buildQS(p)}`),
    nacsaRisk: (hostname: string, p?: { sort?: string }) =>
      http.get<NacsaRiskRow[]>(`/v1/nacsa/hosts/${encodeURIComponent(hostname)}/risk${buildQS(p)}`),
    nacsaMigration: () =>
      http.get<NacsaMigResponse>('/v1/nacsa/migration'),

    // Admin users (Phase 4)
    listAdminUsers: () => http.get<ReportUser[]>('/v1/admin/users/'),
    createAdminUser: (req: ReportUserCreate) =>
      http.post<ReportUser>('/v1/admin/users/', req),
    updateAdminUser: (id: string, req: ReportUserUpdate) =>
      http.put<ReportUser>(`/v1/admin/users/${encodeURIComponent(id)}`, req),
    deleteAdminUser: (id: string) =>
      http.del<{ status: string }>(`/v1/admin/users/${encodeURIComponent(id)}`),
    resendInvite: (id: string) =>
      http.post<{ status: string }>(`/v1/admin/users/${encodeURIComponent(id)}/resend-invite`, {}),

    // Admin audit (Phase 4)
    listAudit: (filter?: { limit?: number; offset?: number; actor_id?: string }) =>
      http.get<AuditEvent[]>(`/v1/admin/audit/${buildQS(filter)}`),

    // Setup (superadmin first-run)
    setupStatus: () => http.get<{ needsSetup: boolean }>('/v1/setup/status'),
    firstSetup: (req: { name: string; email: string }) =>
      http.post<{ id: string; tempPassword: string }>('/v1/setup', req),

    // Platform admin management
    listPlatformAdmins: () => http.get<ReportUser[]>('/v1/platform/admins'),
    invitePlatformAdmin: (req: { name: string; email: string }) =>
      http.post<{ id: string; tempPassword: string }>('/v1/platform/admins', req),
    deletePlatformAdmin: (id: string) =>
      http.del<void>(`/v1/platform/admins/${encodeURIComponent(id)}`),

    // Platform tenant management
    listPlatformTenants: () => http.get<TenantResponse[]>('/v1/platform/tenants'),
    createPlatformTenant: (req: { licenceKey: string; adminName: string; adminEmail: string }) =>
      http.post<TenantResponse>('/v1/platform/tenants', req),
    getPlatformTenant: (id: string) =>
      http.get<TenantResponse>(`/v1/platform/tenants/${encodeURIComponent(id)}`),
    renewTenantLicence: (id: string, licenceKey: string) =>
      http.post<{ status: string }>(`/v1/platform/tenants/${encodeURIComponent(id)}/renew`, { licenceKey }),
    deletePlatformTenant: (id: string) =>
      http.del<void>(`/v1/platform/tenants/${encodeURIComponent(id)}`),
  };
}

// buildQS serialises a flat record into a leading-`?` query string.
// Undefined / empty values are skipped so callers can pass partial
// filter objects without conditional URL construction at call sites.
function buildQS(params?: Record<string, string | number | boolean | undefined>): string {
  if (!params) return '';
  const pairs: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return pairs.length ? `?${pairs.join('&')}` : '';
}

export type ReportApi = ReturnType<typeof createReportApi>;
