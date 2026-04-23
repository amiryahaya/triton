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

/**
 * createReportApi wraps an Http client with the Report Server's v1 REST
 * surface. Paths begin with `/v1/` — the caller's baseUrl is expected to
 * be `/api` so full URLs resolve to `/api/v1/...`.
 *
 * Phase 1 ships only the auth endpoints needed by TAuthGate.
 * Data + admin endpoints land alongside their views in later phases.
 */
export function createReportApi(http: Http) {
  return {
    login: (req: LoginRequest) => http.post<LoginResponse>('/v1/auth/login', req),
    logout: () => http.post<{ status: string }>('/v1/auth/logout', {}),
    refresh: () => http.post<RefreshResponse>('/v1/auth/refresh', {}),
    changePassword: (req: ChangePasswordRequest) =>
      http.post<ChangePasswordResponse>('/v1/auth/change-password', req),
  };
}

export type ReportApi = ReturnType<typeof createReportApi>;
