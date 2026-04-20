// Manage Server DTOs — field names match the Go JSON shape verbatim
// (snake_case). We intentionally preserve casing to match reportServer
// and licenseServer, and to avoid a silent-rename layer between HTTP
// and the UI. Convert at display time, not at the wire.

export interface SetupStatus {
  admin_created: boolean;
  license_activated: boolean;
  setup_required: boolean;
}

export interface CreateAdminReq {
  email: string;
  name: string;
  password: string;
}

export interface CreateAdminResp {
  ok: boolean;
  user_id: string;
}

export interface ActivateLicenseReq {
  license_server_url: string;
  license_key: string;
}

export interface ActivateLicenseResp {
  ok: boolean;
  features: Record<string, boolean>;
  limits: Record<string, unknown>;
}

export interface LoginResp {
  token: string;
  expires_at: string;
  must_change_password: boolean;
}

export interface ManageUser {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'network_engineer';
  must_change_pw: boolean;
  created_at: string;
  updated_at: string;
}

export interface Zone {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Host {
  id: string;
  hostname: string;
  ip?: string;
  zone_id?: string;
  os: string;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateHostReq {
  hostname: string;
  ip?: string;
  zone_id?: string;
  os?: string;
}

export interface UpdateHostReq {
  hostname: string;
  ip?: string;
  zone_id?: string;
  os?: string;
}

export type AgentStatus = 'pending' | 'active' | 'revoked';

export interface Agent {
  id: string;
  name: string;
  zone_id?: string;
  cert_serial: string;
  cert_expires_at: string;
  status: AgentStatus;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}

export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanJobProfile = 'quick' | 'standard' | 'comprehensive';

export interface ScanJob {
  id: string;
  tenant_id: string;
  zone_id?: string;
  host_id?: string;
  profile: ScanJobProfile;
  credentials_ref?: string;
  status: ScanJobStatus;
  cancel_requested: boolean;
  worker_id?: string;
  enqueued_at: string;
  started_at?: string;
  finished_at?: string;
  running_heartbeat_at?: string;
  progress_text: string;
  error_message: string;
}

export interface EnqueueReq {
  zones: string[];
  target_filter?: string;
  profile: ScanJobProfile;
  credentials_ref?: string;
}

export interface PushStatus {
  queue_depth: number;
  oldest_row_age_seconds: number;
  last_push_error: string;
  consecutive_failures: number;
  last_pushed_at?: string;
}

export interface CreateUserReq {
  email: string;
  name: string;
  role: 'admin' | 'network_engineer';
}

export interface CreateUserResp {
  id: string;
  email: string;
  role: string;
  temp_password: string;
}

export interface LimitPair {
  cap: number;
  used: number;
}

export interface ScansLimitPair extends LimitPair {
  soft_buffer_ceiling: number;
}

export interface LicenceSummary {
  tier: string;
  features: Record<string, boolean>;
  limits: {
    seats: LimitPair;
    hosts: LimitPair;
    agents: LimitPair;
    scans: ScansLimitPair;
  };
  license_server_url: string;
  instance_id: string;
  last_pushed_at: string | null;
  last_push_error: string;
  consecutive_failures: number;
}

// SettingsSummary mirrors pkg/manageserver.SettingsSummary — the
// read-only runtime config exposed at GET /v1/admin/settings. Field
// names are snake_case to match the Go JSON shape 1:1 (no rename layer).
export interface SettingsSummary {
  parallelism: number;
  gateway_listen: string;
  gateway_hostname: string;
  report_server_url: string;
  manage_listen: string;
  instance_id: string;
  version: string;
}

// GatewayHealthResponse mirrors pkg/manageserver.GatewayHealthResponse —
// the read-only gateway cert/listener state exposed at
// GET /v1/admin/gateway-health. Field names are snake_case to match the
// Go JSON shape 1:1 (no rename layer).
export interface GatewayHealthResponse {
  ca_bootstrapped: boolean;
  listener_state: 'pending_setup' | 'retry_loop' | 'up' | 'failed';
  cert_expires_at: string | null;
  cert_days_remaining: number;
}
