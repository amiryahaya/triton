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
