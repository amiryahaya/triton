export interface HttpConfig {
  baseUrl: string;
  authHeader: () => Record<string, string>;
  onUnauthorized?: () => void;
}

export interface Http {
  get:   <T>(path: string) => Promise<T>;
  post:  <T>(path: string, body?: unknown) => Promise<T>;
  put:   <T>(path: string, body?: unknown) => Promise<T>;
  patch: <T>(path: string, body?: unknown) => Promise<T>;
  del:   <T>(path: string) => Promise<T>;
}

export function createHttp(cfg: HttpConfig): Http {
  async function request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = cfg.baseUrl + path;
    const init: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...cfg.authHeader(),
      },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    const res = await fetch(url, init);
    if (res.status === 401) {
      cfg.onUnauthorized?.();
      throw new Error('401 Unauthorized');
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    const ct = res.headers.get('content-type') ?? '';
    if (ct.includes('application/json')) return (await res.json()) as T;
    return (await res.text()) as unknown as T;
  }

  return {
    get:   (path)       => request('GET',    path),
    post:  (path, body) => request('POST',   path, body),
    put:   (path, body) => request('PUT',    path, body),
    patch: (path, body) => request('PATCH',  path, body),
    del:   (path)       => request('DELETE', path),
  };
}
