const TOKEN_STORAGE_KEY = 'ninehr_auth_token';

export function getStoredToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage quota issues in restricted browsers
  }
}

export class ApiError extends Error {
  public readonly status: number;
  public readonly data: Record<string, unknown>;

  constructor(message: string, status: number, data: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

export async function apiRequest<T = unknown>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getStoredToken();
  const headers = new Headers(options.headers || {});
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  const contentType = response.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');
  const data = isJson ? await response.json() : {};

  if (!response.ok) {
    const msg =
      (data && typeof data.error === 'string' && data.error) ||
      `Request failed (${response.status})`;
    throw new ApiError(msg, response.status, data);
  }

  return data as T;
}

export async function fetchAuthorizedBlobUrl(url: string): Promise<string> {
  const token = getStoredToken();
  const headers = new Headers();
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const resp = await fetch(url, { headers, credentials: 'include' });
  if (!resp.ok) {
    throw new Error(`Unable to load file (${resp.status})`);
  }
  const blob = await resp.blob();
  return URL.createObjectURL(blob);
}
