import { useCallback, useEffect, useState } from 'react';

export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api${path}`, { credentials: 'same-origin', ...options });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: `Local server returned HTTP ${response.status}.` }));
    const detail = Array.isArray(body.detail)
      ? body.detail.map((item: { msg: string; loc: string[] }) => `${item.loc?.slice(1).join('.') || 'Input'}: ${item.msg}`).join(' ')
      : String(body.detail || 'The request failed. Try again.');
    throw new ApiError(detail, response.status);
  }
  return response.json() as Promise<T>;
}

export function send<T>(path: string, body: unknown, method = 'POST') {
  return request<T>(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

export function useResource<T>(path: string | null, version = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(Boolean(path));
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => setAttempt(value => value + 1), []);
  useEffect(() => {
    if (!path) { setData(null); setLoading(false); return; }
    const controller = new AbortController();
    setLoading(true);
    setError('');
    request<T>(path, { signal: controller.signal })
      .then(result => { if (!controller.signal.aborted) setData(result); })
      .catch(error => { if (!controller.signal.aborted) setError(error instanceof Error ? error.message : 'The local server could not be reached.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [path, version, attempt]);
  return { data, error, loading, reload };
}
