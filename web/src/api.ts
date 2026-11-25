export class AuthError extends Error {}

export class ApiError extends Error {
  constructor(message: string, public status: number, public data: any = null) {
    super(message);
  }
}

type Opts = { method?: "GET" | "POST"; body?: unknown };

/** Calls the penlocal API. POSTs carry the X-Penlocal header the server requires. */
export async function api<T = unknown>(path: string, opts: Opts = {}): Promise<T> {
  const init: RequestInit = { credentials: "same-origin", headers: {} };
  if (opts.method === "POST") {
    init.method = "POST";
    init.headers = { "X-Penlocal": "1", "Content-Type": "application/json" };
    init.body = JSON.stringify(opts.body ?? {});
  }
  const res = await fetch("/api/" + path, init);
  let data: any = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }
  if (res.status === 401) throw new AuthError("unauthorised");
  if (!res.ok) throw new ApiError((data && data.error) || res.statusText, res.status, data);
  return data as T;
}

export const enc = encodeURIComponent;

export const fileUrl = (jobId: string, name: string) => `/api/jobs/${enc(jobId)}/files/${enc(name)}`;
