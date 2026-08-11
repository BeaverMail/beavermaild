// Types and client for Beaver /api/v1 (cookie + optional Bearer).
export type Account = {
  email: string
  role: string
  tenant_id: number
}

export type Domain = {
  id: number
  name: string
  tenant_id: number
}

export type Tenant = {
  id: number
  name: string
}

export type ListedAccount = {
  id: number
  local_part: string
  email: string
  role: string
  tenant_id: number
  active: boolean
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

let bearer = ''

/** Stores Bearer after login (cookie is primary; Bearer helps Vite proxy edge cases). */
export function setBearer(token: string) {
  bearer = token
}

/** Clears in-memory Bearer on logout. */
export function clearBearer() {
  bearer = ''
}

type ApiOpts = {
  method?: string
  body?: unknown
}

/** JSON fetch against /api/v1 with credentials and optional Bearer. */
export async function api<T>(path: string, opts: ApiOpts = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json'
  }
  if (bearer) {
    headers.Authorization = `Bearer ${bearer}`
  }
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  const res = await fetch(`/api/v1${path}`, {
    method: opts.method ?? (opts.body !== undefined ? 'POST' : 'GET'),
    credentials: 'include',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined
  })
  if (!res.ok) {
    let msg = res.statusText
    try {
      const j = (await res.json()) as { error?: string }
      if (j.error) msg = j.error
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, msg)
  }
  if (res.status === 204) {
    return undefined as T
  }
  return (await res.json()) as T
}

/** Login and keep Bearer for subsequent calls. */
export async function login(email: string, password: string): Promise<Account> {
  const out = await api<{ token: string; account: Account }>('/auth/login', {
    body: { email, password }
  })
  setBearer(out.token)
  return out.account
}

/** Logout clears cookie (server) and Bearer (client). */
export async function logout(): Promise<void> {
  try {
    await api('/auth/logout', { method: 'POST' })
  } finally {
    clearBearer()
  }
}

export async function fetchMe(): Promise<Account> {
  return api<Account>('/me')
}

export async function fetchDomains(): Promise<Domain[]> {
  const out = await api<{ domains: Domain[] }>('/domains')
  return out.domains ?? []
}

export async function fetchTenants(): Promise<Tenant[]> {
  const out = await api<{ tenants: Tenant[] }>('/tenants')
  return out.tenants ?? []
}

export async function fetchAccounts(domain: string): Promise<ListedAccount[]> {
  const out = await api<{ accounts: ListedAccount[] }>(`/domains/${encodeURIComponent(domain)}/accounts`)
  return out.accounts ?? []
}
