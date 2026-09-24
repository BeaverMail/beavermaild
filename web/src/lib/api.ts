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
  catch_all?: string
  mail_hostname?: string
  ssl_mode?: string
  dkim_enabled?: boolean
  dkim_selector?: string
  dkim_dns_name?: string
  dkim_dns_value?: string
  antispam?: boolean
  send_max_messages?: number
  send_window?: string
  storage_bytes?: number
  messages_quota?: number
  relay_host?: string
  relay_user?: string
  relay_starttls?: boolean
  account_count: number
  storage_used: number
  ssl_active: boolean
  dkim_active: boolean
  antispam_active: boolean
}

export type CreateDomainInput = {
  name: string
  tenant_id?: number
  catch_all?: string
  mail_hostname?: string
  ssl_mode?: string
  cert_pem?: string
  key_pem?: string
  dkim_enabled?: boolean
  antispam?: boolean
  send_max_messages?: number
  send_window?: string
  storage_bytes?: number
  messages_quota?: number
  relay_host?: string
  relay_user?: string
  relay_password?: string
  relay_starttls?: boolean
}

export type PatchDomainInput = Omit<CreateDomainInput, 'name' | 'tenant_id'>

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

export async function fetchSetup(): Promise<{ needed: boolean }> {
  return api<{ needed: boolean }>('/setup')
}

/** First-install bootstrap; returns session like login. */
export async function bootstrapSetup(email: string, password: string): Promise<Account> {
  const out = await api<{ token: string; account: Account }>('/setup', {
    body: { email, password }
  })
  setBearer(out.token)
  const { markSetupComplete } = await import('$lib/setup')
  markSetupComplete()
  return out.account
}

export async function fetchDomains(): Promise<Domain[]> {
  const out = await api<{ domains: Domain[] }>('/domains')
  return out.domains ?? []
}

export async function fetchTenants(): Promise<Tenant[]> {
  const out = await api<{ tenants: Tenant[] }>('/tenants')
  return out.tenants ?? []
}

export async function createTenant(name: string): Promise<Tenant> {
  return api<Tenant>('/tenants', { body: { name } })
}

export async function patchTenant(id: number, name: string): Promise<Tenant> {
  return api<Tenant>(`/tenants/${id}`, { method: 'PATCH', body: { name } })
}

export async function deleteTenant(id: number, confirmName: string): Promise<void> {
  await api(`/tenants/${id}`, { method: 'DELETE', body: { confirm: confirmName } })
}

export async function fetchAccounts(domain: string): Promise<ListedAccount[]> {
  const out = await api<{ accounts: ListedAccount[] }>(`/domains/${encodeURIComponent(domain)}/accounts`)
  return out.accounts ?? []
}

export async function createDomain(input: CreateDomainInput): Promise<Domain> {
  const body: Record<string, unknown> = { name: input.name }
  if (input.tenant_id !== undefined) body.tenant_id = input.tenant_id
  Object.assign(body, domainHostingBody(input))
  return api<Domain>('/domains', { body })
}

export async function fetchDomain(name: string): Promise<Domain> {
  return api<Domain>(`/domains/${encodeURIComponent(name)}`)
}

export async function patchDomain(name: string, input: PatchDomainInput): Promise<Domain> {
  return api<Domain>(`/domains/${encodeURIComponent(name)}`, {
    method: 'PATCH',
    body: domainHostingBody(input)
  })
}

function domainHostingBody(input: PatchDomainInput): Record<string, unknown> {
  const body: Record<string, unknown> = {}
  body.catch_all = input.catch_all ?? ''
  body.mail_hostname = input.mail_hostname ?? ''
  body.ssl_mode = input.ssl_mode ?? 'none'
  if (input.cert_pem) body.cert_pem = input.cert_pem
  if (input.key_pem) body.key_pem = input.key_pem
  body.dkim_enabled = !!input.dkim_enabled
  body.antispam = !!input.antispam
  if (input.send_max_messages) body.send_max_messages = input.send_max_messages
  if (input.send_window) body.send_window = input.send_window
  if (input.storage_bytes) body.storage_bytes = input.storage_bytes
  if (input.messages_quota) body.messages_quota = input.messages_quota
  body.relay_host = input.relay_host ?? ''
  body.relay_user = input.relay_user ?? ''
  if (input.relay_password) body.relay_password = input.relay_password
  body.relay_starttls = !!input.relay_starttls
  return body
}

export async function deleteDomain(name: string): Promise<void> {
  await api(`/domains/${encodeURIComponent(name)}`, {
    method: 'DELETE',
    body: { confirm: name }
  })
}

export async function createAccount(
  domain: string,
  localPart: string,
  password: string,
  role?: string
): Promise<ListedAccount> {
  return api<ListedAccount>(`/domains/${encodeURIComponent(domain)}/accounts`, {
    body: { local_part: localPart, password, role: role || 'user' }
  })
}

export async function deleteAccount(email: string): Promise<void> {
  await api(`/accounts/${encodeURIComponent(email)}`, { method: 'DELETE' })
}

export async function patchAccount(
  email: string,
  patch: { role?: string; password?: string; active?: boolean }
): Promise<ListedAccount> {
  return api<ListedAccount>(`/accounts/${encodeURIComponent(email)}`, {
    method: 'PATCH',
    body: patch
  })
}

export type QueueRecipient = {
  address: string
  retry: number
  status: string
  next_due_ms: number
  last_attempt_ms: number
}

export type QueueEntry = {
  id: number
  return_path: string
  size: number
  created: number
  pending: number
  held: boolean
  recipients: QueueRecipient[]
}

/** Lists outbound queue entries (admin). Pass all=true for non-pending too. */
export async function fetchQueue(all = false): Promise<QueueEntry[]> {
  const q = all ? '?all=1' : ''
  const out = await api<{ entries: QueueEntry[] }>(`/queue${q}`)
  return out.entries ?? []
}

export async function retryQueueEntry(id: number, address?: string): Promise<void> {
  const q = address ? `?address=${encodeURIComponent(address)}` : ''
  await api(`/queue/${id}/retry${q}`, { method: 'POST', body: {} })
}

export async function holdQueueEntry(id: number): Promise<void> {
  await api(`/queue/${id}/hold`, { method: 'POST', body: {} })
}

export async function unholdQueueEntry(id: number): Promise<void> {
  await api(`/queue/${id}/unhold`, { method: 'POST', body: {} })
}

export async function cancelQueueEntry(id: number): Promise<void> {
  await api(`/queue/${id}`, { method: 'DELETE' })
}

export type DeliveryProbeStep = {
  name: string
  ok: boolean
  detail?: string
  error?: string
}

export type DeliveryProbeResult = {
  ok: boolean
  mode: string
  domain?: string
  host?: string
  steps: DeliveryProbeStep[]
}

export type DeliveryStatus = {
  relay_configured: boolean
  relay: string
}

/** Admin outbound delivery options (relay presence, no secrets). */
export async function fetchDeliveryStatus(): Promise<DeliveryStatus> {
  return api<DeliveryStatus>('/delivery')
}

/** Admin outbound connectivity probe (no message sent). */
export async function runDeliveryTest(body: {
  to?: string
  mode?: 'auto' | 'mx' | 'relay'
}): Promise<DeliveryProbeResult> {
  return api<DeliveryProbeResult>('/delivery/test', { method: 'POST', body })
}

export type ServiceStatus = {
  id: string
  name: string
  listen?: string
  state: 'up' | 'down' | 'disabled' | 'error' | string
  error?: string
}

/** Admin process/listener status. */
export async function fetchServicesStatus(): Promise<ServiceStatus[]> {
  const out = await api<{ services: ServiceStatus[] }>('/status')
  return out.services ?? []
}

export type LogEntry = {
  time: string
  level: string
  msg: string
  attrs?: Record<string, unknown>
}

/** Admin ops logs from rotating JSON file. */
export async function fetchLogs(opts?: {
  level?: string
  q?: string
  limit?: number
  before?: string
}): Promise<{ entries: LogEntry[] }> {
  const params = new URLSearchParams()
  if (opts?.level) params.set('level', opts.level)
  if (opts?.q) params.set('q', opts.q)
  if (opts?.limit) params.set('limit', String(opts.limit))
  if (opts?.before) params.set('before', opts.before)
  const qs = params.toString()
  return api<{ entries: LogEntry[] }>(`/logs${qs ? `?${qs}` : ''}`)
}

export type DnsRecord = {
  type: string
  host: string
  value: string
  placeholder?: boolean
  note?: string
}

/** Recommended DNS records for a hosted domain (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, autoconfig). */
export async function fetchDnsRecommended(domain: string): Promise<DnsRecord[]> {
  const out = await api<{ records: DnsRecord[] }>(
    `/domains/${encodeURIComponent(domain)}/dns-recommended`
  )
  return out.records ?? []
}
