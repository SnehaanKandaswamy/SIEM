// Typed API client. Tokens live in sessionStorage (cleared when the tab closes); see docs/SECURITY.md.

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical'
export type Role = 'viewer' | 'analyst' | 'admin'
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']

export interface Session {
  access_token: string
  refresh_token: string
  role: Role
  username: string
}

export interface Alert {
  id: number
  rule_id: string
  title: string
  severity: Severity
  status: 'open' | 'acknowledged' | 'resolved'
  source: string
  host: string
  event_count: number
  first_seen: string
  last_seen: string
  mitre: { technique_id: string; technique: string; tactic: string }[]
  synthetic: boolean
  acknowledged_by: string | null
  resolved_by: string | null
}
export interface AlertDetail extends Alert {
  evidence: Record<string, unknown>
  event_ids: string[]
  correlation_key: string
}
export interface SiemEvent {
  event_id: string
  '@timestamp': string
  host: string
  source_type: string
  category: string
  action: string
  outcome: string
  severity: Severity
  user: string | null
  src_ip: string | null
  dst_ip: string | null
  dst_port: number | null
  process_name: string | null
  command_line: string | null
  message: string
  raw: string
  fields: Record<string, unknown>
  geo: { scope: string; located: boolean; country?: string; city?: string } | null
  synthetic: boolean
  detections: string[]
  seq?: number
}
export interface Page<T> {
  total: number
  page: number
  size: number
  items: T[]
}
export interface Incident {
  id: number
  title: string
  severity: Severity
  status: 'open' | 'investigating' | 'resolved' | 'closed'
  assignee: string | null
  assignee_id: number | null
  resolution_summary: string
  created_by: string
  created_at: string
  updated_at: string
  alert_count: number
}
export interface IncidentDetail extends Incident {
  alerts: Pick<Alert, 'id' | 'title' | 'severity' | 'status' | 'rule_id' | 'last_seen'>[]
  notes: { id: number; author: string; body: string; created_at: string }[]
  history: { id: number; actor: string; action: string; detail: string; created_at: string }[]
  events: SiemEvent[]
}
export interface Overview {
  window_minutes: number
  events_total: number
  events_window: number
  events_per_minute: number
  timeline: { t: string; count: number }[]
  alerts_by_severity: Partial<Record<Severity, number>>
  detections_by_rule: Record<string, number>
  incidents_by_status: Record<string, number>
  top_src_ips: { key: string; count: number }[]
  top_hosts: { key: string; count: number }[]
  by_source_type: { key: string; count: number }[]
  recent_alerts: {
    id: number
    title: string
    severity: Severity
    last_seen: string
    rule_id: string
    status: string
  }[]
  collectors: {
    name: string
    source_type: string
    events_total: number
    errors_total: number
    last_seen: string
    healthy: boolean
  }[]
  search_backend: { status: string; backend: string }
}
export interface User {
  id: number
  username: string
  email: string
  role: Role
  is_active: boolean
}
export interface Rule {
  rule_id: string
  name: string
  description: string
  enabled: boolean
  severity: Severity
  config: Record<string, unknown>
  mitre: { technique_id: string; technique: string; tactic: string }[]
}
export interface Mitre {
  techniques: {
    technique_id: string
    technique: string
    tactic: string
    url: string
    alert_count: number
    by_severity: Record<string, number>
    rules: { rule_id: string; name: string; enabled: boolean }[]
  }[]
  unmapped_rules: { rule_id: string; name: string; reason: string }[]
  reference: string
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

const KEY = 'siem.session'
let session: Session | null = null
let onLogout: (() => void) | null = null

export function loadSession(): Session | null {
  if (session) return session
  try {
    const raw = sessionStorage.getItem(KEY)
    session = raw ? (JSON.parse(raw) as Session) : null
  } catch {
    session = null
  }
  return session
}
export function setSession(s: Session | null) {
  session = s
  try {
    if (s) sessionStorage.setItem(KEY, JSON.stringify(s))
    else sessionStorage.removeItem(KEY)
  } catch {
    /* storage unavailable: session lives in memory only */
  }
}
export function setLogoutHandler(fn: () => void) {
  onLogout = fn
}

function qs(params?: Record<string, unknown>): string {
  if (!params) return ''
  const u = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    if (Array.isArray(v)) v.forEach((x) => u.append(k, String(x)))
    else u.append(k, String(v))
  }
  const s = u.toString()
  return s ? `?${s}` : ''
}

async function refresh(): Promise<boolean> {
  const s = loadSession()
  if (!s) return false
  const r = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: s.refresh_token }),
  })
  if (!r.ok) return false
  setSession((await r.json()) as Session)
  return true
}

export async function raw(path: string, init: RequestInit = {}, retry = true): Promise<Response> {
  const s = loadSession()
  const headers = new Headers(init.headers)
  if (s) headers.set('Authorization', `Bearer ${s.access_token}`)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  let res: Response
  try {
    res = await fetch(path, { ...init, headers })
  } catch {
    throw new ApiError(0, 'Network error: the API is unreachable')
  }
  if (res.status === 401 && retry && s && !path.startsWith('/api/auth/')) {
    if (await refresh()) return raw(path, init, false)
    setSession(null)
    onLogout?.()
  }
  if (!res.ok) {
    let msg = res.statusText
    try {
      const body = await res.json()
      msg = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? body)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, msg)
  }
  return res
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  return (await raw(path, init)).json() as Promise<T>
}
const post = <T>(path: string, body?: unknown) =>
  json<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
const patch = <T>(path: string, body: unknown) =>
  json<T>(path, { method: 'PATCH', body: JSON.stringify(body) })

export const api = {
  login: async (username: string, password: string): Promise<Session> => {
    const s = await post<Session>('/api/auth/login', { username, password })
    setSession(s)
    return s
  },
  me: () => json<User>('/api/auth/me'),
  overview: (minutes = 60) => json<Overview>(`/api/dashboard/overview${qs({ minutes })}`),
  geo: () =>
    json<{
      points: {
        ip: string
        country: string
        city: string
        lat: number
        lon: number
        count: number
        rules: string[]
      }[]
      unlocated_events: number
    }>('/api/dashboard/geo'),
  alerts: (p: Record<string, unknown>) => json<Page<Alert>>(`/api/alerts${qs(p)}`),
  alert: (id: number) => json<{ alert: AlertDetail; events: SiemEvent[] }>(`/api/alerts/${id}`),
  ackAlert: (id: number) => post<Alert>(`/api/alerts/${id}/acknowledge`),
  resolveAlert: (id: number) => post<Alert>(`/api/alerts/${id}/resolve`),
  incidents: (p: Record<string, unknown>) => json<Page<Incident>>(`/api/incidents${qs(p)}`),
  incident: (id: number) => json<IncidentDetail>(`/api/incidents/${id}`),
  createIncident: (title: string, alert_ids: number[]) =>
    post<Incident>('/api/incidents', { title, alert_ids }),
  updateIncident: (
    id: number,
    body: Partial<{ status: string; assignee_id: number; resolution_summary: string }>,
  ) => patch<Incident>(`/api/incidents/${id}`, body),
  addNote: (id: number, body: string) => post(`/api/incidents/${id}/notes`, { body }),
  search: (p: Record<string, unknown>) => json<Page<SiemEvent>>(`/api/events/search${qs(p)}`),
  recent: (after: number) =>
    json<{ items: SiemEvent[]; last_seq: number }>(`/api/events/recent${qs({ after })}`),
  mitre: () => json<Mitre>('/api/mitre'),
  rules: () => json<Rule[]>('/api/rules'),
  updateRule: (
    id: string,
    body: Partial<{ enabled: boolean; severity: Severity; config: Record<string, unknown> }>,
  ) => patch<Rule>(`/api/rules/${id}`, body),
  users: () => json<User[]>('/api/users'),
  createUser: (b: { username: string; email: string; password: string; role: Role }) =>
    post<User>('/api/users', b),
  updateUser: (id: number, b: Partial<{ role: Role; is_active: boolean; password: string }>) =>
    patch<User>(`/api/users/${id}`, b),
  audit: (p: Record<string, unknown>) =>
    json<
      Page<{
        id: number
        actor: string
        action: string
        target: string
        outcome: string
        detail: string
        remote_ip: string
        created_at: string
      }>
    >(`/api/admin/audit${qs(p)}`),
  collectors: () => json<Overview['collectors']>('/api/admin/collectors'),
  integrations: () =>
    json<{
      email: { configured: boolean; min_severity: string; host: string; to: string }
      slack: { configured: boolean; min_severity: string }
      geoip: { mmdb_configured: boolean; static_configured: boolean }
      deliveries: Record<string, number>
    }>('/api/admin/integrations'),
  testNotify: (channel: 'email' | 'slack') =>
    post<{ status: string }>(`/api/admin/integrations/test?channel=${channel}`),
  settings: () => json<Record<string, unknown>>('/api/admin/settings'),
  demoIngest: (scenario = 'all') =>
    post<{ indexed: number; alerts_created: number }>(`/api/demo/ingest?scenario=${scenario}`),
  diagnostics: () =>
    json<{ recent_parse_errors: { at: string; collector: string; error: string; snippet: string }[] }>(
      '/api/ingest/diagnostics',
    ),
  download: async (path: string, params: Record<string, unknown>) => {
    const res = await raw(`${path}${qs(params)}`)
    const blob = await res.blob()
    const cd = res.headers.get('Content-Disposition') ?? ''
    const name = /filename="([^"]+)"/.exec(cd)?.[1] ?? 'report'
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    return name
  },
  /** Authenticated server-sent-events reader (EventSource cannot send Authorization headers). */
  async stream(onEvent: (e: SiemEvent) => void, signal: AbortSignal) {
    const res = await raw('/api/events/stream', { signal, headers: { Accept: 'text/event-stream' } })
    if (!res.body) throw new ApiError(0, 'Streaming not supported')
    const reader = res.body.getReader()
    const dec = new TextDecoder()
    let buf = ''
    for (;;) {
      const { done, value } = await reader.read()
      if (done) return
      buf += dec.decode(value, { stream: true })
      let i: number
      while ((i = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, i)
        buf = buf.slice(i + 2)
        const line = chunk.split('\n').find((l) => l.startsWith('data: '))
        if (line) {
          try {
            onEvent(JSON.parse(line.slice(6)) as SiemEvent)
          } catch {
            /* ignore malformed frame */
          }
        }
      }
    }
  },
}
