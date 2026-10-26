import { render } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { vi } from 'vitest'
import { setSession, type Role } from '../api/client'
import { AuthProvider } from '../auth'

type Handler = (url: URL, init?: RequestInit) => unknown | Response
export const calls: { method: string; url: string; body?: string }[] = []

/** Installs a fetch mock: routes are matched by "METHOD /path" (query string ignored). */
export function mockApi(routes: Record<string, Handler>) {
  calls.length = 0
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({ method, url: url.pathname + url.search, body: init?.body as string | undefined })
    const h = routes[`${method} ${url.pathname}`]
    if (!h)
      return new Response(JSON.stringify({ detail: `no mock for ${method} ${url.pathname}` }), {
        status: 500,
      })
    const out = h(url, init)
    if (out instanceof Response) return out
    return new Response(JSON.stringify(out), { status: 200, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

export const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

export function loginAs(role: Role | null) {
  setSession(role ? { access_token: 't', refresh_token: 'r', role, username: `${role}-user` } : null)
}

export function renderApp(ui: ReactElement, route = '/') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>{ui}</AuthProvider>
    </MemoryRouter>,
  )
}

export const emptyOverview = {
  window_minutes: 60,
  events_total: 0,
  events_window: 0,
  events_per_minute: 0,
  timeline: [],
  alerts_by_severity: {},
  detections_by_rule: {},
  incidents_by_status: {},
  top_src_ips: [],
  top_hosts: [],
  by_source_type: [],
  recent_alerts: [],
  collectors: [],
  search_backend: { status: 'green', backend: 'memory' },
}

export const alert = (over: Record<string, unknown> = {}) => ({
  id: 1,
  rule_id: 'SIEM-001',
  title: 'Brute-force from 198.51.100.23',
  severity: 'high',
  status: 'open',
  source: '198.51.100.23',
  host: 'web-01',
  event_count: 8,
  first_seen: '2026-01-01T00:00:00Z',
  last_seen: '2026-01-01T00:01:00Z',
  mitre: [{ technique_id: 'T1110', technique: 'Brute Force', tactic: 'Credential Access' }],
  synthetic: true,
  acknowledged_by: null,
  resolved_by: null,
  ...over,
})

export const event = (over: Record<string, unknown> = {}) => ({
  event_id: 'e1',
  '@timestamp': '2026-01-01T00:00:00Z',
  host: 'web-01',
  source_type: 'linux',
  category: 'authentication',
  action: 'ssh_login',
  outcome: 'failure',
  severity: 'low',
  user: 'root',
  src_ip: '198.51.100.23',
  dst_ip: null,
  dst_port: null,
  process_name: 'sshd',
  command_line: null,
  message: 'Failed password <img src=x onerror=alert(1)>',
  raw: 'raw',
  fields: {},
  geo: null,
  synthetic: true,
  detections: [],
  ...over,
})
