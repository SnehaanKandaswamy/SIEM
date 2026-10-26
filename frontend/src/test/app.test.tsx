import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { App } from '../App'
import { Alerts } from '../pages/Alerts'
import { Explorer } from '../pages/Explorer'
import { IncidentDetail } from '../pages/Incidents'
import { Live } from '../pages/Live'
import { Overview } from '../pages/Overview'
import { Reports } from '../pages/Reports'
import { Route, Routes } from 'react-router-dom'
import { alert, calls, emptyOverview, event, json, loginAs, mockApi, renderApp } from './helpers'

beforeEach(() => {
  sessionStorage.clear()
  loginAs(null)
})
afterEach(() => vi.unstubAllGlobals())

const page = (items: unknown[]) => ({ total: items.length, page: 1, size: 20, items })

describe('authentication', () => {
  it('shows the login form when signed out and signs in', async () => {
    mockApi({
      'POST /api/auth/login': () => ({
        access_token: 'a',
        refresh_token: 'r',
        role: 'viewer',
        username: 'vic',
      }),
      'GET /api/dashboard/overview': () => emptyOverview,
    })
    renderApp(<App />)
    await userEvent.type(screen.getByLabelText('Username'), 'vic')
    await userEvent.type(screen.getByLabelText('Password'), 'pw')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    await waitFor(() => expect(screen.getByText(/Signed in as/)).toBeInTheDocument())
    expect(JSON.parse(sessionStorage.getItem('siem.session')!).role).toBe('viewer')
  })

  it('shows an error on bad credentials and stays signed out', async () => {
    mockApi({ 'POST /api/auth/login': () => json(401, { detail: 'Invalid credentials' }) })
    renderApp(<App />)
    await userEvent.type(screen.getByLabelText('Username'), 'x')
    await userEvent.type(screen.getByLabelText('Password'), 'y')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid credentials')
    expect(sessionStorage.getItem('siem.session')).toBeNull()
  })
})

describe('permission-dependent UI', () => {
  const routes = {
    'GET /api/alerts': () => page([alert()]),
    'GET /api/dashboard/overview': () => emptyOverview,
  }
  it('viewer cannot see analyst actions, reports or admin navigation', async () => {
    loginAs('viewer')
    mockApi(routes)
    renderApp(<App />, '/alerts')
    await screen.findByText('Brute-force from 198.51.100.23')
    expect(screen.queryByRole('button', { name: 'Acknowledge' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Create incident' })).toBeNull()
    const nav = screen.getByRole('navigation', { name: 'Main' })
    expect(within(nav).queryByText('Reports')).toBeNull()
    expect(within(nav).queryByText('Administration')).toBeNull()
  })

  it('analyst sees actions but not administration; direct URL is guarded', async () => {
    loginAs('analyst')
    mockApi(routes)
    renderApp(<App />, '/admin')
    expect(await screen.findByText(/do not have permission/)).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Main' })
    expect(within(nav).getByText('Reports')).toBeInTheDocument()
    expect(within(nav).queryByText('Administration')).toBeNull()
  })

  it('admin sees administration', async () => {
    loginAs('admin')
    mockApi({ ...routes, 'GET /api/users': () => [] })
    renderApp(<App />, '/admin')
    expect(await screen.findByRole('tab', { name: 'Users' })).toBeInTheDocument()
  })
})

describe('overview', () => {
  it('renders live backend numbers, never placeholders', async () => {
    loginAs('viewer')
    mockApi({
      'GET /api/dashboard/overview': () => ({
        window_minutes: 60,
        events_total: 1234,
        events_window: 99,
        events_per_minute: 1.65,
        timeline: [{ t: '2026-01-01T00:00:00Z', count: 5 }],
        alerts_by_severity: { critical: 2, high: 3 },
        detections_by_rule: { 'SIEM-001': 4 },
        incidents_by_status: { open: 2, resolved: 1 },
        top_src_ips: [{ key: '198.51.100.23', count: 8 }],
        top_hosts: [{ key: 'web-01', count: 8 }],
        by_source_type: [],
        recent_alerts: [],
        collectors: [
          {
            name: 'fluent-bit',
            source_type: 'linux',
            events_total: 10,
            errors_total: 0,
            last_seen: '2026-01-01T00:00:00Z',
            healthy: true,
          },
        ],
        search_backend: { status: 'green', backend: 'opensearch' },
      }),
    })
    renderApp(<Overview />)
    expect(await screen.findByText('1,234')).toBeInTheDocument()
    expect(screen.getByText('1.65/min')).toBeInTheDocument()
    expect(screen.getByText('2 / 1')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.23')).toBeInTheDocument()
  })

  it('shows an error state with retry when the API fails', async () => {
    loginAs('viewer')
    let n = 0
    mockApi({
      'GET /api/dashboard/overview': () =>
        n++ === 0
          ? json(503, { detail: 'Search backend unavailable' })
          : {
              window_minutes: 60,
              events_total: 7,
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
            },
    })
    renderApp(<Overview />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Search backend unavailable')
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('7')).toBeInTheDocument()
  })
})

describe('alerts workflow', () => {
  it('acknowledges selected alerts and reports the result', async () => {
    loginAs('analyst')
    mockApi({
      'GET /api/alerts': () => page([alert()]),
      'POST /api/alerts/1/acknowledge': () => alert({ status: 'acknowledged' }),
    })
    renderApp(<Alerts />)
    await userEvent.click(await screen.findByLabelText('Select alert 1'))
    await userEvent.click(screen.getByRole('button', { name: 'Acknowledge' }))
    expect(await screen.findByRole('status')).toHaveTextContent('1 alert(s) updated')
    expect(calls.some((c) => c.method === 'POST' && c.url === '/api/alerts/1/acknowledge')).toBe(true)
  })

  it('surfaces a failed action instead of silently succeeding', async () => {
    loginAs('analyst')
    mockApi({
      'GET /api/alerts': () => page([alert()]),
      'POST /api/alerts/1/resolve': () => json(409, { detail: 'Alert already resolved' }),
    })
    renderApp(<Alerts />)
    await userEvent.click(await screen.findByLabelText('Select alert 1'))
    await userEvent.click(screen.getByRole('button', { name: 'Resolve' }))
    expect(await screen.findByRole('status')).toHaveTextContent('1 of 1 failed')
  })

  it('applies severity filters and sorting through the API query', async () => {
    loginAs('viewer')
    mockApi({ 'GET /api/alerts': () => page([alert()]) })
    renderApp(<Alerts />)
    await screen.findByText('Brute-force from 198.51.100.23')
    await userEvent.click(screen.getByLabelText('high'))
    await waitFor(() => expect(calls.at(-1)!.url).toContain('severity=high'))
    await userEvent.click(screen.getByRole('button', { name: /Events/ }))
    await waitFor(() => expect(calls.at(-1)!.url).toContain('sort=event_count'))
  })

  it('shows an empty state', async () => {
    loginAs('viewer')
    mockApi({ 'GET /api/alerts': () => page([]) })
    renderApp(<Alerts />)
    expect(await screen.findByText('No alerts match these filters.')).toBeInTheDocument()
  })
})

describe('incident workflow', () => {
  const incident = (over = {}) => ({
    id: 5,
    title: 'Possible intrusion',
    severity: 'high',
    status: 'open',
    assignee: null,
    assignee_id: null,
    resolution_summary: '',
    created_by: 'ana',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    alert_count: 1,
    alerts: [
      {
        id: 1,
        title: 'Brute-force',
        severity: 'high',
        status: 'open',
        rule_id: 'SIEM-001',
        last_seen: '2026-01-01T00:00:00Z',
      },
    ],
    notes: [{ id: 1, author: 'ana', body: '<script>alert(1)</script>', created_at: '2026-01-01T00:00:00Z' }],
    history: [{ id: 1, actor: 'ana', action: 'created', detail: '', created_at: '2026-01-01T00:00:00Z' }],
    events: [],
    ...over,
  })
  const view = () =>
    renderApp(
      <Routes>
        <Route path="/incidents/:id" element={<IncidentDetail />} />
      </Routes>,
      '/incidents/5',
    )

  it('renders notes as inert text, adds a note and moves status', async () => {
    loginAs('analyst')
    mockApi({
      'GET /api/incidents/5': () => incident(),
      'POST /api/incidents/5/notes': () => ({}),
      'PATCH /api/incidents/5': () => incident({ status: 'investigating' }),
    })
    const { container } = view()
    expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(container.querySelector('script')).toBeNull()
    await userEvent.type(screen.getByLabelText('New note'), 'contained the host')
    await userEvent.click(screen.getByRole('button', { name: 'Add note' }))
    await waitFor(() =>
      expect(calls.some((c) => c.url === '/api/incidents/5/notes' && c.body!.includes('contained'))).toBe(
        true,
      ),
    )
    await userEvent.click(screen.getByRole('button', { name: 'Move to investigating' }))
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'PATCH' && c.body!.includes('investigating'))).toBe(true),
    )
  })

  it('shows backend validation errors (resolution summary required)', async () => {
    loginAs('analyst')
    mockApi({
      'GET /api/incidents/5': () => incident({ status: 'investigating' }),
      'PATCH /api/incidents/5': () =>
        json(422, { detail: 'A resolution summary is required before resolving or closing' }),
    })
    view()
    await userEvent.click(await screen.findByRole('button', { name: 'Move to resolved' }))
    expect(await screen.findByRole('status')).toHaveTextContent('resolution summary is required')
  })

  it('viewer gets a read-only incident', async () => {
    loginAs('viewer')
    mockApi({ 'GET /api/incidents/5': () => incident() })
    view()
    await screen.findByText('Related alerts')
    expect(screen.queryByLabelText('New note')).toBeNull()
    expect(screen.queryByText('Workflow')).toBeNull()
  })

  it('closed incidents are read-only for analysts', async () => {
    loginAs('analyst')
    mockApi({ 'GET /api/incidents/5': () => incident({ status: 'closed', resolution_summary: 'done' }) })
    view()
    await screen.findByText('Related alerts')
    expect(screen.queryByLabelText('New note')).toBeNull()
  })
})

describe('log explorer', () => {
  it('sends search text and filters, renders hostile log text safely, opens details', async () => {
    loginAs('viewer')
    mockApi({ 'GET /api/events/search': () => ({ total: 1, page: 1, size: 50, items: [event()] }) })
    const { container } = renderApp(<Explorer />)
    expect(await screen.findByText(/Failed password/)).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
    await userEvent.type(screen.getByLabelText('Search text'), 'failed password')
    await userEvent.type(screen.getByLabelText('Source IP'), '198.51.100.23')
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))
    await waitFor(() => {
      const u = calls.at(-1)!.url
      expect(u).toContain('q=failed+password')
      expect(u).toContain('src_ip=198.51.100.23')
    })
    await userEvent.click(screen.getByText(/Failed password/))
    expect(await screen.findByRole('dialog', { name: 'Event details' })).toBeInTheDocument()
    expect(document.querySelector('dialog img, [role=dialog] img')).toBeNull()
  })

  it('handles empty results and invalid-request errors', async () => {
    loginAs('viewer')
    mockApi({ 'GET /api/events/search': () => json(400, { detail: 'src_ip is not a valid IP address' }) })
    renderApp(<Explorer />)
    expect(await screen.findByRole('alert')).toHaveTextContent('not a valid IP')
    mockApi({ 'GET /api/events/search': () => ({ total: 0, page: 1, size: 50, items: [] }) })
    await userEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect(await screen.findByText('No events match this search.')).toBeInTheDocument()
  })
})

describe('reports export', () => {
  it('requests the selected report with filters and downloads it', async () => {
    loginAs('analyst')
    const click = vi.fn()
    vi.stubGlobal(
      'URL',
      Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:x'), revokeObjectURL: vi.fn() }),
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(click)
    mockApi({
      'GET /api/reports/alerts': () =>
        new Response('%PDF-1.4', {
          status: 200,
          headers: { 'Content-Disposition': 'attachment; filename="alerts-1.pdf"' },
        }),
    })
    renderApp(<Reports />)
    await userEvent.click(screen.getByLabelText('critical'))
    await userEvent.click(screen.getByRole('button', { name: /Generate/ }))
    expect(await screen.findByRole('status')).toHaveTextContent('Downloaded alerts-1.pdf')
    expect(calls.at(-1)!.url).toContain('/api/reports/alerts?format=pdf&severity=critical')
    expect(click).toHaveBeenCalled()
  })

  it('shows a failure when the export is forbidden', async () => {
    loginAs('analyst')
    mockApi({ 'GET /api/reports/alerts': () => json(403, { detail: "Requires role 'analyst' or higher" }) })
    renderApp(<Reports />)
    await userEvent.click(screen.getByRole('button', { name: /Generate/ }))
    expect(await screen.findByRole('status')).toHaveTextContent('Requires role')
  })
})

describe('live stream', () => {
  it('appends streamed events and keeps the buffer bounded', async () => {
    loginAs('viewer')
    const enc = new TextEncoder()
    const frames = Array.from({ length: 3 }, (_, i) =>
      enc.encode(
        `id: ${i + 1}\ndata: ${JSON.stringify({ ...event({ event_id: `s${i}`, message: `streamed ${i}` }), seq: i + 1 })}\n\n`,
      ),
    )
    const stream = new ReadableStream({
      start(c) {
        frames.forEach((f) => c.enqueue(f))
      },
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () => new Response(stream, { status: 200, headers: { 'Content-Type': 'text/event-stream' } }),
      ),
    )
    renderApp(<Live />)
    expect(await screen.findByText('streamed 2')).toBeInTheDocument()
    expect(screen.getByTestId('live-mode')).toHaveTextContent('Live (SSE)')
    await act(async () => {})
  })

  it('falls back to polling after repeated stream failures', async () => {
    loginAs('viewer')
    vi.useFakeTimers({ shouldAdvanceTime: true })
    mockApi({
      'GET /api/events/stream': () => json(500, { detail: 'boom' }),
      'GET /api/events/recent': () => ({
        items: [{ ...event({ event_id: 'p1', message: 'polled event' }), seq: 1 }],
        last_seq: 1,
      }),
    })
    renderApp(<Live />)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000)
    })
    expect(await screen.findByText('polled event')).toBeInTheDocument()
    expect(screen.getByTestId('live-mode')).toHaveTextContent(/Polling|Connecting/)
    vi.useRealTimers()
  })
})
