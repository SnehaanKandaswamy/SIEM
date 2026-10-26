import { useState, type FormEvent } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, type IncidentDetail as IncidentDetailT } from '../api/client'
import { useAuth } from '../auth'
import { EventDetail } from '../components/EventDetail'
import { EventTable } from '../components/EventTable'
import { PageHeader, Pagination, SevBadge, State, fmt } from '../components/ui'
import { useAsync } from '../hooks'

const STATUSES = ['open', 'investigating', 'resolved', 'closed']
// Mirrors the server-side transition table (the backend remains authoritative).
const NEXT: Record<string, string[]> = {
  open: ['investigating', 'closed'],
  investigating: ['resolved', 'open'],
  resolved: ['closed', 'investigating'],
  closed: [],
}

export function Incidents() {
  const [sp, setSp] = useSearchParams()
  const status = sp.getAll('status')
  const page = Number(sp.get('page') ?? 1)
  const { data, error, loading, reload } = useAsync(
    () => api.incidents({ status, page, size: 20 }),
    [sp.toString()],
  )
  const setStatus = (s: string) => {
    const n = new URLSearchParams()
    if (s) n.set('status', s)
    setSp(n)
  }
  return (
    <>
      <PageHeader title="Incidents">
        <label className="text-sm">
          Status{' '}
          <select className="input" value={status[0] ?? ''} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All</option>
            {STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
      </PageHeader>
      <State
        loading={loading}
        error={error}
        empty={!!data && data.items.length === 0}
        emptyText="No incidents yet. Select alerts and choose “Create incident” to start an investigation."
        onRetry={reload}
      >
        {data && (
          <>
            <div className="card overflow-x-auto p-0">
              <table className="w-full">
                <thead className="border-b border-line">
                  <tr>
                    {['#', 'Title', 'Severity', 'Status', 'Assignee', 'Alerts', 'Updated'].map((h) => (
                      <th key={h} className="th">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((i) => (
                    <tr key={i.id} className="border-b border-line/50 hover:bg-panel2">
                      <td className="td">{i.id}</td>
                      <td className="td">
                        <Link className="text-sky-300 hover:underline" to={`/incidents/${i.id}`}>
                          {i.title}
                        </Link>
                      </td>
                      <td className="td">
                        <SevBadge sev={i.severity} />
                      </td>
                      <td className="td">{i.status}</td>
                      <td className="td">
                        {i.assignee ?? <span className="text-slate-500">unassigned</span>}
                      </td>
                      <td className="td">{i.alert_count}</td>
                      <td className="td text-xs">{fmt(i.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination
              page={page}
              size={20}
              total={data.total}
              onPage={(p) => {
                const n = new URLSearchParams(sp)
                n.set('page', String(p))
                setSp(n)
              }}
            />
          </>
        )}
      </State>
    </>
  )
}

export function IncidentDetail() {
  const { id } = useParams()
  const iid = Number(id)
  const { can } = useAuth()
  const { data, error, loading, reload } = useAsync(() => api.incident(iid), [iid])
  const users = useAsync(() => (can('admin') ? api.users() : Promise.resolve([])), [])
  const [note, setNote] = useState('')
  const [summary, setSummary] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<IncidentDetailT['events'][number] | null>(null)
  const canEdit = can('analyst')

  async function run(fn: () => Promise<unknown>, ok: string) {
    try {
      await fn()
      setMsg({ ok: true, text: ok })
      reload()
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Action failed' })
    }
  }
  async function addNote(e: FormEvent) {
    e.preventDefault()
    if (!note.trim()) return
    await run(() => api.addNote(iid, note), 'Note added')
    setNote('')
  }

  const inc = data
  const closed = inc?.status === 'closed'
  return (
    <>
      <PageHeader title={inc ? `#${inc.id} ${inc.title}` : `Incident #${id}`}>
        <Link className="btn" to="/incidents">
          ← All incidents
        </Link>
      </PageHeader>
      {msg && (
        <p role="status" className={`mb-2 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>
          {msg.text}
        </p>
      )}
      <State loading={loading} error={error} empty={!inc} onRetry={reload}>
        {inc && (
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="space-y-4 lg:col-span-2">
              <div className="card grid gap-2 text-sm md:grid-cols-2">
                <div>
                  <SevBadge sev={inc.severity} /> Status: <b>{inc.status}</b>
                </div>
                <div>
                  Assignee: <b>{inc.assignee ?? 'unassigned'}</b>
                </div>
                <div>
                  Created by {inc.created_by} · {fmt(inc.created_at)}
                </div>
                <div>Updated {fmt(inc.updated_at)}</div>
              </div>

              {canEdit && !closed && (
                <div className="card space-y-3">
                  <h2 className="font-semibold">Workflow</h2>
                  <div className="flex flex-wrap gap-2">
                    {NEXT[inc.status].map((s) => (
                      <button
                        key={s}
                        className="btn"
                        onClick={() =>
                          run(
                            () =>
                              api.updateIncident(iid, {
                                status: s,
                                ...(summary !== null ? { resolution_summary: summary } : {}),
                              }),
                            `Status changed to ${s}`,
                          )
                        }
                      >
                        Move to {s}
                      </button>
                    ))}
                    {can('admin') && (users.data?.length ?? 0) > 0 && (
                      <select
                        aria-label="Assign to"
                        className="input"
                        value={inc.assignee_id ?? ''}
                        onChange={(e) =>
                          e.target.value &&
                          run(
                            () => api.updateIncident(iid, { assignee_id: Number(e.target.value) }),
                            'Assignee updated',
                          )
                        }
                      >
                        <option value="">Assign to…</option>
                        {users.data
                          ?.filter((u) => u.is_active && u.role !== 'viewer')
                          .map((u) => (
                            <option key={u.id} value={u.id}>
                              {u.username}
                            </option>
                          ))}
                      </select>
                    )}
                    {!can('admin') && (
                      <button className="btn" onClick={() => void assignMe()}>
                        Assign to me
                      </button>
                    )}
                  </div>
                  <label className="block text-sm">
                    Resolution summary (required to resolve or close)
                    <textarea
                      className="input mt-1 w-full"
                      rows={3}
                      value={summary ?? inc.resolution_summary}
                      onChange={(e) => setSummary(e.target.value)}
                    />
                  </label>
                  <button
                    className="btn"
                    disabled={summary === null}
                    onClick={() =>
                      run(
                        () => api.updateIncident(iid, { resolution_summary: summary ?? '' }),
                        'Summary saved',
                      )
                    }
                  >
                    Save summary
                  </button>
                </div>
              )}
              {closed && (
                <div className="card text-sm">
                  <b>Resolution:</b> {inc.resolution_summary}
                </div>
              )}

              <div className="card">
                <h2 className="mb-2 font-semibold">Related alerts</h2>
                <ul className="space-y-1 text-sm">
                  {inc.alerts.map((a) => (
                    <li key={a.id}>
                      <SevBadge sev={a.severity} />{' '}
                      <Link className="text-sky-300 hover:underline" to={`/alerts/${a.id}`}>
                        {a.title}
                      </Link>{' '}
                      <span className="text-xs text-slate-500">
                        {a.status} · {fmt(a.last_seen)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h2 className="mb-2 font-semibold">Related events ({inc.events.length})</h2>
                {inc.events.length === 0 ? (
                  <p className="card text-slate-400">No related events available.</p>
                ) : (
                  <EventTable events={inc.events} onSelect={setSelectedEvent} />
                )}
              </div>
            </div>

            <div className="space-y-4">
              <div className="card">
                <h2 className="mb-2 font-semibold">Investigation notes</h2>
                {inc.notes.length === 0 && <p className="text-sm text-slate-400">No notes yet.</p>}
                <ul className="space-y-2">
                  {inc.notes.map((n) => (
                    <li key={n.id} className="rounded border border-line p-2 text-sm">
                      <div className="text-xs text-slate-400">
                        {n.author} · {fmt(n.created_at)}
                      </div>
                      <div className="whitespace-pre-wrap break-words">{n.body}</div>
                    </li>
                  ))}
                </ul>
                {canEdit && !closed && (
                  <form onSubmit={addNote} className="mt-3 space-y-2">
                    <textarea
                      aria-label="New note"
                      className="input w-full"
                      rows={3}
                      value={note}
                      onChange={(e) => setNote(e.target.value)}
                      placeholder="Add an investigation note"
                    />
                    <button className="btn btn-primary" disabled={!note.trim()}>
                      Add note
                    </button>
                  </form>
                )}
              </div>
              <div className="card">
                <h2 className="mb-2 font-semibold">Audit timeline</h2>
                <ol className="space-y-2 border-l border-line pl-3 text-sm">
                  {inc.history.map((h) => (
                    <li key={h.id}>
                      <div className="font-medium">{h.action.replace(/_/g, ' ')}</div>
                      <div className="text-xs text-slate-400">
                        {h.actor} · {fmt(h.created_at)}
                      </div>
                      {h.detail && <div className="text-xs">{h.detail}</div>}
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </div>
        )}
      </State>
      {selectedEvent && <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    </>
  )

  async function assignMe() {
    try {
      const me = await api.me()
      await run(() => api.updateIncident(iid, { assignee_id: me.id }), 'Assigned to you')
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Failed to assign' })
    }
  }
}
