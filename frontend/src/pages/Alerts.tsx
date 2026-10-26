import { useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { SEVERITIES, api } from '../api/client'
import { useAuth } from '../auth'
import { useAsync } from '../hooks'
import { PageHeader, Pagination, SevBadge, State, SyntheticTag, fmt } from '../components/ui'

const STATUSES = ['open', 'acknowledged', 'resolved']
const RULES = ['SIEM-001', 'SIEM-002', 'SIEM-003', 'SIEM-004', 'SIEM-005']

function SortTh({
  col,
  sort,
  order,
  onSort,
  children,
}: {
  col: string
  sort: string
  order: string
  onSort: (col: string) => void
  children: string
}) {
  return (
    <th className="th" aria-sort={sort === col ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button onClick={() => onSort(col)} className="uppercase">
        {children} {sort === col ? (order === 'asc' ? '▲' : '▼') : ''}
      </button>
    </th>
  )
}

export function Alerts() {
  const [sp, setSp] = useSearchParams()
  const { can } = useAuth()
  const nav = useNavigate()
  const [selected, setSelected] = useState<number[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const severity = sp.getAll('severity')
  const status = sp.getAll('status')
  const rule_id = sp.getAll('rule_id')
  const page = Number(sp.get('page') ?? 1)
  const sort = sp.get('sort') ?? 'last_seen'
  const order = sp.get('order') ?? 'desc'
  const start = sp.get('start') ?? ''
  const { data, error, loading, reload } = useAsync(
    () =>
      api.alerts({
        severity,
        status,
        rule_id,
        page,
        sort,
        order,
        size: 20,
        start: start ? new Date(start).toISOString() : undefined,
      }),
    [sp.toString()],
  )

  const set = (k: string, v: string[] | string) => {
    const n = new URLSearchParams(sp)
    n.delete(k)
    ;(Array.isArray(v) ? v : [v]).filter(Boolean).forEach((x) => n.append(k, x))
    if (k !== 'page') n.set('page', '1')
    setSp(n)
  }
  const toggleSort = (col: string) => {
    const n = new URLSearchParams(sp)
    n.set('sort', col)
    n.set('order', sort === col && order === 'desc' ? 'asc' : 'desc')
    setSp(n)
  }
  const multi = (k: string, cur: string[], opts: string[]) => (
    <fieldset className="flex flex-wrap items-center gap-1 text-xs">
      <legend className="sr-only">{k}</legend>
      <span className="mr-1 text-slate-400">{k}:</span>
      {opts.map((o) => (
        <label
          key={o}
          className={`cursor-pointer rounded border px-2 py-1 ${cur.includes(o) ? 'border-sky-500 bg-sky-900/40' : 'border-line'}`}
        >
          <input
            type="checkbox"
            className="sr-only"
            checked={cur.includes(o)}
            onChange={() => set(k, cur.includes(o) ? cur.filter((x) => x !== o) : [...cur, o])}
          />
          {o}
        </label>
      ))}
    </fieldset>
  )

  async function act(kind: 'ack' | 'resolve') {
    setBusy(kind)
    setMsg(null)
    const results = await Promise.allSettled(
      selected.map((id) => (kind === 'ack' ? api.ackAlert(id) : api.resolveAlert(id))),
    )
    const failed = results.filter((r) => r.status === 'rejected').length
    setMsg({
      ok: failed === 0,
      text: failed
        ? `${failed} of ${results.length} failed (already in that state?)`
        : `${results.length} alert(s) updated`,
    })
    setSelected([])
    setBusy(null)
    reload()
  }
  async function toIncident() {
    const title = window.prompt(
      'Incident title',
      'Investigation: ' + (data?.items.find((a) => a.id === selected[0])?.title ?? ''),
    )
    if (!title) return
    setBusy('inc')
    try {
      const inc = await api.createIncident(title, selected)
      nav(`/incidents/${inc.id}`)
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Failed to create incident' })
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <PageHeader title="Alerts">
        {can('analyst') && (
          <>
            <button className="btn" disabled={!selected.length || !!busy} onClick={() => act('ack')}>
              Acknowledge
            </button>
            <button className="btn" disabled={!selected.length || !!busy} onClick={() => act('resolve')}>
              Resolve
            </button>
            <button className="btn btn-primary" disabled={!selected.length || !!busy} onClick={toIncident}>
              Create incident
            </button>
          </>
        )}
      </PageHeader>
      <div className="card mb-3 space-y-2">
        {multi('severity', severity, SEVERITIES)}
        {multi('status', status, STATUSES)}
        {multi('rule_id', rule_id, RULES)}
        <label className="block text-xs text-slate-400">
          Since{' '}
          <input
            type="datetime-local"
            className="input"
            value={start}
            onChange={(e) => set('start', e.target.value)}
          />
        </label>
      </div>
      {msg && (
        <p role="status" className={`mb-2 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>
          {msg.text}
        </p>
      )}
      <State
        loading={loading}
        error={error}
        empty={!!data && data.items.length === 0}
        emptyText="No alerts match these filters."
        onRetry={reload}
      >
        {data && (
          <>
            <div className="card overflow-x-auto p-0">
              <table className="w-full">
                <thead className="border-b border-line">
                  <tr>
                    <th className="th w-8" />
                    <SortTh sort={sort} order={order} onSort={toggleSort} col="severity">
                      Severity
                    </SortTh>
                    <th className="th">Alert</th>
                    <th className="th">Host / source</th>
                    <SortTh sort={sort} order={order} onSort={toggleSort} col="event_count">
                      Events
                    </SortTh>
                    <SortTh sort={sort} order={order} onSort={toggleSort} col="status">
                      Status
                    </SortTh>
                    <SortTh sort={sort} order={order} onSort={toggleSort} col="last_seen">
                      Last seen
                    </SortTh>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((a) => (
                    <tr key={a.id} className="border-b border-line/50 hover:bg-panel2">
                      <td className="td">
                        {can('analyst') && (
                          <input
                            type="checkbox"
                            aria-label={`Select alert ${a.id}`}
                            checked={selected.includes(a.id)}
                            onChange={(e) =>
                              setSelected((s) =>
                                e.target.checked ? [...s, a.id] : s.filter((x) => x !== a.id),
                              )
                            }
                          />
                        )}
                      </td>
                      <td className="td">
                        <SevBadge sev={a.severity} />
                      </td>
                      <td className="td">
                        <Link className="text-sky-300 hover:underline" to={`/alerts/${a.id}`}>
                          {a.title}
                        </Link>
                        <SyntheticTag show={a.synthetic} />
                        <div className="text-xs text-slate-500">
                          {a.rule_id} {a.mitre.map((m) => m.technique_id).join(' ')}
                        </div>
                      </td>
                      <td className="td text-xs">
                        {a.host}
                        <div className="text-slate-500">{a.source}</div>
                      </td>
                      <td className="td">{a.event_count}</td>
                      <td className="td">{a.status}</td>
                      <td className="td whitespace-nowrap text-xs">{fmt(a.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} size={20} total={data.total} onPage={(p) => set('page', String(p))} />
          </>
        )}
      </State>
    </>
  )
}
