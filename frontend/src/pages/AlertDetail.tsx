import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, type SiemEvent } from '../api/client'
import { useAuth } from '../auth'
import { EventDetail } from '../components/EventDetail'
import { EventTable } from '../components/EventTable'
import { PageHeader, SevBadge, State, SyntheticTag, fmt } from '../components/ui'
import { useAsync } from '../hooks'

export function AlertDetail() {
  const { id } = useParams()
  const nav = useNavigate()
  const { can } = useAuth()
  const alertId = Number(id)
  const { data, error, loading, reload } = useAsync(() => api.alert(alertId), [alertId])
  const [selected, setSelected] = useState<SiemEvent | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  async function run(fn: () => Promise<unknown>, ok: string) {
    try {
      await fn()
      setMsg({ ok: true, text: ok })
      reload()
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Action failed' })
    }
  }
  async function createIncident() {
    const title = window.prompt('Incident title', 'Investigation: ' + (data?.alert.title ?? ''))
    if (!title) return
    try {
      const inc = await api.createIncident(title, [alertId])
      nav(`/incidents/${inc.id}`)
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Failed to create incident' })
    }
  }

  const a = data?.alert
  const evidence = a?.evidence ?? {}
  const { samples: _samples, ...summary } = evidence as Record<string, unknown>
  void _samples
  return (
    <>
      <PageHeader title={a ? a.title : `Alert #${id}`}>
        <Link to="/alerts" className="btn">
          ← All alerts
        </Link>
        {can('analyst') && a && (
          <>
            <button
              className="btn"
              disabled={a.status !== 'open'}
              onClick={() => run(() => api.ackAlert(alertId), 'Alert acknowledged')}
            >
              Acknowledge
            </button>
            <button
              className="btn"
              disabled={a.status === 'resolved'}
              onClick={() => run(() => api.resolveAlert(alertId), 'Alert resolved')}
            >
              Resolve
            </button>
            <button className="btn btn-primary" onClick={createIncident}>
              Create incident
            </button>
          </>
        )}
      </PageHeader>
      {msg && (
        <p role="status" className={`mb-2 text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>
          {msg.text}
        </p>
      )}
      <State loading={loading} error={error} empty={!a} onRetry={reload}>
        {a && data && (
          <div className="space-y-4">
            <div className="card grid gap-2 text-sm md:grid-cols-3">
              <div>
                <SevBadge sev={a.severity} /> <SyntheticTag show={a.synthetic} />
              </div>
              <div>
                Status: <b>{a.status}</b>
              </div>
              <div>
                Rule: <b>{a.rule_id}</b>
              </div>
              <div>Host: {a.host}</div>
              <div>Source: {a.source}</div>
              <div>Events: {a.event_count}</div>
              <div>First seen: {fmt(a.first_seen)}</div>
              <div>Last seen: {fmt(a.last_seen)}</div>
              <div>
                MITRE:{' '}
                {a.mitre.length === 0
                  ? 'no technique mapping'
                  : a.mitre.map((m) => `${m.technique_id} ${m.technique} (${m.tactic})`).join(', ')}
              </div>
              {a.acknowledged_by && <div>Acknowledged by {a.acknowledged_by}</div>}
              {a.resolved_by && <div>Resolved by {a.resolved_by}</div>}
            </div>
            <div className="card">
              <h2 className="mb-2 font-semibold">Detection evidence</h2>
              <pre className="whitespace-pre-wrap break-all text-xs">{JSON.stringify(summary, null, 2)}</pre>
            </div>
            <div>
              <h2 className="mb-2 font-semibold">Supporting events ({data.events.length})</h2>
              {data.events.length === 0 ? (
                <p className="card text-slate-400">
                  Supporting events are no longer available (retention) or not yet indexed.
                </p>
              ) : (
                <EventTable events={data.events} onSelect={setSelected} />
              )}
            </div>
          </div>
        )}
      </State>
      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}
    </>
  )
}
