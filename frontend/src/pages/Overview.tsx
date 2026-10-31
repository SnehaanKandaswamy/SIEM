import { useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Link } from 'react-router-dom'
import { SEVERITIES, api } from '../api/client'
import { useAsync } from '../hooks'
import { PageHeader, SEV_COLOR, SevBadge, State, fmt } from '../components/ui'

const RANGES = [
  { label: '1h', minutes: 60 },
  { label: '6h', minutes: 360 },
  { label: '24h', minutes: 1440 },
]

export function Overview() {
  const [minutes, setMinutes] = useState(60)
  const { data, error, loading, reload } = useAsync(() => api.overview(minutes), [minutes], 15000)
  const timeline = (data?.timeline ?? []).map((p) => ({
    time: new Date(p.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    count: p.count,
  }))
  const byRule = Object.entries(data?.detections_by_rule ?? {}).map(([rule, count]) => ({ rule, count }))
  const inc = data?.incidents_by_status ?? {}
  const openInc = (inc.open ?? 0) + (inc.investigating ?? 0)
  const resolvedInc = (inc.resolved ?? 0) + (inc.closed ?? 0)

  return (
    <>
      <PageHeader title="Overview">
        <div role="group" aria-label="Time range" className="flex gap-1">
          {RANGES.map((r) => (
            <button
              key={r.minutes}
              className={`btn ${minutes === r.minutes ? 'btn-primary' : ''}`}
              onClick={() => setMinutes(r.minutes)}
            >
              {r.label}
            </button>
          ))}
        </div>
        <button className="btn" onClick={reload}>
          Refresh
        </button>
      </PageHeader>
      <State loading={loading} error={error} empty={!data} onRetry={reload}>
        {data && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <Stat label="Total events" value={data.events_total.toLocaleString()} />
              <Stat
                label={`Events (last ${RANGES.find((r) => r.minutes === minutes)?.label})`}
                value={data.events_window.toLocaleString()}
              />
              <Stat label="Ingestion rate" value={`${data.events_per_minute}/min`} />
              <Stat label="Open / resolved incidents" value={`${openInc} / ${resolvedInc}`} />
            </div>

            <div className="grid grid-cols-2 gap-3 md:grid-cols-5" aria-label="Alerts by severity">
              {SEVERITIES.map((s) => (
                <Link
                  key={s}
                  to={`/alerts?severity=${s}&status=open`}
                  className="card block hover:bg-panel2"
                  style={{ borderLeft: `4px solid ${SEV_COLOR[s]}` }}
                >
                  <div className="text-xs uppercase text-slate-400">{s}</div>
                  <div className="text-2xl font-bold" style={{ color: SEV_COLOR[s] }}>
                    {data.alerts_by_severity[s] ?? 0}
                  </div>
                  <div className="text-xs text-slate-500">active alerts</div>
                </Link>
              ))}
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <div className="card lg:col-span-2">
                <h2 className="mb-2 font-semibold">Events over time</h2>
                {timeline.length === 0 ? (
                  <p className="text-sm text-slate-400">No events in this window.</p>
                ) : (
                  <ResponsiveContainer width="100%" height={220}>
                    <LineChart data={timeline}>
                      <CartesianGrid stroke="#2a2c2f" strokeDasharray="3 3" />
                      <XAxis dataKey="time" stroke="#9a9a97" fontSize={11} />
                      <YAxis stroke="#9a9a97" fontSize={11} allowDecimals={false} />
                      <Tooltip contentStyle={{ background: '#0d0d0e', border: '1px solid #2a2c2f' }} />
                      <Line type="monotone" dataKey="count" stroke="#d4f8b8" dot={false} strokeWidth={2} />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </div>
              <div className="card">
                <h2 className="mb-2 font-semibold">Detection activity</h2>
                {byRule.length === 0 ? (
                  <p className="text-sm text-slate-400">No detections in this window.</p>
                ) : (
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={byRule} layout="vertical" margin={{ left: 20 }}>
                      <XAxis type="number" stroke="#9a9a97" fontSize={11} allowDecimals={false} />
                      <YAxis dataKey="rule" type="category" stroke="#9a9a97" fontSize={11} width={70} />
                      <Tooltip contentStyle={{ background: '#0d0d0e', border: '1px solid #2a2c2f' }} />
                      <Bar dataKey="count">
                        {byRule.map((r) => (
                          <Cell key={r.rule} fill="#d4f8b8" />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <div className="card lg:col-span-1">
                <h2 className="mb-2 font-semibold">Recent detections</h2>
                {data.recent_alerts.length === 0 && <p className="text-sm text-slate-400">No alerts yet.</p>}
                <ul className="space-y-2">
                  {data.recent_alerts.map((a) => (
                    <li key={a.id} className="text-sm">
                      <SevBadge sev={a.severity} />{' '}
                      <Link className="text-sky-300 hover:underline" to={`/alerts/${a.id}`}>
                        {a.title}
                      </Link>
                      <div className="text-xs text-slate-500">{fmt(a.last_seen)}</div>
                    </li>
                  ))}
                </ul>
              </div>
              <TopList title="Top source IPs" rows={data.top_src_ips} />
              <TopList title="Top hosts" rows={data.top_hosts} />
            </div>

            <div className="card">
              <h2 className="mb-2 font-semibold">Collector &amp; infrastructure health</h2>
              <p className="mb-2 text-sm text-slate-400">
                Search backend: <b>{data.search_backend.backend}</b> ({data.search_backend.status})
              </p>
              {data.collectors.length === 0 ? (
                <p className="text-sm text-slate-400">No collector has sent data yet.</p>
              ) : (
                <ul className="grid gap-2 md:grid-cols-2">
                  {data.collectors.map((c) => (
                    <li
                      key={c.name}
                      className="flex items-center justify-between rounded border border-line px-3 py-2 text-sm"
                    >
                      <span>
                        <span className={c.healthy ? 'text-green-400' : 'text-red-400'}>●</span> {c.name}{' '}
                        <span className="text-xs text-slate-500">({c.source_type})</span>
                      </span>
                      <span className="text-xs text-slate-400">
                        {c.events_total.toLocaleString()} events · {c.errors_total} errors ·{' '}
                        {fmt(c.last_seen)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </State>
    </>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="card">
      <div className="text-xs uppercase text-slate-400">{label}</div>
      <div className="text-2xl font-bold text-white">{value}</div>
    </div>
  )
}

function TopList({ title, rows }: { title: string; rows: { key: string; count: number }[] }) {
  return (
    <div className="card">
      <h2 className="mb-2 font-semibold">{title}</h2>
      {rows.length === 0 && <p className="text-sm text-slate-400">No data.</p>}
      <ul className="space-y-1 text-sm">
        {rows.map((r) => (
          <li key={r.key} className="flex justify-between font-mono text-xs">
            <span>{r.key}</span>
            <span className="text-slate-400">{r.count}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
