import { useState, type FormEvent } from 'react'
import { SEVERITIES, api } from '../api/client'
import { PageHeader } from '../components/ui'

type Kind = 'alerts' | 'incidents' | 'events'

export function Reports() {
  const [kind, setKind] = useState<Kind>('alerts')
  const [format, setFormat] = useState<'csv' | 'pdf'>('pdf')
  const [severity, setSeverity] = useState<string[]>([])
  const [start, setStart] = useState('')
  const [end, setEnd] = useState('')
  const [q, setQ] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setMsg(null)
    try {
      const params: Record<string, unknown> = { format, severity }
      if (start) params.start = new Date(start).toISOString()
      if (end) params.end = new Date(end).toISOString()
      if (kind === 'events' && q) params.q = q
      if (kind === 'incidents') delete params.severity
      const name = await api.download(`/api/reports/${kind}`, params)
      setMsg({ ok: true, text: `Downloaded ${name}` })
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : 'Export failed' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <PageHeader title="Reports &amp; exports" />
      <form onSubmit={submit} className="card max-w-2xl space-y-3">
        <div className="flex flex-wrap gap-3 text-sm">
          <label>
            Report{' '}
            <select className="input" value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
              <option value="alerts">Alerts</option>
              <option value="incidents">Incidents</option>
              <option value="events">Events</option>
            </select>
          </label>
          <label>
            Format{' '}
            <select
              className="input"
              value={format}
              onChange={(e) => setFormat(e.target.value as 'csv' | 'pdf')}
            >
              <option value="pdf">PDF</option>
              <option value="csv">CSV</option>
            </select>
          </label>
        </div>
        {kind !== 'incidents' && (
          <fieldset className="flex flex-wrap items-center gap-1 text-xs">
            <legend className="sr-only">Severity</legend>
            <span className="mr-1 text-slate-400">severity:</span>
            {SEVERITIES.map((s) => (
              <label
                key={s}
                className={`cursor-pointer rounded border px-2 py-1 ${severity.includes(s) ? 'border-sky-500 bg-sky-900/40' : 'border-line'}`}
              >
                <input
                  type="checkbox"
                  className="sr-only"
                  checked={severity.includes(s)}
                  onChange={() =>
                    setSeverity((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))
                  }
                />
                {s}
              </label>
            ))}
          </fieldset>
        )}
        {kind !== 'incidents' && (
          <div className="flex flex-wrap gap-3 text-sm">
            <label>
              From{' '}
              <input
                type="datetime-local"
                className="input"
                value={start}
                onChange={(e) => setStart(e.target.value)}
              />
            </label>
            <label>
              To{' '}
              <input
                type="datetime-local"
                className="input"
                value={end}
                onChange={(e) => setEnd(e.target.value)}
              />
            </label>
          </div>
        )}
        {kind === 'events' && (
          <label className="block text-sm">
            Search text
            <input
              className="input mt-1 w-full"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              maxLength={500}
            />
          </label>
        )}
        <p className="text-xs text-slate-400">
          Exports are limited to 5,000 rows and are recorded in the audit log.
        </p>
        <button className="btn btn-primary" disabled={busy}>
          {busy ? 'Generating…' : 'Generate & download'}
        </button>
        {msg && (
          <p role="status" className={`text-sm ${msg.ok ? 'text-green-400' : 'text-red-400'}`}>
            {msg.text}
          </p>
        )}
      </form>
    </>
  )
}
