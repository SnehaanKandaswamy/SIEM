import { useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { SEVERITIES, api, type SiemEvent } from '../api/client'
import { EventDetail } from '../components/EventDetail'
import { EventTable } from '../components/EventTable'
import { PageHeader, Pagination, State } from '../components/ui'
import { useAsync } from '../hooks'

const SOURCES = ['windows', 'linux', 'nginx', 'docker', 'json']
const CATEGORIES = ['authentication', 'network', 'process', 'web', 'container', 'system', 'iam']
const RANGES: Record<string, number | null> = {
  '15 minutes': 15,
  '1 hour': 60,
  '24 hours': 1440,
  '7 days': 10080,
  'All time': null,
}

export function Explorer() {
  const [sp, setSp] = useSearchParams()
  const [selected, setSelected] = useState<SiemEvent | null>(null)
  const [draft, setDraft] = useState({
    q: sp.get('q') ?? '',
    host: sp.get('host') ?? '',
    src_ip: sp.get('src_ip') ?? '',
    range: sp.get('range') ?? '24 hours',
  })
  const page = Number(sp.get('page') ?? 1)
  const sort = sp.get('sort') ?? '@timestamp'
  const order = sp.get('order') ?? 'desc'

  const { data, error, loading, reload } = useAsync(() => {
    const mins = RANGES[sp.get('range') ?? '24 hours']
    return api.search({
      q: sp.get('q') ?? '',
      host: sp.get('host') ?? '',
      src_ip: sp.get('src_ip') ?? '',
      severity: sp.getAll('severity'),
      source_type: sp.getAll('source_type'),
      category: sp.getAll('category'),
      start: mins ? new Date(Date.now() - mins * 60000).toISOString() : undefined,
      page,
      size: 50,
      sort,
      order,
    })
  }, [sp.toString()])

  function submit(e: FormEvent) {
    e.preventDefault()
    const n = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(draft)) {
      if (v) n.set(k, v)
      else n.delete(k)
    }
    n.set('page', '1')
    setSp(n)
  }
  const toggle = (k: string, v: string) => {
    const n = new URLSearchParams(sp)
    const cur = n.getAll(k)
    n.delete(k)
    ;(cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]).forEach((x) => n.append(k, x))
    n.set('page', '1')
    setSp(n)
  }
  const chips = (k: string, opts: string[]) => (
    <fieldset className="flex flex-wrap items-center gap-1 text-xs">
      <legend className="sr-only">{k}</legend>
      <span className="mr-1 text-slate-400">{k}:</span>
      {opts.map((o) => (
        <label
          key={o}
          className={`cursor-pointer rounded border px-2 py-1 ${sp.getAll(k).includes(o) ? 'border-sky-500 bg-sky-900/40' : 'border-line'}`}
        >
          <input
            type="checkbox"
            className="sr-only"
            checked={sp.getAll(k).includes(o)}
            onChange={() => toggle(k, o)}
          />
          {o}
        </label>
      ))}
    </fieldset>
  )

  const invalid = error && /^(400|422)|invalid/i.test(error)
  return (
    <>
      <PageHeader title="Log explorer" />
      <form onSubmit={submit} className="card mb-3 space-y-3" role="search">
        <div className="flex flex-wrap gap-2">
          <input
            aria-label="Search text"
            className="input min-w-64 flex-1"
            placeholder='Search events, e.g. failed password OR "encoded command"'
            value={draft.q}
            onChange={(e) => setDraft({ ...draft, q: e.target.value })}
            maxLength={500}
          />
          <input
            aria-label="Host"
            className="input w-40"
            placeholder="Host"
            value={draft.host}
            onChange={(e) => setDraft({ ...draft, host: e.target.value })}
          />
          <input
            aria-label="Source IP"
            className="input w-40"
            placeholder="Source IP"
            value={draft.src_ip}
            onChange={(e) => setDraft({ ...draft, src_ip: e.target.value })}
          />
          <select
            aria-label="Time range"
            className="input"
            value={draft.range}
            onChange={(e) => setDraft({ ...draft, range: e.target.value })}
          >
            {Object.keys(RANGES).map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
          <button className="btn btn-primary">Search</button>
        </div>
        {chips('severity', [...SEVERITIES])}
        {chips('source_type', SOURCES)}
        {chips('category', CATEGORIES)}
        <div className="flex gap-2 text-xs">
          <label>
            Sort{' '}
            <select
              className="input"
              value={`${sort}:${order}`}
              onChange={(e) => {
                const [s, o] = e.target.value.split(':')
                const n = new URLSearchParams(sp)
                n.set('sort', s)
                n.set('order', o)
                setSp(n)
              }}
            >
              <option value="@timestamp:desc">Newest first</option>
              <option value="@timestamp:asc">Oldest first</option>
              <option value="severity:desc">Severity (Z→A)</option>
              <option value="host:asc">Host (A→Z)</option>
            </select>
          </label>
        </div>
      </form>
      {invalid && (
        <p className="mb-2 text-sm text-amber-400">
          The search request was rejected. Check the IP address or filter values.
        </p>
      )}
      <State
        loading={loading}
        error={error}
        empty={!!data && data.items.length === 0}
        emptyText="No events match this search."
        onRetry={reload}
      >
        {data && (
          <>
            <EventTable events={data.items} onSelect={setSelected} />
            <Pagination
              page={page}
              size={50}
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
      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}
    </>
  )
}
