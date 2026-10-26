import { useEffect, useRef, useState } from 'react'
import { api, ApiError, type SiemEvent } from '../api/client'
import { EventDetail } from '../components/EventDetail'
import { EventTable } from '../components/EventTable'
import { PageHeader } from '../components/ui'

const MAX_BUFFER = 300
type Mode = 'connecting' | 'stream' | 'polling'

const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms))

/** Live tail: authenticated SSE via fetch streaming, reconnect with backoff, polling fallback, bounded buffer. */
export function Live() {
  const [events, setEvents] = useState<SiemEvent[]>([])
  const [mode, setMode] = useState<Mode>('connecting')
  const [paused, setPaused] = useState(false)
  const [selected, setSelected] = useState<SiemEvent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const pausedRef = useRef(false)
  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    const ctl = new AbortController()
    let lastSeq = 0
    let failures = 0

    const push = (batch: SiemEvent[]) => {
      if (pausedRef.current || batch.length === 0) return
      setEvents((prev) => [...batch.slice().reverse(), ...prev].slice(0, MAX_BUFFER))
    }

    async function run() {
      while (!ctl.signal.aborted) {
        try {
          setMode(failures >= 2 ? 'polling' : 'connecting')
          if (failures >= 2) {
            const r = await api.recent(lastSeq)
            lastSeq = r.last_seq
            push(r.items)
            setError(null)
          }
          await api.stream((e) => {
            if (failures !== 0) failures = 0
            setMode('stream')
            setError(null)
            lastSeq = Math.max(lastSeq, e.seq ?? 0)
            push([e])
          }, ctl.signal)
        } catch (e) {
          if (ctl.signal.aborted) return
          setError(e instanceof ApiError ? e.message : 'Connection interrupted')
        }
        failures++
        await sleep(Math.min(1000 * 2 ** failures, 10000))
      }
    }
    void run()
    return () => ctl.abort()
  }, [])

  const label =
    mode === 'stream' ? '● Live (SSE)' : mode === 'polling' ? '◐ Polling fallback' : '○ Connecting…'
  return (
    <>
      <PageHeader title="Live event stream">
        <span className="text-sm text-slate-400" data-testid="live-mode">
          {label}
        </span>
        <button className="btn" onClick={() => setPaused((p) => !p)}>
          {paused ? 'Resume' : 'Pause'}
        </button>
        <button className="btn" onClick={() => setEvents([])}>
          Clear
        </button>
      </PageHeader>
      {error && (
        <p role="alert" className="mb-2 text-sm text-amber-400">
          {error} — retrying…
        </p>
      )}
      {events.length === 0 ? (
        <p className="card text-slate-400">
          Waiting for new events. Ingest events (for example with the synthetic generator) to see them here.
        </p>
      ) : (
        <EventTable events={events} onSelect={setSelected} />
      )}
      <p className="mt-2 text-xs text-slate-500">Showing the latest {MAX_BUFFER} events at most.</p>
      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}
    </>
  )
}
