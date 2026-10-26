import type { SiemEvent } from '../api/client'
import { SevBadge, SyntheticTag, fmt } from './ui'

/** Untrusted log text is only ever rendered as React text nodes (auto-escaped). */
export function EventDetail({ event, onClose }: { event: SiemEvent; onClose: () => void }) {
  const rows: [string, unknown][] = [
    ['Event ID', event.event_id],
    ['Time', fmt(event['@timestamp'])],
    ['Host', event.host],
    ['Source type', event.source_type],
    ['Category / action', `${event.category} / ${event.action}`],
    ['Outcome', event.outcome],
    ['User', event.user],
    ['Source IP', event.src_ip],
    ['Destination', event.dst_ip ? `${event.dst_ip}${event.dst_port ? ':' + event.dst_port : ''}` : null],
    ['Process', event.process_name],
    ['Command line', event.command_line],
    ['Geo', event.geo ? JSON.stringify(event.geo) : null],
    ['Detections', event.detections.join(', ')],
  ]
  return (
    <div
      role="dialog"
      aria-label="Event details"
      className="fixed inset-0 z-30 flex justify-end bg-black/60"
      onClick={onClose}
    >
      <div
        className="h-full w-full max-w-xl overflow-y-auto border-l border-line bg-panel p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold">
            Event <SevBadge sev={event.severity} />
            <SyntheticTag show={event.synthetic} />
          </h2>
          <button className="btn" onClick={onClose}>
            Close
          </button>
        </div>
        <dl className="grid grid-cols-3 gap-x-3 gap-y-1 text-sm">
          {rows
            .filter(([, v]) => v !== null && v !== undefined && v !== '')
            .map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-slate-400">{k}</dt>
                <dd className="col-span-2 break-all font-mono text-xs">{String(v)}</dd>
              </div>
            ))}
        </dl>
        <h3 className="mb-1 mt-4 text-sm font-semibold text-slate-300">Message</h3>
        <pre className="whitespace-pre-wrap break-all rounded bg-bg p-2 text-xs">{event.message}</pre>
        <h3 className="mb-1 mt-4 text-sm font-semibold text-slate-300">Raw evidence</h3>
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-bg p-2 text-xs">
          {event.raw}
        </pre>
        <h3 className="mb-1 mt-4 text-sm font-semibold text-slate-300">Fields</h3>
        <pre className="whitespace-pre-wrap break-all rounded bg-bg p-2 text-xs">
          {JSON.stringify(event.fields, null, 2)}
        </pre>
      </div>
    </div>
  )
}
