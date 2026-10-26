import type { SiemEvent } from '../api/client'
import { SevBadge, SyntheticTag, fmt } from './ui'

export function EventTable({ events, onSelect }: { events: SiemEvent[]; onSelect: (e: SiemEvent) => void }) {
  return (
    <div className="card overflow-x-auto p-0">
      <table className="w-full">
        <thead className="border-b border-line">
          <tr>
            {['Time', 'Sev', 'Host', 'Source', 'Action', 'User', 'Src IP', 'Message'].map((h) => (
              <th key={h} className="th">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr
              key={e.event_id}
              className="cursor-pointer border-b border-line/50 hover:bg-panel2"
              onClick={() => onSelect(e)}
            >
              <td className="td whitespace-nowrap font-mono text-xs">{fmt(e['@timestamp'])}</td>
              <td className="td">
                <SevBadge sev={e.severity} />
              </td>
              <td className="td">{e.host}</td>
              <td className="td">{e.source_type}</td>
              <td className="td">
                {e.action}
                <SyntheticTag show={e.synthetic} />
                {e.detections.length > 0 && (
                  <span className="ml-1 text-xs text-amber-400">⚑ {e.detections.join(',')}</span>
                )}
              </td>
              <td className="td">{e.user ?? ''}</td>
              <td className="td font-mono text-xs">{e.src_ip ?? ''}</td>
              <td className="td max-w-md truncate" title={e.message}>
                {e.message}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
