import { api } from '../api/client'
import { useAsync } from '../hooks'
import { PageHeader, State } from '../components/ui'

const W = 720
const H = 360
const x = (lon: number) => ((lon + 180) / 360) * W
const y = (lat: number) => ((90 - lat) / 180) * H

/**
 * Plots only IPs that a configured GeoIP source located. No basemap tiles are fetched (no third-party
 * requests); a lat/lon grid is drawn instead. Private/reserved/unknown addresses are counted, never placed.
 */
export function Geo() {
  const { data, error, loading, reload } = useAsync(() => api.geo(), [], 30000)
  return (
    <>
      <PageHeader title="Attack map">
        <button className="btn" onClick={reload}>
          Refresh
        </button>
      </PageHeader>
      <State loading={loading} error={error} empty={!data} onRetry={reload}>
        {data && (
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="card lg:col-span-2">
              <svg
                viewBox={`0 0 ${W} ${H}`}
                role="img"
                aria-label="Map of suspicious source locations"
                className="w-full rounded bg-bg"
              >
                {[-60, -30, 0, 30, 60].map((lat) => (
                  <line
                    key={lat}
                    x1={0}
                    x2={W}
                    y1={y(lat)}
                    y2={y(lat)}
                    stroke="#263147"
                    strokeWidth={lat === 0 ? 1 : 0.5}
                  />
                ))}
                {[-120, -60, 0, 60, 120].map((lon) => (
                  <line
                    key={lon}
                    y1={0}
                    y2={H}
                    x1={x(lon)}
                    x2={x(lon)}
                    stroke="#263147"
                    strokeWidth={lon === 0 ? 1 : 0.5}
                  />
                ))}
                {data.points.map((p) => (
                  <g key={p.ip}>
                    <circle
                      cx={x(p.lon)}
                      cy={y(p.lat)}
                      r={Math.min(6 + Math.log2(p.count + 1) * 2, 18)}
                      fill="#ef444455"
                      stroke="#ef4444"
                    />
                    <title>{`${p.ip} — ${p.city || 'unknown city'}, ${p.country || 'unknown country'}: ${p.count} events (${p.rules.join(', ')})`}</title>
                  </g>
                ))}
              </svg>
              {data.points.length === 0 && (
                <p className="mt-2 text-sm text-slate-400">
                  No located suspicious sources. Public IPs are placed only when a GeoIP database is
                  configured (SIEM_GEOIP_DB_PATH); private, reserved and unknown addresses are never given
                  coordinates.
                </p>
              )}
            </div>
            <div className="card">
              <h2 className="mb-2 font-semibold">Located sources</h2>
              <ul className="space-y-1 text-sm">
                {data.points.map((p) => (
                  <li key={p.ip} className="flex justify-between font-mono text-xs">
                    <span>
                      {p.ip}{' '}
                      <span className="text-slate-500">{[p.city, p.country].filter(Boolean).join(', ')}</span>
                    </span>
                    <span>{p.count}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-slate-400">
                Detection-related events without a location (private, reserved or unknown source):{' '}
                <b>{data.unlocated_events}</b>
              </p>
            </div>
          </div>
        )}
      </State>
    </>
  )
}
